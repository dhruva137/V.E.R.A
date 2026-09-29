"""WP5: SSH KEXINIT parsing and the live probe against a local fake server.

The fake server records every byte the probe sends, so the test proves the
probe sends nothing beyond its own identification line.
"""

from __future__ import annotations

import os
import socket
import struct
import threading

import pytest

from collectors import ssh_scanner as ssh
from collectors.registry import REGISTRY
from engine import protocol_names as names

SERVER_LISTS = {
    "kex_algorithms": ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
                       "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "ext-info-s",
                       "kex-strict-s-v00@openssh.com"],
    "server_host_key_algorithms": ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
    "encryption_client_to_server": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"],
    "encryption_server_to_client": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"],
    "mac_client_to_server": ["hmac-sha2-256-etm@openssh.com", "hmac-sha1"],
    "mac_server_to_client": ["hmac-sha2-256-etm@openssh.com", "hmac-sha1"],
    "compression_client_to_server": ["none", "zlib@openssh.com"],
    "compression_server_to_client": ["none", "zlib@openssh.com"],
    "languages_client_to_server": [],
    "languages_server_to_client": [],
}


def kexinit_payload(lists: dict) -> bytes:
    body = bytes([ssh.MSG_KEXINIT]) + os.urandom(16)
    for name in ssh.NAME_LISTS:
        raw = ",".join(lists[name]).encode()
        body += struct.pack(">I", len(raw)) + raw
    return body + b"\x00" + b"\x00\x00\x00\x00"


def packet(payload: bytes) -> bytes:
    padding = 8 - ((len(payload) + 5) % 8) + 4
    return struct.pack(">IB", len(payload) + padding + 1, padding) + payload + b"\x00" * padding


class FakeSSHServer:
    def __init__(self, banner: bytes, pre_banner: bytes = b"", payload: bytes | None = None):
        self.banner, self.pre_banner = banner, pre_banner
        self.payload = payload if payload is not None else kexinit_payload(SERVER_LISTS)
        self.received = b""
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        conn, _ = self.sock.accept()
        with conn:
            conn.settimeout(3)
            conn.sendall(self.pre_banner + self.banner)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    self.received += chunk
                    if b"\n" in self.received:
                        conn.sendall(packet(self.payload))
                        # Keep reading: anything more the client sends is recorded.
            except (socket.timeout, ConnectionError):
                pass
        self.sock.close()


def test_parse_kexinit_round_trip():
    parsed = ssh.parse_kexinit(kexinit_payload(SERVER_LISTS))
    for name in ssh.NAME_LISTS:
        assert parsed[name] == SERVER_LISTS[name]
    assert parsed["first_kex_packet_follows"] is False


@pytest.mark.parametrize("payload,message", [
    (b"\x15" + b"\x00" * 40, "expected SSH_MSG_KEXINIT"),
    (bytes([20]) + b"\x00" * 16 + struct.pack(">I", 999) + b"abc", "truncated inside kex_algorithms"),
    (bytes([20]) + b"\x00" * 10, "truncated before kex_algorithms"),
])
def test_parse_kexinit_rejects_malformed(payload, message):
    with pytest.raises(ssh.ProtocolError, match=message):
        ssh.parse_kexinit(payload)


def test_parse_packet_rejects_implausible_length():
    with pytest.raises(ssh.ProtocolError, match="implausible"):
        ssh.parse_packet(struct.pack(">IB", 10_000_000, 4) + b"x" * 20)


def test_live_probe_sends_only_its_banner_and_reads_kexinit():
    server = FakeSSHServer(b"SSH-2.0-OpenSSH_10.0p2 Debian-5\r\n", pre_banner=b"Authorized use only\r\n")
    result = ssh.probe("127.0.0.1", server.port, timeout=3)
    server.thread.join(timeout=5)
    assert server.received == ssh.CLIENT_BANNER
    assert result["banner"] == "SSH-2.0-OpenSSH_10.0p2 Debian-5"
    assert result["kex_algorithms"][0] == "mlkem768x25519-sha256"


def test_collector_findings_from_a_live_server():
    server = FakeSSHServer(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
    result = ssh.SSHCollector().collect([f"127.0.0.1:{server.port}"])
    server.thread.join(timeout=5)
    assert result.failures == []
    assert result.stats == {"targets": 1, "reachable": 1, "pq_hybrid_offered": 1,
                            "duration_ms": result.stats["duration_ms"]}
    kex = [f for f in result.findings if f.raw_details["name_list"] == "kex_algorithms"]
    assert [f.algorithm for f in kex] == ["X25519MLKEM768", "SNTRUP761X25519", "X25519", "ECDH", "DH"]
    first = kex[0].raw_details
    assert first["plane"] == "observed" and first["provenance"] == "runtime_observed"
    assert first["pq_hybrid_kex_offered"] is True
    assert first["openssh_version"] == "9.6"
    assert first["openssh_default_pq_kex"] == "sntrup761x25519-sha512@openssh.com"
    assert kex[0].asset_class == "ssh_key_exchange" and kex[0].source_type == "ssh"
    hostkeys = [f.algorithm for f in result.findings if f.raw_details["name_list"] == "server_host_key_algorithms"]
    assert hostkeys == ["RSA", "RSA", "ECDSA", "Ed25519"]


def test_unreachable_host_is_a_reported_failure():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    result = ssh.SSHCollector().collect([f"127.0.0.1:{port}"])
    assert result.findings == [] and result.failures


def test_non_ssh_server_is_a_protocol_error():
    server = FakeSSHServer(b"HTTP/1.1 400 Bad Request\r\n" * 800)
    with pytest.raises(ssh.ProtocolError):
        ssh.probe("127.0.0.1", server.port, timeout=3)


@pytest.mark.parametrize("banner,version,default", [
    ("SSH-2.0-OpenSSH_8.9p1", (8, 9), None),
    ("SSH-2.0-OpenSSH_9.0", (9, 0), "sntrup761x25519-sha512@openssh.com"),
    ("SSH-2.0-OpenSSH_10.2", (10, 2), "mlkem768x25519-sha256"),
    ("SSH-2.0-dropbear_2024.86", None, None),
])
def test_openssh_default_hybrid_by_version(banner, version, default):
    assert names.openssh_version(banner) == version
    assert names.openssh_default_pq_kex(version) == default


def test_registered_in_the_collector_registry():
    assert REGISTRY["ssh"].plane == "observed"
