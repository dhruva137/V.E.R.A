"""SSH collector (plane: observed): what a live SSH server actually offers.

PROTOCOL (RFC 4253, sections 4.2 and 7.1)
-----------------------------------------
Connect, read the server's identification line, send ours, then read one
binary packet: the server's SSH_MSG_KEXINIT (type 20). Its ten name-lists are
the key-exchange, host-key, cipher, MAC and compression algorithms the server
will negotiate, in its order of preference. The connection is then closed.

**Nothing is sent beyond our own identification line.** No KEXINIT of ours, no
key exchange, no authentication attempt: the probe cannot log in and does not
look like a login attempt in the server's auth log.

WHAT IT PRODUCES
----------------
One finding per offered key-exchange, host-key, cipher and MAC algorithm, in
preference order, plus the server banner and whether a post-quantum hybrid key
exchange (mlkem768x25519, sntrup761x25519) is offered. For OpenSSH, the release
where that hybrid became the default is reported next to the version.

STATED LIMITATIONS
------------------
- What is *offered* is not what a given client *negotiates*; the negotiated
  algorithm depends on the client's list too.
- Servers behind a proxy or bastion report the proxy's algorithms.
"""

from __future__ import annotations

import socket
import struct
from concurrent.futures import ThreadPoolExecutor

from collectors.base import DEFAULT_LIMITS, CollectResult, Limits, Timer, evidence, stable_id
from engine import offline
from engine import protocol_names as names
from models.schemas import RawCryptoFinding

COLLECTOR = "ssh_live"
CLIENT_BANNER = b"SSH-2.0-VERA_Probe_1.0\r\n"
MSG_KEXINIT = 20
MAX_PACKET = 256 * 1024
NAME_LISTS = ("kex_algorithms", "server_host_key_algorithms", "encryption_client_to_server",
              "encryption_server_to_client", "mac_client_to_server", "mac_server_to_client",
              "compression_client_to_server", "compression_server_to_client",
              "languages_client_to_server", "languages_server_to_client")
PQ_HYBRID_KEX = {"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
                 "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"}


class ProtocolError(ValueError):
    """The peer did not speak SSH as RFC 4253 describes."""


def parse_kexinit(payload: bytes) -> dict:
    """Decode an SSH_MSG_KEXINIT payload (starting at the message-type byte)."""
    if not payload or payload[0] != MSG_KEXINIT:
        raise ProtocolError(f"expected SSH_MSG_KEXINIT (20), got {payload[:1]!r}")
    pos = 1 + 16                                 # message type, 16-byte cookie
    lists: dict[str, list[str]] = {}
    for name in NAME_LISTS:
        if pos + 4 > len(payload):
            raise ProtocolError(f"truncated before {name}")
        (length,) = struct.unpack(">I", payload[pos:pos + 4])
        pos += 4
        if pos + length > len(payload):
            raise ProtocolError(f"truncated inside {name}")
        raw = payload[pos:pos + length].decode("ascii", errors="replace")
        lists[name] = [item for item in raw.split(",") if item]
        pos += length
    if pos + 5 > len(payload):
        raise ProtocolError("truncated before first_kex_packet_follows")
    lists["first_kex_packet_follows"] = bool(payload[pos])
    return lists


def parse_packet(data: bytes) -> tuple[bytes, int]:
    """(payload, bytes consumed) from an unencrypted SSH binary packet."""
    if len(data) < 5:
        raise ProtocolError("short packet header")
    packet_length, padding = struct.unpack(">IB", data[:5])
    if packet_length > MAX_PACKET or padding >= packet_length:
        raise ProtocolError(f"implausible packet length {packet_length}")
    end = 4 + packet_length
    if len(data) < end:
        raise ProtocolError("incomplete packet")
    return data[5:end - padding], end


def _fill(sock: socket.socket, buf: bytes, size: int) -> bytes:
    """Read until `buf` holds at least `size` bytes."""
    while len(buf) < size:
        chunk = sock.recv(max(4096, size - len(buf)))
        if not chunk:
            raise ProtocolError("connection closed by peer")
        buf += chunk
    return buf


def probe(host: str, port: int = 22, timeout: float = 6.0) -> dict:
    """Banner + server KEXINIT from one SSH server. Sends only our identification line."""
    offline.allow(host)  # an operator-named target stays reachable under VERA_OFFLINE=1
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        buf, seen = b"", 0
        while True:                       # RFC 4253 4.2: other lines may precede "SSH-"
            while b"\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    raise ProtocolError("connection closed before an SSH banner")
                buf += chunk
                seen += len(chunk)
                if seen > 16384:
                    raise ProtocolError("no SSH banner in the first 16 KB")
            line, buf = buf.split(b"\n", 1)
            if line.startswith(b"SSH-"):
                banner = line.rstrip(b"\r").decode("ascii", errors="replace")
                break
        sock.sendall(CLIENT_BANNER)
        buf = _fill(sock, buf, 5)
        (packet_length,) = struct.unpack(">I", buf[:4])
        if packet_length > MAX_PACKET:
            raise ProtocolError(f"implausible packet length {packet_length}")
        buf = _fill(sock, buf, 4 + packet_length)
        payload, _ = parse_packet(buf)
    return {"banner": banner, **parse_kexinit(payload)}


def findings_from_probe(target: str, result: dict) -> list[RawCryptoFinding]:
    """One finding per offered algorithm, in the server's preference order."""
    banner = result["banner"]
    version = names.openssh_version(banner)
    default_pq = names.openssh_default_pq_kex(version)
    offered_hybrid = [k for k in result["kex_algorithms"] if k in PQ_HYBRID_KEX]
    context = {
        "discovered_by": COLLECTOR, "plane": "observed", "provenance": "runtime_observed", "confidence": 0.95,
        "banner": banner, "pq_hybrid_kex_offered": bool(offered_hybrid), "pq_hybrid_kex": offered_hybrid,
        "openssh_version": ".".join(map(str, version)) if version else None,
        "openssh_default_pq_kex": default_pq,
        "evidence_refs": [evidence(COLLECTOR, target)],
    }
    groups = (("kex_algorithms", "kex", "key_exchange", "ssh_key_exchange"),
              ("server_host_key_algorithms", "host_key", "signing", "ssh_key"),
              ("encryption_server_to_client", "cipher", "encryption", "config"),
              ("mac_server_to_client", "mac", "authentication", "config"))
    findings = []
    for list_name, role, usage, asset_class in groups:
        for position, wire in enumerate(result.get(list_name, [])):
            mapped = names.ssh(wire, role)
            if mapped is None:
                continue
            details = {**context, "name_list": list_name, "wire_name": wire, "position": position,
                       "role": mapped.role,
                       "display_name": f"{mapped.algorithm} offered by {target} ({wire})"}
            if mapped.note:
                details["note"] = mapped.note
            findings.append(RawCryptoFinding(
                id=stable_id(COLLECTOR, target, list_name, wire),
                source_type="ssh", source_location=f"ssh://{target}", asset_class=asset_class,
                algorithm=mapped.algorithm, key_size=mapped.key_size, protocol="SSH-2.0", usage=usage,
                tags=["ssh-live", f"ssh:{role}"] + (["pq-hybrid"] if wire in PQ_HYBRID_KEX else []),
                raw_details=details,
            ))
    return findings


def _parse_target(target: str) -> tuple[str, int]:
    target = target.removeprefix("ssh://")
    if target.startswith("["):                      # [ipv6]:port
        host, _, port = target[1:].partition("]:")
        return host, int(port or 22)
    host, _, port = target.rpartition(":") if target.count(":") == 1 else (target, "", "")
    return (host or target), int(port or 22)


class SSHCollector:
    """Collector-contract implementation; see `collectors.base.Collector`."""

    name = "ssh"
    plane = "observed"
    label = "Live SSH endpoints"
    description = "Server banner and KEXINIT name-lists; sends only its own identification line."
    target_kinds = ("host",)

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult:
        result = CollectResult(stats={"targets": len(targets), "reachable": 0, "pq_hybrid_offered": 0})
        timer = Timer(limits)

        def one(target: str):
            try:
                host, port = _parse_target(target)
                return target, probe(host, port), None
            except (OSError, ProtocolError, ValueError) as exc:
                return target, None, f"{type(exc).__name__}: {exc}"

        with ThreadPoolExecutor(max_workers=8) as pool:
            for target, probed, error in pool.map(one, targets):
                if error:
                    result.fail(target, error)
                    continue
                result.stats["reachable"] += 1
                found = findings_from_probe(target, probed)
                if found and found[0].raw_details["pq_hybrid_kex_offered"]:
                    result.stats["pq_hybrid_offered"] += 1
                result.findings.extend(found)
        result.stats["duration_ms"] = timer.elapsed_ms
        return result


def scan_ssh_endpoints(targets: list[str]) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Function-style entry point, matching the other collectors."""
    result = SSHCollector().collect(targets)
    return result.findings, result.failures
