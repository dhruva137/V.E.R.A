"""WP5: configuration collector, one fixture per format."""

from __future__ import annotations

import textwrap

import pytest

from collectors.config_scanner import detect_format, scan_configs, scan_text
from engine import protocol_names as names


def _scan(name: str, text: str):
    return scan_text(textwrap.dedent(text).lstrip("\n"), f"/etc/fixture/{name}")


def _algorithms(findings):
    return [(f.algorithm, f.key_size) for f in findings if f.algorithm]


def _protocols(findings):
    return sorted({f.protocol for f in findings if f.protocol})


def test_sshd_config_lists_become_ordered_findings():
    findings = _scan("sshd_config", """
        # hardened? not quite
        KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,diffie-hellman-group1-sha1
        HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,ssh-rsa-cert-v01@openssh.com
        Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,3des-cbc
        MACs hmac-sha2-256-etm@openssh.com,hmac-md5
        """)
    kex = [f for f in findings if f.raw_details["directive"] == "KexAlgorithms"]
    assert [f.algorithm for f in kex] == ["X25519MLKEM768", "X25519", "DH"]
    assert [f.raw_details["position"] for f in kex] == [0, 1, 2]
    assert kex[2].key_size == 1024 and "weak classically" in kex[2].raw_details["note"]
    hostkeys = [f for f in findings if f.raw_details["directive"] == "HostKeyAlgorithms"]
    assert [f.algorithm for f in hostkeys] == ["Ed25519", "RSA", "RSA"]
    assert "OpenSSH certificate" in hostkeys[2].raw_details["note"]
    assert ("3DES", None) in _algorithms(findings)
    assert all(f.raw_details["plane"] == "declared" and f.source_type == "config" for f in findings)


def test_nginx_protocols_ciphers_and_curves():
    findings = _scan("site.conf", """
        server {
            listen 443 ssl;
            ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
            ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:HIGH:!aNULL:!MD5;
            ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;
        }
        """)
    assert detect_format("/etc/nginx/sites-enabled/site.conf", "ssl_protocols TLSv1;") == "nginx"
    assert _protocols(findings) == ["TLSv1.0", "TLSv1.1"]
    suites = [f.cipher_suite for f in findings if f.cipher_suite]
    assert suites == ["ECDHE-RSA-AES128-GCM-SHA256", "DES-CBC3-SHA"]      # HIGH and !-exclusions skipped
    curves = [f.algorithm for f in findings if f.raw_details["directive"] == "ssl_ecdh_curve"]
    assert curves == ["X25519MLKEM768", "X25519", "ECDH"]


def test_apache_protocol_arithmetic():
    findings = _scan("ssl.conf", """
        SSLProtocol all -SSLv3 -TLSv1
        SSLCipherSuite HIGH:RC4:!aNULL
        SSLOpenSSLConfCmd Curves X25519:secp384r1
        """)
    assert _protocols(findings) == ["TLSv1.1"]          # all minus TLSv1 still leaves 1.1
    assert ("RC4", None) in _algorithms(findings)
    assert ("ECDH", 384) in _algorithms(findings)


def test_haproxy_min_version_and_ciphers():
    findings = _scan("haproxy.cfg", """
        global
            ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:RC4-SHA
            ssl-default-bind-options ssl-min-ver TLSv1.0 no-tls-tickets
        frontend web
            bind :443 ssl crt /etc/ssl/site.pem curves P-256:X25519
        """)
    assert _protocols(findings) == ["TLSv1.0"]
    assert "RC4-SHA" in [f.cipher_suite for f in findings]
    assert {("ECDH", 256), ("X25519", None)} <= set(_algorithms(findings))


def test_openssl_cnf():
    findings = _scan("openssl.cnf", """
        [system_default_sect]
        MinProtocol = TLSv1
        CipherString = DEFAULT@SECLEVEL=1
        Groups = X25519MLKEM768:X25519:P-256:ffdhe2048
        """)
    assert _protocols(findings) == ["TLSv1.0"]
    assert [a for a, _ in _algorithms(findings)] == ["X25519MLKEM768", "X25519", "ECDH", "DH"]
    assert not [f for f in findings if f.cipher_suite]   # DEFAULT@SECLEVEL is a meta keyword


def test_java_security_reports_what_is_not_disabled():
    findings = _scan("java.security", """
        jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, MD5withRSA, \\
            DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, \\
            RSA keySize < 1024
        """)
    assert _protocols(findings) == ["TLSv1.0", "TLSv1.1"]
    rsa = [f for f in findings if f.algorithm == "RSA"]
    assert rsa and rsa[0].key_size == 1024
    assert all(f.raw_details.get("permitted_because") or f.algorithm == "RSA" for f in findings)


def test_strongswan_ipsec_conf():
    findings = _scan("ipsec.conf", """
        conn branch
            ike=aes256-sha256-modp2048,aes128-sha1-modp1024!
            esp=aes256gcm16-ecp384-ke1_mlkem768
        """)
    groups = [(f.algorithm, f.key_size) for f in findings if f.raw_details.get("role") == "group"]
    assert groups == [("DH", 2048), ("DH", 1024), ("ECDH", 384), ("ML-KEM-768", None)]
    assert all(f.asset_class == "vpn_ipsec" for f in findings)
    assert any(f.algorithm == "HMAC" and "SHA-1" in f.raw_details["note"] for f in findings)
    modp1024 = next(f for f in findings if f.raw_details["wire_name"] == "modp1024")
    assert "Weak classically" in modp1024.raw_details["note"]


def test_swanctl_proposals():
    findings = _scan("swanctl.conf", """
        connections {
          hq {
            proposals = aes256-sha384-x25519
            children { net { esp_proposals = aes128gcm16-modp3072 } }
          }
        }
        """)
    assert ("X25519", None) in _algorithms(findings)
    assert ("DH", 3072) in _algorithms(findings)


def test_terraform_kms_acm_tls_and_policies():
    findings = _scan("main.tf", """
        resource "aws_kms_key" "payments_signing" {
          description              = "payments signing"
          customer_master_key_spec = "RSA_2048"
          key_usage                = "SIGN_VERIFY"
        }
        resource "aws_kms_key" "data" {
          description = "defaults to symmetric"
        }
        resource "aws_kms_key" "pq" {
          key_spec  = "ML_DSA_65"
          key_usage = "SIGN_VERIFY"
        }
        resource "aws_acm_certificate" "web" {
          domain_name   = "pay.example.com"
          key_algorithm = "EC_prime256v1"
        }
        resource "tls_private_key" "bootstrap" {
          algorithm = "RSA"
          rsa_bits  = 3072
        }
        resource "aws_kms_key" "templated" {
          customer_master_key_spec = var.key_spec
        }
        resource "aws_lb_listener" "https" {
          port       = 443
          ssl_policy = "ELBSecurityPolicy-2016-08"
        }
        """)
    by_resource = {f.raw_details["resource"]: f for f in findings}
    assert (by_resource["aws_kms_key.payments_signing"].algorithm, by_resource["aws_kms_key.payments_signing"].key_size) == ("RSA", 2048)
    assert by_resource["aws_kms_key.payments_signing"].usage == "signing"
    assert by_resource["aws_kms_key.data"].algorithm == "AES-256"
    assert "provider default" in by_resource["aws_kms_key.data"].raw_details["defaulted"]
    assert by_resource["aws_kms_key.pq"].algorithm == "ML-DSA-65"
    assert (by_resource["aws_acm_certificate.web"].algorithm, by_resource["aws_acm_certificate.web"].key_size) == ("ECDSA", 256)
    assert (by_resource["tls_private_key.bootstrap"].algorithm, by_resource["tls_private_key.bootstrap"].key_size) == ("RSA", 3072)
    templated = by_resource["aws_kms_key.templated"]
    assert templated.algorithm is None and templated.raw_details["unresolved"] is True
    assert by_resource["aws_lb_listener.https"].protocol == "TLSv1.0"


def test_modern_only_configs_produce_no_protocol_findings():
    findings = _scan("nginx.conf", "ssl_protocols TLSv1.2 TLSv1.3;\n")
    assert findings == []


def test_unknown_files_are_ignored():
    assert _scan("README.conf", "hello = world\n") == []


def test_ids_are_deterministic():
    text = "KexAlgorithms curve25519-sha256\n"
    assert [f.id for f in _scan("sshd_config", text)] == [f.id for f in _scan("sshd_config", text)]


def test_scan_configs_walks_a_directory(tmp_path):
    (tmp_path / "ssh").mkdir()
    (tmp_path / "ssh" / "sshd_config").write_text("Ciphers aes128-cbc\n")
    (tmp_path / "nginx.conf").write_text("ssl_protocols SSLv3;\n")
    findings, failures = scan_configs([str(tmp_path), str(tmp_path / "missing")])
    assert {(f.algorithm, f.protocol) for f in findings} == {("AES-128", None), (None, "SSLv3")}
    assert failures == [{"path": str(tmp_path / "missing"), "reason": "path does not exist"}]


@pytest.mark.parametrize("token,expected", [
    ("aes256gcm16", ("AES-256", 256)), ("3des", ("3DES", None)), ("ecp256bp", ("ECDH", 256)),
    ("ke2_mlkem1024", ("ML-KEM-1024", None)), ("sha1", ("HMAC", None)), ("prfsha256", ("HMAC", None)),
])
def test_ike_token_mapping(token, expected):
    mapped = names.ike_token(token)
    assert (mapped.algorithm, mapped.key_size) == expected


def test_ssh_pseudo_algorithms_are_not_findings():
    assert names.ssh("ext-info-c", "kex") is None
    assert names.ssh("kex-strict-s-v00@openssh.com", "kex") is None


def test_ike_version_stated_default_or_unknown():
    stated = _scan("ipsec.conf", """
        conn %default
            keyexchange=ikev1
        conn dc
            keyexchange=ikev2
            ike=aes256-sha256-modp2048!
        conn legacy
            ike=aes128-sha1-modp1024!
        """)
    by_line = {f.source_location.rsplit(":", 1)[1]: f.raw_details for f in stated}
    assert by_line["5"]["ike_version"] == "2" and by_line["5"]["ike_version_source"].startswith("stated")
    assert by_line["7"]["ike_version"] == "1"  # conn %default applies where the connection says nothing

    default = _scan("swanctl.conf", """
        connections {
          pinned { version = 2
            proposals = aes256-sha384-x25519 }
          open {
            proposals = aes128-sha256-modp3072
          }
        }
        """)
    versions = {f.raw_details["wire_name"]: (f.raw_details["ike_version"], f.raw_details["ike_version_source"])
                for f in default}
    assert versions["x25519"][0] == "2"
    assert versions["modp3072"][0] == "1" and "strongSwan default" in versions["modp3072"][1]

    # Without strongSwan syntax the file may be libreswan's, whose default differs: no guess.
    unknown = _scan("ipsec.conf", """
        conn branch
            ike=aes256-sha2_256;modp2048
        """)
    assert unknown and all("ike_version" not in f.raw_details for f in unknown)
