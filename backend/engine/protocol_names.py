"""Protocol wire names -> taxonomy names, for SSH, IPsec/IKE and TLS groups.

Configuration files and live handshakes name algorithms the way their protocol
does (`curve25519-sha256`, `ecp384`, `ke1_mlkem768`, `prime256v1`). The
taxonomy speaks one vocabulary (`X25519`, `ECDH`, `ML-KEM-768`). This module
translates, keeping the wire name alongside so a report can quote the exact
token an operator must change.

Every function returns `Mapped(algorithm, key_size, role, note)` or None for a
pseudo-algorithm that is not cryptography (`ext-info-c`, `kex-strict-*`). An
unknown name maps to itself: the taxonomy then reports it as unknown rather
than it being dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Mapped:
    algorithm: str
    key_size: int | None = None
    role: str = ""            # key_exchange | host_key | cipher | mac | group | integrity | prf
    note: str = ""


# --------------------------------------------------------------------------
# SSH (RFC 4253 name-lists, OpenSSH extensions)
# --------------------------------------------------------------------------

_SSH_KEX = {
    "curve25519-sha256": ("X25519", None, ""),
    "curve25519-sha256@libssh.org": ("X25519", None, ""),
    "curve448-sha512": ("X448", None, ""),
    "ecdh-sha2-nistp256": ("ECDH", 256, ""),
    "ecdh-sha2-nistp384": ("ECDH", 384, ""),
    "ecdh-sha2-nistp521": ("ECDH", 521, ""),
    "diffie-hellman-group1-sha1": ("DH", 1024, "1024-bit group with a SHA-1 exchange hash; weak classically."),
    "diffie-hellman-group14-sha1": ("DH", 2048, "SHA-1 exchange hash."),
    "diffie-hellman-group14-sha256": ("DH", 2048, ""),
    "diffie-hellman-group15-sha512": ("DH", 3072, ""),
    "diffie-hellman-group16-sha512": ("DH", 4096, ""),
    "diffie-hellman-group17-sha512": ("DH", 6144, ""),
    "diffie-hellman-group18-sha512": ("DH", 8192, ""),
    "diffie-hellman-group-exchange-sha1": ("DH", None, "Group size negotiated; SHA-1 exchange hash."),
    "diffie-hellman-group-exchange-sha256": ("DH", None, "Group size negotiated."),
    "sntrup761x25519-sha512": ("SNTRUP761X25519", None, "Post-quantum hybrid (not a NIST standard)."),
    "sntrup761x25519-sha512@openssh.com": ("SNTRUP761X25519", None, "Post-quantum hybrid (not a NIST standard)."),
    "mlkem768x25519-sha256": ("X25519MLKEM768", None, "ML-KEM-768 + X25519 hybrid."),
    "mlkem768nistp256-sha256": ("SECP256R1MLKEM768", None, "ML-KEM-768 + P-256 hybrid."),
    "mlkem1024nistp384-sha384": ("SECP384R1MLKEM1024", None, "ML-KEM-1024 + P-384 hybrid."),
}
_SSH_PSEUDO = re.compile(r"^(ext-info-[cs]|kex-strict-[cs]-v00@openssh\.com|kex-strict-[cs])$")

_SSH_HOSTKEY = {
    "ssh-rsa": ("RSA", None, "RSA with SHA-1 signatures; disabled by default since OpenSSH 8.8."),
    "rsa-sha2-256": ("RSA", None, ""),
    "rsa-sha2-512": ("RSA", None, ""),
    "ssh-dss": ("DSA", 1024, "DSA; removed from OpenSSH defaults in 7.0."),
    "ecdsa-sha2-nistp256": ("ECDSA", 256, ""),
    "ecdsa-sha2-nistp384": ("ECDSA", 384, ""),
    "ecdsa-sha2-nistp521": ("ECDSA", 521, ""),
    "ssh-ed25519": ("Ed25519", None, ""),
    "ssh-ed448": ("Ed448", None, ""),
    "sk-ssh-ed25519@openssh.com": ("Ed25519", None, "FIDO security-key backed."),
    "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA", 256, "FIDO security-key backed."),
}

_SSH_CIPHER = {
    "3des-cbc": ("3DES", None, ""),
    "blowfish-cbc": ("Blowfish", None, ""),
    "cast128-cbc": ("CAST-128", None, "64-bit block cipher."),
    "arcfour": ("RC4", None, ""), "arcfour128": ("RC4", None, ""), "arcfour256": ("RC4", None, ""),
    "chacha20-poly1305@openssh.com": ("ChaCha20", None, ""),
}
_SSH_AES = re.compile(r"^aes(128|192|256)-(ctr|cbc|gcm@openssh\.com)$")
_SSH_MAC = re.compile(r"^hmac-(md5|sha1|sha2-256|sha2-512|ripemd160)(-96)?(-etm@openssh\.com)?$")
_MAC_DIGEST = {"md5": "MD5", "sha1": "SHA-1", "sha2-256": "SHA-256", "sha2-512": "SHA-512", "ripemd160": "RIPEMD-160"}


def ssh(name: str, role: str) -> Mapped | None:
    """Map one SSH algorithm name. `role` is kex | host_key | cipher | mac."""
    name = name.strip()
    if not name or _SSH_PSEUDO.match(name) or name == "none" and role in ("cipher", "mac"):
        return None
    if role == "kex":
        algorithm, size, note = _SSH_KEX.get(name, (name, None, "Not in the VERA SSH table."))
        return Mapped(algorithm, size, "key_exchange", note)
    if role == "host_key":
        base = name.replace("-cert-v01@openssh.com", "")
        algorithm, size, note = _SSH_HOSTKEY.get(base, (name, None, "Not in the VERA SSH table."))
        cert = " OpenSSH certificate." if base != name else ""
        return Mapped(algorithm, size, "host_key", (note + cert).strip())
    if role == "cipher":
        m = _SSH_AES.match(name)
        if m:
            mode = m.group(2).split("@")[0].upper()
            return Mapped(f"AES-{m.group(1)}", int(m.group(1)), "cipher", f"{mode} mode.")
        algorithm, size, note = _SSH_CIPHER.get(name, (name, None, "Not in the VERA SSH table."))
        return Mapped(algorithm, size, "cipher", note)
    if role == "mac":
        m = _SSH_MAC.match(name)
        if m:
            truncated = " Truncated to 96 bits." if m.group(2) else ""
            return Mapped("HMAC", None, "mac", f"HMAC-{_MAC_DIGEST[m.group(1)]}.{truncated}")
        return Mapped(name.split("@")[0].upper(), None, "mac", "Not in the VERA SSH table.")
    raise ValueError(f"unknown SSH role: {role}")


# OpenSSH releases and their default post-quantum key exchange. VERIFY against
# the OpenSSH release notes before a report cites them.
OPENSSH_PQ_DEFAULTS = (
    ((10, 0), "mlkem768x25519-sha256"),
    ((9, 0), "sntrup761x25519-sha512@openssh.com"),
)


def openssh_version(banner: str) -> tuple[int, int] | None:
    """'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13' -> (9, 6)."""
    m = re.search(r"OpenSSH_(\d+)\.(\d+)", banner or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def openssh_default_pq_kex(version: tuple[int, int] | None) -> str | None:
    if version is None:
        return None
    for since, kex in OPENSSH_PQ_DEFAULTS:
        if version >= since:
            return kex
    return None


# --------------------------------------------------------------------------
# IKE / IPsec (strongSwan proposal keywords)
# --------------------------------------------------------------------------

_IKE_GROUP = [
    (re.compile(r"^modp(\d{3,4})(s\d+)?$"), lambda m: Mapped("DH", int(m.group(1)), "group",
                                                             "Weak classically below 2048 bits." if int(m.group(1)) < 2048 else "")),
    (re.compile(r"^ecp(192|224|256|384|521)(bp)?$"), lambda m: Mapped("ECDH", int(m.group(1)), "group",
                                                                      "Brainpool curve." if m.group(2) else "")),
    (re.compile(r"^(curve25519|x25519)$"), lambda m: Mapped("X25519", None, "group")),
    (re.compile(r"^(curve448|x448)$"), lambda m: Mapped("X448", None, "group")),
    (re.compile(r"^(?:ke\d_)?mlkem(512|768|1024)$"), lambda m: Mapped(f"ML-KEM-{m.group(1)}", None, "group",
                                                                      "Additional key exchange (RFC 9370).")),
]
_IKE_ENC = re.compile(r"^(aes|camellia)(128|192|256)?(ctr|gcm\d+|ccm\d+|ccm|gcm)?$")
_IKE_OTHER_ENC = {"3des": "3DES", "des": "DES", "blowfish": "Blowfish", "blowfish128": "Blowfish",
                  "cast128": "CAST-128", "chacha20poly1305": "ChaCha20", "null": "NULL"}
_IKE_INTEG = {"md5": "MD5", "md5_128": "MD5", "sha1": "SHA-1", "sha": "SHA-1", "sha1_160": "SHA-1",
              "sha256": "SHA-256", "sha2_256": "SHA-256", "sha384": "SHA-384", "sha2_384": "SHA-384",
              "sha512": "SHA-512", "sha2_512": "SHA-512", "aesxcbc": "AES-XCBC", "aescmac": "AES-CMAC"}


def ike_token(token: str) -> Mapped | None:
    """Map one strongSwan proposal keyword (`aes256gcm16`, `sha256`, `ecp384`, `ke1_mlkem768`)."""
    token = token.strip().lower().rstrip("!")
    if not token:
        return None
    for pattern, build in _IKE_GROUP:
        m = pattern.match(token)
        if m:
            return build(m)
    m = _IKE_ENC.match(token)
    if m and m.group(1) == "aes":
        bits = int(m.group(2) or 128)
        mode = (m.group(3) or "cbc").upper()
        return Mapped(f"AES-{bits}", bits, "cipher", f"{mode} mode.")
    if m:
        return Mapped(f"Camellia-{m.group(2) or 128}", None, "cipher")
    if token in _IKE_OTHER_ENC:
        return Mapped(_IKE_OTHER_ENC[token], None, "cipher")
    if token.startswith("prf"):
        digest = _IKE_INTEG.get(token[3:])
        return Mapped("HMAC", None, "prf", f"PRF over {digest}.") if digest else Mapped(token.upper(), None, "prf")
    if token in _IKE_INTEG:
        digest = _IKE_INTEG[token]
        if digest.startswith("AES"):
            return Mapped(digest, None, "integrity")
        return Mapped("HMAC", None, "integrity", f"HMAC-{digest}.")
    if token in ("esn", "noesn"):
        return None
    return Mapped(token, None, "unknown", "Not in the VERA IKE table.")


# --------------------------------------------------------------------------
# TLS named groups (OpenSSL, nginx, Apache, HAProxy, Java spellings)
# --------------------------------------------------------------------------

_TLS_GROUPS = {
    "x25519": ("X25519", None), "x448": ("X448", None),
    "p-256": ("ECDH", 256), "prime256v1": ("ECDH", 256), "secp256r1": ("ECDH", 256),
    "p-384": ("ECDH", 384), "secp384r1": ("ECDH", 384),
    "p-521": ("ECDH", 521), "secp521r1": ("ECDH", 521),
    "ffdhe2048": ("DH", 2048), "ffdhe3072": ("DH", 3072), "ffdhe4096": ("DH", 4096),
    "ffdhe6144": ("DH", 6144), "ffdhe8192": ("DH", 8192),
    "x25519mlkem768": ("X25519MLKEM768", None), "secp256r1mlkem768": ("SECP256R1MLKEM768", None),
    "secp384r1mlkem1024": ("SECP384R1MLKEM1024", None),
    "mlkem512": ("ML-KEM-512", None), "mlkem768": ("ML-KEM-768", None), "mlkem1024": ("ML-KEM-1024", None),
    "x25519kyber768draft00": ("X25519MLKEM768", None),
}


def tls_group(name: str) -> Mapped | None:
    key = name.strip().lower().lstrip("?*")
    if not key or key.startswith(("!", "-", "default")):
        return None
    algorithm, size = _TLS_GROUPS.get(key, (name.strip(), None))
    note = "Pre-standard Kyber draft; replace with X25519MLKEM768." if key == "x25519kyber768draft00" else ""
    return Mapped(algorithm, size, "group", note)
