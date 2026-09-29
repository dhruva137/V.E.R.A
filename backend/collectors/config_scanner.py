"""Configuration collector (plane: declared): what systems are told to negotiate.

FORMATS
-------
    OpenSSH       sshd_config / ssh_config: KexAlgorithms, HostKeyAlgorithms, Ciphers, MACs
    nginx         ssl_protocols, ssl_ciphers, ssl_ecdh_curve (+ ssl_conf_command Groups)
    Apache        SSLProtocol (+/- arithmetic), SSLCipherSuite, SSLOpenSSLConfCmd Curves/Groups
    HAProxy       ssl-default-bind-ciphers, ssl-min-ver, curves
    OpenSSL       openssl.cnf: MinProtocol, CipherString, Groups / Curves
    Java          java.security: jdk.tls.disabledAlgorithms (what is *not* disabled is the finding)
    IPsec         strongSwan ipsec.conf ike= / esp= / keyexchange=, swanctl.conf proposals /
                  esp_proposals / version, libreswan ikev2=
    Terraform     aws_kms_key, aws_acm_certificate, google_kms_crypto_key, azurerm_key_vault_key,
                  tls_private_key, aws_lb_listener ssl_policy, CloudFront minimum_protocol_version

Algorithm lists become one finding per algorithm, in preference order, because
each entry is separately negotiable and separately migrated (`position` records
the order). Protocol versions become findings only when deprecated: a config
that allows TLS 1.2 is not a weakness, one that still allows TLS 1.0 is.
OpenSSL cipher strings are read as a list: concrete suite names and weak
keywords that are enabled (`RC4`, not `!RC4`) become findings; meta keywords
such as `HIGH` or `DEFAULT` do not, because what they expand to depends on the
library build.

Files are recognised by name first, then by content, so an nginx site file
called `default` is still read as nginx. Wire names are translated by
`engine.protocol_names` and kept in `wire_name`.

STATED LIMITATIONS
------------------
- `Include` directives are not followed; each file is read on its own.
- Terraform is read with a structural regex, not an HCL parser: variables and
  modules are not resolved, and an unresolved value is reported as such.
- Defaults are not inferred. A server with no `KexAlgorithms` line uses its
  build's defaults, which only a live probe (the SSH and TLS collectors) shows.
"""

from __future__ import annotations

import re
from pathlib import Path

from collectors.base import DEFAULT_LIMITS, CollectResult, Limits, Timer, evidence, read_capped, stable_id, walk
from engine import protocol_names as names
from engine.taxonomy import classify_protocol
from models.schemas import RawCryptoFinding

COLLECTOR = "config_scanner"
CONFIDENCE = 0.70

_CONFIG_SUFFIXES = {".conf", ".cnf", ".cfg", ".config", ".tf", ".security", ""}
_CONFIG_NAMES = {"sshd_config", "ssh_config", "nginx.conf", "haproxy.cfg", "java.security", "openssl.cnf",
                 "ipsec.conf", "swanctl.conf", "httpd.conf", "apache2.conf", "ssl.conf"}
_DEPRECATED = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


class _Out:
    """Accumulates findings for one file with shared location and format."""

    def __init__(self, location: str, fmt: str):
        self.location, self.fmt = location, fmt
        self.findings: list[RawCryptoFinding] = []
        self._seen: set[tuple] = set()

    def add(self, line: int, directive: str, value: str, *, token: str, algorithm: str | None = None,
            key_size: int | None = None, protocol: str | None = None, cipher_suite: str | None = None,
            usage: str = "encryption", asset_class: str = "config", position: int | None = None,
            extra: dict | None = None) -> None:
        key = (line, directive, token, algorithm, protocol, cipher_suite)
        if key in self._seen:
            return
        self._seen.add(key)
        file_name = self.location.replace("\\", "/").rsplit("/", 1)[-1]
        details = {
            "type": "config_directive",
            "discovered_by": COLLECTOR,
            "plane": "declared",
            "provenance": "config_parsed",
            "confidence": CONFIDENCE,
            "format": self.fmt,
            "directive": directive,
            "value": value[:300],
            "wire_name": token,
            "evidence_refs": [evidence(COLLECTOR, self.location, line=line)],
            "display_name": f"{algorithm or protocol or cipher_suite or token} ({directive}, {file_name}:{line})",
        }
        if position is not None:
            details["position"] = position
        details.update(extra or {})
        self.findings.append(RawCryptoFinding(
            id=stable_id("config", self.location, line, directive, token, algorithm or protocol or cipher_suite),
            source_type="config", source_location=f"{self.location}:{line}", asset_class=asset_class,
            algorithm=algorithm, key_size=key_size, protocol=protocol, cipher_suite=cipher_suite,
            usage=usage, tags=["config-scan", f"format:{self.fmt}"], raw_details=details,
        ))

    def mapped(self, line: int, directive: str, value: str, mapped: names.Mapped | None, token: str,
               position: int, usage: str, asset_class: str = "config", extra: dict | None = None) -> None:
        if mapped is None:
            return
        self.add(line, directive, value, token=token, algorithm=mapped.algorithm, key_size=mapped.key_size,
                 usage=usage, asset_class=asset_class, position=position,
                 extra={"role": mapped.role, **({"note": mapped.note} if mapped.note else {}), **(extra or {})})

    def protocol(self, line: int, directive: str, value: str, version: str, extra: dict | None = None) -> None:
        if version in _DEPRECATED and classify_protocol(version)[0] == "classical":
            self.add(line, directive, value, token=version, protocol=version, extra=extra)


def _lines(text: str):
    """(line number, stripped line) skipping blanks and full-line comments."""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line and not line.startswith(("#", ";", "//")):
            yield number, line


def _split_list(value: str) -> list[str]:
    return [t for t in re.split(r"[,:\s]+", value.strip().strip('"\';')) if t]


# --------------------------------------------------------------------------
# OpenSSL cipher strings
# --------------------------------------------------------------------------

_META = {"DEFAULT", "ALL", "HIGH", "MEDIUM", "COMPLEMENTOFDEFAULT", "COMPLEMENTOFALL", "FIPS", "SUITEB128",
         "SUITEB128ONLY", "SUITEB192", "PROFILE=SYSTEM", "ECDHE", "EECDH", "EDH", "DHE", "AESGCM", "AES",
         "AES128", "AES256", "CHACHA20", "SHA256", "SHA384", "SHA", "TLSV1.2", "TLSV1", "SSLV3", "KEECDH",
         "KEDH", "AECDSA", "ARSA", "KRSA", "RSA", "ECDSA", "CAMELLIA", "ARIA", "PSK", "SRP", "KECDHE"}
_WEAK = {"RC4": "RC4", "DES": "DES", "3DES": "3DES", "MD5": "MD5", "EXPORT": "EXPORT", "EXP": "EXPORT",
         "NULL": "NULL", "ENULL": "NULL", "ANULL": "NULL", "LOW": "LOW", "IDEA": "IDEA", "SEED": "SEED"}


def _cipher_string(out: _Out, line: int, directive: str, value: str) -> None:
    for position, token in enumerate(t for t in re.split(r"[:,\s]+", value.strip().strip('"\';')) if t):
        if token.startswith(("!", "-", "@", "+")):
            continue
        upper = token.upper()
        if upper in _WEAK:
            weak = _WEAK[upper]
            out.add(line, directive, value, token=token,
                    algorithm=weak if weak in {"RC4", "DES", "3DES", "MD5"} else None,
                    cipher_suite=None if weak in {"RC4", "DES", "3DES", "MD5"} else token,
                    position=position, extra={"cipher_keyword": True, "note": f"'{token}' is enabled, not excluded."})
        elif upper in _META or upper.startswith("SECLEVEL") or "=" in upper:
            continue
        elif "-" in token or upper.startswith("TLS_"):
            out.add(line, directive, value, token=token, cipher_suite=token, position=position)


# --------------------------------------------------------------------------
# Format parsers
# --------------------------------------------------------------------------

_SSH_DIRECTIVES = {"kexalgorithms": ("kex", "key_exchange"), "hostkeyalgorithms": ("host_key", "signing"),
                   "pubkeyacceptedalgorithms": ("host_key", "signing"), "pubkeyacceptedkeytypes": ("host_key", "signing"),
                   "casignaturealgorithms": ("host_key", "signing"), "ciphers": ("cipher", "encryption"),
                   "macs": ("mac", "authentication")}


def parse_ssh(out: _Out, text: str) -> None:
    for number, line in _lines(text):
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        directive, value = parts
        spec = _SSH_DIRECTIVES.get(directive.lower())
        if not spec:
            continue
        role, usage = spec
        for position, token in enumerate(t for t in value.split(",") if t):
            if token.startswith(("-", "^")):
                token = token[1:]               # a modifier on the default list, still a named algorithm
            if token.startswith("+"):
                token = token[1:]
            out.mapped(number, directive, value, names.ssh(token, role), token, position, usage)


def parse_nginx(out: _Out, text: str) -> None:
    for number, line in _lines(text):
        m = re.match(r"(ssl_protocols|ssl_ciphers|ssl_ecdh_curve|proxy_ssl_protocols|proxy_ssl_ciphers)\s+([^;]+);?", line)
        if m:
            directive, value = m.group(1), m.group(2).strip().strip('"')
            if directive.endswith("protocols"):
                for token in value.split():
                    out.protocol(number, directive, value, _proto(token))
            elif directive.endswith("ciphers"):
                _cipher_string(out, number, directive, value)
            else:
                for position, token in enumerate(_split_list(value)):
                    out.mapped(number, directive, value, names.tls_group(token), token, position, "key_exchange")
            continue
        m = re.match(r"ssl_conf_command\s+(Groups|Curves|MinProtocol)\s+([^;]+);?", line, re.I)
        if m:
            _openssl_command(out, number, f"ssl_conf_command {m.group(1)}", m.group(1), m.group(2))


def _proto(token: str) -> str:
    token = token.strip().strip('";').lstrip("+")
    return {"TLSv1": "TLSv1.0", "SSLv3": "SSLv3", "SSLv2": "SSLv2"}.get(token, token)


_APACHE_ALL = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def _apache_enabled(value: str) -> list[str]:
    """Protocol versions an SSLProtocol line leaves enabled (`all -SSLv3 -TLSv1` -> 1.1, 1.2, 1.3)."""
    enabled: list[str] = []
    for token in value.split():
        sign, name = (token[0], token[1:]) if token[0] in "+-" else ("+", token)
        for version in (_APACHE_ALL if name.lower() == "all" else [_proto(name)]):
            if sign == "-" and version in enabled:
                enabled.remove(version)
            elif sign == "+" and version not in enabled:
                enabled.append(version)
    return enabled


def parse_apache(out: _Out, text: str) -> None:
    for number, line in _lines(text):
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        directive, value = parts[0], parts[1].strip().strip('"')
        low = directive.lower()
        if low in ("sslprotocol", "sslproxyprotocol"):
            for version in _apache_enabled(value):
                out.protocol(number, directive, value, version, {"resolved_from": value})
        elif low in ("sslciphersuite", "sslproxyciphersuite"):
            tokens = value.split(None, 1)       # Apache 2.4.36+: optional "SSL" / "TLSv1.3" prefix
            cipher_value = tokens[1] if len(tokens) == 2 and tokens[0] in ("SSL", "TLSv1.3") else value
            _cipher_string(out, number, directive, cipher_value)
        elif low == "sslopensslconfcmd":
            sub = value.split(None, 1)
            if len(sub) == 2:
                _openssl_command(out, number, f"SSLOpenSSLConfCmd {sub[0]}", sub[0], sub[1])


def parse_haproxy(out: _Out, text: str) -> None:
    for number, line in _lines(text):
        m = re.match(r"(ssl-default-(?:bind|server)-ciphers|ssl-default-(?:bind|server)-ciphersuites)\s+(\S+)", line)
        if m:
            _cipher_string(out, number, m.group(1), m.group(2))
        for m in re.finditer(r"\bssl-min-ver\s+(\S+)", line):
            version = {"SSLv3": "SSLv3", "TLSv1.0": "TLSv1.0", "TLSv1.1": "TLSv1.1"}.get(m.group(1))
            if version:
                out.protocol(number, "ssl-min-ver", m.group(1), version)
        for m in re.finditer(r"\bcurves\s+(\S+)", line):
            for position, token in enumerate(_split_list(m.group(1))):
                out.mapped(number, "curves", m.group(1), names.tls_group(token), token, position, "key_exchange")


def _openssl_command(out: _Out, line: int, directive: str, key: str, value: str) -> None:
    key = key.strip().lower()
    value = value.strip().strip('";')
    if key in ("groups", "curves"):
        for position, token in enumerate(_split_list(value)):
            out.mapped(line, directive, value, names.tls_group(token), token, position, "key_exchange")
    elif key == "minprotocol":
        version = _proto(value)
        if version in ("TLSv1.0", "TLSv1.1", "SSLv3"):
            out.protocol(line, directive, value, version, {"note": f"Minimum protocol {version}: older versions accepted."})
    elif key in ("cipherstring", "ciphersuites"):
        _cipher_string(out, line, directive, value)


def parse_openssl_cnf(out: _Out, text: str) -> None:
    for number, line in _lines(text):
        m = re.match(r"(MinProtocol|CipherString|Ciphersuites|Groups|Curves)\s*=\s*(.+)", line, re.I)
        if m:
            _openssl_command(out, number, m.group(1), m.group(1), m.group(2))


_JAVA_MUST_DISABLE = {"SSLv3": ("protocol", "SSLv3"), "TLSv1": ("protocol", "TLSv1.0"),
                      "TLSv1.1": ("protocol", "TLSv1.1"), "RC4": ("algorithm", "RC4"),
                      "DES": ("algorithm", "DES"), "3DES_EDE_CBC": ("algorithm", "3DES"),
                      "MD5withRSA": ("algorithm", "MD5")}


def parse_java_security(out: _Out, text: str) -> None:
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    m = re.search(r"^\s*jdk\.tls\.disabledAlgorithms\s*=\s*(.+)$", joined, re.M)
    if not m:
        return
    value = m.group(1).strip()
    line = text[: text.find("jdk.tls.disabledAlgorithms")].count("\n") + 1
    disabled = {entry.strip().split()[0] for entry in value.split(",") if entry.strip()}
    for name, (field, canonical) in _JAVA_MUST_DISABLE.items():
        if name in disabled:
            continue
        extra = {"permitted_because": "not listed in jdk.tls.disabledAlgorithms"}
        if field == "protocol":
            out.protocol(line, "jdk.tls.disabledAlgorithms", value, canonical, extra)
        else:
            out.add(line, "jdk.tls.disabledAlgorithms", value, token=name, algorithm=canonical, extra=extra)
    for rsa_min in re.findall(r"RSA keySize\s*<\s*(\d+)", value):
        if int(rsa_min) < 2048:
            out.add(line, "jdk.tls.disabledAlgorithms", value, token=f"RSA keySize < {rsa_min}", algorithm="RSA",
                    key_size=int(rsa_min), usage="signing",
                    extra={"note": f"RSA keys from {rsa_min} bits upward are accepted."})


def _ike_proposals(out: _Out, line: int, directive: str, value: str, version: dict | None = None) -> None:
    usage_for = {"group": "key_exchange", "cipher": "encryption", "integrity": "authentication",
                 "prf": "key_derivation", "unknown": "encryption"}
    for proposal in (p for p in value.split(",") if p.strip()):
        for position, token in enumerate(t for t in proposal.strip().split("-") if t):
            mapped = names.ike_token(token)
            if mapped is None:
                continue
            out.mapped(line, directive, value, mapped, token.rstrip("!"), position,
                       usage_for.get(mapped.role, "encryption"), asset_class="vpn_ipsec", extra=version)


# IKE version. It is a connection setting, not part of a proposal, so it is
# resolved per connection and attached to every proposal finding in it. The
# recorded version is the lowest one the connection accepts, as for TLS: that
# is the one a peer can negotiate down to. Where the file does not state it,
# the implementation's documented default applies only when the file is
# recognisably that implementation's; otherwise the version stays unset.
_KEYEXCHANGE = {"ikev1": ("1",), "ikev2": ("2",), "ike": ("1", "2")}
_LIBRESWAN_IKEV2 = {"insist": ("2",), "yes": ("2",), "permit": ("1", "2"), "propose": ("1", "2"),
                    "no": ("1",), "never": ("1",)}
_SWANCTL_VERSION = {"0": ("1", "2"), "1": ("1",), "2": ("2",)}
_STRONGSWAN_DEFAULT = ("strongSwan default: initiates IKEv2 and, as responder, also accepts IKEv1 "
                       "(pin keyexchange=ikev2 / version = 2 to refuse IKEv1)")


def _ike_version(accepted: tuple[str, ...], source: str) -> dict:
    return {"ike_version": min(accepted), "ike_versions_accepted": list(accepted), "ike_version_source": source}


def _ipsec_sections(text: str):
    """(line number, connection name or None, stripped line) for ipsec.conf.

    Section headers (`conn`, `config`, `ca`) start at column 0; their
    parameters are indented. A parameter outside any section keeps None.
    """
    section = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        header = re.match(r"(conn|config|ca)\s+(\S+)", line)
        if header and not raw[:1].isspace():
            section = header.group(2) if header.group(1) == "conn" else None
            continue
        yield number, section, line


def parse_ipsec_conf(out: _Out, text: str) -> None:
    stated: dict[str | None, dict] = {}
    for number, section, line in _ipsec_sections(text):
        m = re.match(r"keyexchange\s*=\s*(\S+)", line)
        if m and m.group(1).lower() in _KEYEXCHANGE:
            stated[section] = _ike_version(_KEYEXCHANGE[m.group(1).lower()], f"stated: keyexchange={m.group(1)} (line {number})")
        m = re.match(r"ikev2\s*=\s*(\S+)", line)
        if m and m.group(1).lower() in _LIBRESWAN_IKEV2:
            stated[section] = _ike_version(_LIBRESWAN_IKEV2[m.group(1).lower()], f"stated: ikev2={m.group(1)} (line {number})")
    # A strict proposal (trailing "!") is strongSwan syntax; without it the file could be libreswan's.
    strongswan = bool(re.search(r"^\s*(ike|esp)\s*=\s*\S*!", text, re.M))
    fallback = stated.get("%default") or (_ike_version(("1", "2"), _STRONGSWAN_DEFAULT) if strongswan else None)
    for number, section, line in _ipsec_sections(text):
        m = re.match(r"(ike|esp|ah|phase1alg|phase2alg)\s*=\s*(\S+)", line)
        if m:
            _ike_proposals(out, number, m.group(1), m.group(2), stated.get(section) or fallback)


def _swanctl_versions(text: str) -> dict[int, dict]:
    """Line number -> IKE version of the connection that line sits in."""
    lines = text.splitlines()
    by_line: dict[int, dict] = {}
    depth, in_connections, start, version = 0, False, None, None
    for number, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0]
        if depth == 0 and re.match(r"\s*connections\s*\{", line):
            in_connections = True
        elif in_connections and depth == 1 and re.match(r"\s*[\w.-]+\s*\{", line):
            start, version = number, None
        m = re.search(r"\bversion\s*=\s*([012])\b", line)
        # The depth at the setting itself, since "name { version = 2" opens the block on the same line.
        if in_connections and m and depth + line[:m.start()].count("{") - line[:m.start()].count("}") == 2:
            version = _ike_version(_SWANCTL_VERSION[m.group(1)], f"stated: version = {m.group(1)} (line {number})")
        depth += line.count("{") - line.count("}")
        if in_connections and start is not None and depth == 1:
            for n in range(start, number + 1):
                by_line[n] = version or _ike_version(("1", "2"), _STRONGSWAN_DEFAULT)
            start = None
        if depth == 0:
            in_connections = False
    return by_line


def parse_swanctl(out: _Out, text: str) -> None:
    versions = _swanctl_versions(text)
    for number, line in _lines(text):
        for m in re.finditer(r"\b(proposals|esp_proposals|ah_proposals)\s*=\s*([^\s}]+)", line):
            if m.group(2) != "default":
                _ike_proposals(out, number, m.group(1), m.group(2), versions.get(number))


# Terraform ------------------------------------------------------------------

_TF_RESOURCE = re.compile(r'resource\s+"(\w+)"\s+"([\w-]+)"\s*\{')


def _tf_blocks(text: str):
    for m in _TF_RESOURCE.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield m.group(1), m.group(2), text[m.end():i - 1], text.count("\n", 0, m.start()) + 1


def _tf_attr(body: str, name: str) -> tuple[str | None, bool]:
    """(value, is_literal). A variable or expression is not a literal."""
    m = re.search(rf"^\s*{name}\s*=\s*(.+)$", body, re.M)
    if not m:
        return None, True
    raw = m.group(1).split("#", 1)[0].strip()
    if raw.startswith('"') and raw.endswith('"') and "${" not in raw:
        return raw.strip('"'), True
    if re.fullmatch(r"\d+", raw):
        return raw, True
    return raw, False


def _tf_key_spec(spec: str) -> tuple[str, int | None]:
    upper = spec.upper()
    if upper in ("SYMMETRIC_DEFAULT", "GOOGLE_SYMMETRIC_ENCRYPTION", "AES_256_GCM", "OCT", "OCT-HSM"):
        return "AES-256", 256
    m = re.search(r"ML_DSA_(44|65|87)", upper)
    if m:
        return f"ML-DSA-{m.group(1)}", None
    if "SLH_DSA" in upper:
        return "SLH-DSA", None
    if upper.startswith("HMAC"):
        return "HMAC", None
    m = re.search(r"RSA\D*?(\d{4})", upper)
    if m or upper.startswith("RSA"):
        return "RSA", int(m.group(1)) if m else None
    m = re.search(r"(?:P|NIST_P|PRIME|SECP)-?(256|384|521)", upper)
    if m or upper.startswith(("EC", "ECC")):
        return "ECDSA", int(m.group(1)) if m else None
    return spec, None


_ELB_TLS10 = re.compile(r"^ELBSecurityPolicy-(2016-08|2015-0[235]|TLS-1-0-.*|FS-2018-06)$")
_ELB_TLS11 = re.compile(r"^ELBSecurityPolicy-(TLS-1-1-.*|FS-1-1-.*)$")


def parse_terraform(out: _Out, text: str) -> None:
    for rtype, rname, body, line in _tf_blocks(text):
        resource = f"{rtype}.{rname}"
        extra = {"resource": resource}
        spec_attr = {"aws_kms_key": ("customer_master_key_spec", "SYMMETRIC_DEFAULT", "generic_key"),
                     "aws_acm_certificate": ("key_algorithm", "RSA_2048", "tls_certificate"),
                     "google_kms_crypto_key": ("algorithm", "GOOGLE_SYMMETRIC_ENCRYPTION", "generic_key")}.get(rtype)
        if rtype == "aws_kms_key" and _tf_attr(body, "key_spec")[0]:
            spec_attr = ("key_spec", "SYMMETRIC_DEFAULT", "generic_key")
        if spec_attr:
            attr, default, asset_class = spec_attr
            value, literal = _tf_attr(body, attr)
            if value is None:
                value, literal = default, True
                extra = {**extra, "defaulted": f"{attr} not set; provider default {default}"}
            if not literal:
                out.add(line, f"{resource}.{attr}", value, token=value, algorithm=None, asset_class=asset_class,
                        extra={**extra, "unresolved": True,
                               "note": f"{attr} is an expression ({value}); resolve the variable to classify it."})
                continue
            algorithm, size = _tf_key_spec(value)
            usage = "signing" if "SIGN" in (value.upper() + (_tf_attr(body, "key_usage")[0] or "").upper()) else "encryption"
            out.add(line, f"{resource}.{attr}", value, token=value, algorithm=algorithm, key_size=size,
                    usage=usage, asset_class=asset_class, extra=extra)
        elif rtype == "azurerm_key_vault_key":
            key_type, _ = _tf_attr(body, "key_type")
            size, _ = _tf_attr(body, "key_size")
            curve, _ = _tf_attr(body, "curve")
            if key_type:
                algorithm, bits = _tf_key_spec(f"{key_type}_{size or curve or ''}")
                out.add(line, f"{resource}.key_type", key_type, token=key_type, algorithm=algorithm,
                        key_size=int(size) if size and size.isdigit() else bits, asset_class="generic_key", extra=extra)
        elif rtype == "tls_private_key":
            algorithm, _ = _tf_attr(body, "algorithm")
            bits, _ = _tf_attr(body, "rsa_bits")
            curve, _ = _tf_attr(body, "ecdsa_curve")
            if algorithm:
                canonical = {"RSA": "RSA", "ECDSA": "ECDSA", "ED25519": "Ed25519"}.get(algorithm.upper(), algorithm)
                size = int(bits) if canonical == "RSA" and bits else (2048 if canonical == "RSA" else None)
                if canonical == "ECDSA" and curve:
                    size = int(re.sub(r"\D", "", curve) or 0) or None
                out.add(line, f"{resource}.algorithm", algorithm, token=algorithm, algorithm=canonical, key_size=size,
                        usage="signing", asset_class="generic_key", extra=extra)
        elif rtype in ("aws_lb_listener", "aws_alb_listener"):
            policy, literal = _tf_attr(body, "ssl_policy")
            if policy and literal:
                version = "TLSv1.0" if _ELB_TLS10.match(policy) else "TLSv1.1" if _ELB_TLS11.match(policy) else None
                if version:
                    out.protocol(line, f"{resource}.ssl_policy", policy, version,
                                 {**extra, "note": f"{policy} still accepts {version}."})
        elif rtype == "aws_cloudfront_distribution":
            minimum, literal = _tf_attr(body, "minimum_protocol_version")
            if minimum and literal:
                version = {"SSLv3": "SSLv3", "TLSv1": "TLSv1.0", "TLSv1_2016": "TLSv1.0",
                           "TLSv1.1_2016": "TLSv1.1"}.get(minimum)
                if version:
                    out.protocol(line, f"{resource}.minimum_protocol_version", minimum, version, extra)


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

_PARSERS = {"ssh": parse_ssh, "nginx": parse_nginx, "apache": parse_apache, "haproxy": parse_haproxy,
            "openssl": parse_openssl_cnf, "java": parse_java_security, "ipsec": parse_ipsec_conf,
            "swanctl": parse_swanctl, "terraform": parse_terraform}


def detect_format(location: str, text: str) -> str | None:
    """Which parser reads this file: by name first, then by content."""
    name = location.replace("\\", "/").rsplit("/", 1)[-1].split(":", 1)[0].lower()
    by_name = {"sshd_config": "ssh", "ssh_config": "ssh", "nginx.conf": "nginx", "haproxy.cfg": "haproxy",
               "openssl.cnf": "openssl", "java.security": "java", "ipsec.conf": "ipsec",
               "swanctl.conf": "swanctl", "httpd.conf": "apache", "apache2.conf": "apache", "ssl.conf": "apache"}
    if name in by_name:
        return by_name[name]
    if name.endswith(".tf"):
        return "terraform"
    if re.search(r"^\s*(KexAlgorithms|HostKeyAlgorithms|Ciphers|MACs)\s", text, re.M | re.I):
        return "ssh"
    if re.search(r"^\s*ssl_(protocols|ciphers|ecdh_curve)\s", text, re.M):
        return "nginx"
    if re.search(r"^\s*SSL(Protocol|CipherSuite|OpenSSLConfCmd)\s", text, re.M | re.I):
        return "apache"
    if re.search(r"^\s*ssl-default-bind-", text, re.M):
        return "haproxy"
    if re.search(r"^\s*(ike|esp)\s*=", text, re.M):
        return "ipsec"
    if re.search(r"^\s*(esp_)?proposals\s*=", text, re.M):
        return "swanctl"
    if re.search(r"^\s*(MinProtocol|CipherString)\s*=", text, re.M):
        return "openssl"
    if "jdk.tls.disabledAlgorithms" in text:
        return "java"
    return None


def scan_text(text: str, location: str) -> list[RawCryptoFinding]:
    """Scan configuration text already in memory (used by the container collector)."""
    fmt = detect_format(location, text)
    if fmt is None:
        return []
    out = _Out(location, fmt)
    _PARSERS[fmt](out, text)
    return out.findings


# --------------------------------------------------------------------------
# Declared posture (for drift): what a host is *told* to allow
# --------------------------------------------------------------------------

_WEAK_CIPHER_TOKENS = ("3DES", "DES-CBC3", "RC4", "DES-CBC-", "NULL", "EXPORT")


def _cipher_posture(value: str) -> dict:
    tokens = [t for t in re.split(r"[:,\s]+", value.strip().strip('"\';')) if t]
    enabled = [t for t in tokens if not t.startswith(("!", "-", "@", "+"))]
    excluded = [t.lstrip("!-") for t in tokens if t.startswith(("!", "-"))]
    return {"ciphers": value, "ciphers_enabled": enabled, "ciphers_excluded": excluded,
            "weak_cipher_enabled": any(w in t.upper() for t in enabled for w in _WEAK_CIPHER_TOKENS)}


def declarations(text: str, location: str) -> list[dict]:
    """Posture facts a drift rule can compare with observations.

    `tls_policy`: hosts (server_name + listen port), allowed protocols, cipher
    list. `ssh_policy`: hosts (ListenAddress + Port) and key-exchange list.
    Hosts are empty when the file does not name them; the scan job then binds
    the file to the host the operator declared for it.
    """
    fmt = detect_format(location, text)
    facts: list[dict] = []
    if fmt == "nginx":
        for block, start in _nginx_server_blocks(text):
            names_ = re.findall(r"^\s*server_name\s+([^;]+);", block, re.M)
            ports = re.findall(r"^\s*listen\s+(?:[\w.\[\]:]*:)?(\d+)[^;]*ssl", block, re.M) or ["443"]
            hosts = [f"{n}:{p}" for line in names_ for n in line.split() if n not in ("_", "localhost")
                     for p in ports]
            fact = {"kind": "tls_policy", "format": "nginx", "hosts": hosts, "location": f"{location}:{start}"}
            proto = re.search(r"^\s*ssl_protocols\s+([^;]+);", block, re.M)
            if proto:
                fact["protocols"] = [_proto(t) for t in proto.group(1).split()]
            ciphers = re.search(r"^\s*ssl_ciphers\s+([^;]+);", block, re.M)
            if ciphers:
                fact.update(_cipher_posture(ciphers.group(1)))
            if "protocols" in fact or "ciphers" in fact:
                facts.append(fact)
    elif fmt == "apache":
        for block, start in _apache_vhosts(text):
            server = re.search(r"^\s*ServerName\s+(\S+)", block, re.M | re.I)
            port = re.search(r"<VirtualHost\s+[^:>]*:(\d+)", block, re.I)
            hosts = [f"{server.group(1)}:{port.group(1) if port else '443'}"] if server else []
            fact = {"kind": "tls_policy", "format": "apache", "hosts": hosts, "location": f"{location}:{start}"}
            proto = re.search(r"^\s*SSLProtocol\s+(.+)$", block, re.M | re.I)
            if proto:
                fact["protocols"] = _apache_enabled(proto.group(1))
            ciphers = re.search(r"^\s*SSLCipherSuite\s+(.+)$", block, re.M | re.I)
            if ciphers:
                fact.update(_cipher_posture(ciphers.group(1)))
            if "protocols" in fact or "ciphers" in fact:
                facts.append(fact)
    elif fmt == "ssh":
        kex = re.search(r"^\s*KexAlgorithms\s+(\S+)", text, re.M | re.I)
        if kex:
            port = re.search(r"^\s*Port\s+(\d+)", text, re.M | re.I)
            addresses = re.findall(r"^\s*ListenAddress\s+(\S+)", text, re.M | re.I)
            hosts = [a if re.search(r":\d+$", a) and a.count(":") == 1 else f"{a}:{port.group(1) if port else 22}"
                     for a in addresses]
            facts.append({"kind": "ssh_policy", "format": "ssh", "hosts": hosts,
                          "kex": [t.lstrip("+-^") for t in kex.group(1).split(",") if t],
                          "location": f"{location}:{text[: kex.start()].count(chr(10)) + 1}"})
    return facts


def _nginx_server_blocks(text: str):
    for m in re.finditer(r"\bserver\s*\{", text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        yield text[m.end():i - 1], text.count("\n", 0, m.start()) + 1


def _apache_vhosts(text: str):
    blocks = list(re.finditer(r"<VirtualHost[^>]*>(.*?)</VirtualHost>", text, re.S | re.I))
    if not blocks:
        yield text, 1
    for m in blocks:
        yield m.group(0), text.count("\n", 0, m.start()) + 1


def _scan_file(path: Path) -> list[RawCryptoFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_text(text, str(path))


def scan_configs(paths: list[str]) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Scan real configuration paths. Returns (findings, unreadable)."""
    findings: list[RawCryptoFinding] = []
    unreadable: list[dict] = []

    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            unreadable.append({"path": raw_path, "reason": "path does not exist"})
            continue

        if path.is_dir():
            candidates = [
                p for p in sorted(path.rglob("*"))
                if p.is_file() and not p.is_symlink()
                and (p.suffix.lower() in _CONFIG_SUFFIXES or p.name in _CONFIG_NAMES)
                and ".git" not in p.parts and p.stat().st_size <= 2 * 1024 * 1024
            ]
        else:
            candidates = [path]

        for candidate in candidates:
            findings.extend(_scan_file(candidate))

    return findings, unreadable


class ConfigCollector:
    """Collector-contract implementation; see `collectors.base.Collector`.

    Besides findings it returns `declarations`: the posture each file declares,
    which drift rules compare with what live collectors observe.
    """

    name = "config"
    plane = "declared"
    label = "Configuration & IaC"
    description = "SSH, nginx, Apache, HAProxy, OpenSSL, Java, strongSwan and Terraform crypto directives."
    target_kinds = ("path", "repo")

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult:
        result = CollectResult(stats={"files_seen": 0, "config_files": 0, "by_format": {}})
        timer = Timer(limits)
        for target in targets:
            for path in walk(Path(target), limits, result):
                if timer.expired:
                    result.fail(target, f"stopped after {limits.timeout_s:.0f}s (timeout)")
                    break
                result.stats["files_seen"] += 1
                if not (path.suffix.lower() in _CONFIG_SUFFIXES or path.name in _CONFIG_NAMES):
                    continue
                data = read_capped(path, limits.max_text_bytes, result)
                if data is None:
                    continue
                text = data.decode("utf-8", errors="replace")
                fmt = detect_format(str(path), text)
                if fmt is None:
                    continue
                result.stats["config_files"] += 1
                result.stats["by_format"][fmt] = result.stats["by_format"].get(fmt, 0) + 1
                result.findings.extend(scan_text(text, str(path)))
                result.declarations.extend(declarations(text, str(path)))
        result.stats["duration_ms"] = timer.elapsed_ms
        return result
