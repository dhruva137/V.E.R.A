"""Binary collector (plane: built): cryptography compiled into shipped artefacts.

WHAT IT READS
-------------
ELF, PE and Mach-O executables and libraries, JAR/WAR/EAR archives and loose
`.class` files. Structure (linked libraries, imported and exported symbols) is
read with LIEF when it is installed, with pyelftools as the ELF fallback. The
parser used is recorded on every finding, and a structure that could not be
read is a reported failure, never a silent gap. Bytes are then read in 16 MB
windows for version banners, constant tables and PEM markers.

DETECTION LAYERS (each finding records which fired; rules in rules/binary_rules.yaml)
    linked_library        DT_NEEDED / PE imports / dylibs: libssl, bcrypt.dll, ...  0.80
    symbol                RSA_*, EC_KEY_*, mbedtls_*, wc_*, crypto_box*, BCrypt*     0.85
    version_banner        "OpenSSL 3.0.18", "wolfSSL 5.7.0", Go build version        0.70
    cng_algorithm_id      UTF-16 "ECDSA_P256" next to BCrypt imports                 0.70
    constant              AES S-box, SHA-256 K, MD5 T, DES S1, P-256 prime, ...      0.60
    jar_constant_pool     "AES/ECB/PKCS5Padding" in classes that call a JCA API       0.75
    embedded_certificate  PEM certificate parsed (public data)                        0.90
    embedded_private_key  PEM private-key marker; the body is never read             0.70
    pqc_table             ML-KEM / ML-DSA NTT twiddle table (engine/binary_ml/signatures)  0.90
                          - migration assurance: what the shipped binary actually contains
    learned_function      disassembly + v1 model + conformal FDR selection, ONLY when no
                          other layer found anything in the binary (engine/binary_ml)     0.60

WHAT IT PRODUCES
----------------
- One `crypto_library` finding per library a binary links, bundles or *is*, with
  the version when a banner gives it, and the KB answer to "does this version
  block PQC migration?" (engine/kb/libraries.py).
- One `binary` finding per algorithm an application binary uses (imports,
  constants, Go packages, JCA strings), with the symbols or offsets as evidence.
  A known crypto library's own exports are recorded on its library finding
  (`implements`), not as uses: libcrypto implementing DES is not a DES use.
- Embedded certificates and private-key markers.

STATED LIMITATIONS
------------------
- No execution or dataflow. Disassembly is used only by the learned_function
  layer, which says *that* a function looks cryptographic, with a q-value, not
  *which* algorithm it is; it runs on ELF/PE for x86-64, AArch64 and ARM32 and
  skips (and reports) binaries over VERA_DETECTOR_MAX_FUNCTIONS. An algorithm
  chosen at runtime from a string is found only when that string is a
  recognisable constant.
- Constant tables can false-positive (data can look like code) and are missed
  when an implementation computes its tables at start-up.
- A version is reported only when a banner states it. Linking `libcrypto-3`
  says the major version, not whether it is 3.0 or 3.5, so the answer stays
  "unknown" rather than being inferred from the file name.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable

import yaml

from collectors.base import (
    DEFAULT_LIMITS, CollectResult, Limits, Timer, evidence, read_capped, stable_id, walk,
)
from engine.binary_ml import detector as learned
from engine.binary_ml.functions import functions_in_bytes
from engine.binary_ml.signatures import scan as pqc_tables
from engine.kb import libraries as kb
from engine.taxonomy import classify_algorithm
from models.schemas import RawCryptoFinding

try:  # LIEF is the primary structure parser; its absence is reported, not hidden.
    import lief
    lief.logging.disable()
    _HAVE_LIEF = True
except ImportError:  # pragma: no cover - exercised only on hosts without LIEF
    lief = None
    _HAVE_LIEF = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection
    _HAVE_ELFTOOLS = True
except ImportError:  # pragma: no cover
    _HAVE_ELFTOOLS = False

RULES_PATH = Path(__file__).resolve().parent / "rules" / "binary_rules.yaml"
COLLECTOR = "binary_scanner"
GO_BUILDINFO = b"\xff Go buildinf:"
_WINDOW_OVERLAP = 4096
_MAX_OFFSETS = 5
_MAX_SYMBOLS = 12
_MAX_SUITES = 20
_MAX_NESTED_JAR_BYTES = 64 * 1024 * 1024

_USAGE_BY_PRIMITIVE = {
    "signature": "signing", "pke": "encryption", "key-agree": "key_exchange", "kem": "key_exchange",
    "hash": "hashing", "mac": "authentication", "kdf": "key_derivation",
    "block-cipher": "encryption", "stream-cipher": "encryption", "ae": "encryption",
}


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rules:
    layers: dict[str, float]
    symbols: tuple[tuple[re.Pattern, str | None, str | None], ...]
    require_symbol_for: frozenset[str]
    go_packages: tuple[tuple[re.Pattern, str], ...]
    cng_ids: tuple[tuple[bytes, str, str], ...]
    cipher_suite: re.Pattern
    jca_api_classes: frozenset[str]
    jca_strings: tuple[tuple[re.Pattern, str], ...]
    pem_certificate: bytes
    pem_private_key: re.Pattern
    constants: tuple[tuple[str, str, str, tuple[bytes, ...]], ...]


@lru_cache(maxsize=1)
def rules() -> _Rules:
    raw = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    return _Rules(
        layers={k: float(v) for k, v in raw["layers"].items()},
        symbols=tuple((re.compile(r["pattern"]), r.get("algorithm"), r.get("library"))
                      for r in raw["symbols"]),
        require_symbol_for=frozenset(n.lower() for n in raw.get("require_symbol_for", [])),
        go_packages=tuple((re.compile(r["pattern"].encode()), r["algorithm"])
                          for r in raw.get("go_packages", [])),
        cng_ids=tuple((r["id"].encode("utf-16-le"), r["id"], r["algorithm"])
                      for r in raw.get("cng_algorithm_ids", [])),
        cipher_suite=re.compile(raw["cipher_suite_pattern"].encode()),
        jca_api_classes=frozenset(raw.get("jca_api_classes", [])),
        jca_strings=tuple((re.compile(r["pattern"]), r["kind"]) for r in raw.get("jca_strings", [])),
        pem_certificate=raw["pem_certificate"].encode(),
        pem_private_key=re.compile(raw["pem_private_key"].encode()),
        constants=tuple(
            (c["id"], c["algorithm"], c.get("note", ""), tuple(bytes.fromhex(h) for h in c["hex"]))
            for c in raw["constants"]
        ),
    )


# --------------------------------------------------------------------------
# Format sniffing and structure
# --------------------------------------------------------------------------

_MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
_ARCHIVE_SUFFIXES = {".jar", ".war", ".ear"}


def sniff(head: bytes, name: str) -> str | None:
    """File format from its first bytes: elf | pe | macho | jar | class | None."""
    suffix = Path(name).suffix.lower()
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in _MACHO_MAGICS:
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe":
        # Java class files and fat Mach-O share this magic; the suffix decides.
        return "class" if suffix == ".class" else "macho"
    if head[:4] == b"PK\x03\x04" and suffix in _ARCHIVE_SUFFIXES:
        return "jar"
    return None


@dataclass
class _Structure:
    parser: str
    libraries: list[str] = field(default_factory=list)
    imports: list[tuple[str, str | None]] = field(default_factory=list)   # (symbol, from_library)
    exports: list[str] = field(default_factory=list)
    note: str = ""


def _structure_lief(data: bytes) -> _Structure | None:
    binary = lief.parse(data)
    if binary is None:
        return None
    out = _Structure(parser="lief")
    if isinstance(binary, lief.PE.Binary):
        for imp in binary.imports:
            out.libraries.append(imp.name)
            for entry in imp.entries:
                if entry.name:
                    out.imports.append((entry.name, imp.name))
    else:
        out.libraries = [str(lib if isinstance(lib, str) else getattr(lib, "name", lib))
                         for lib in binary.libraries]
        out.imports = [(f.name, None) for f in binary.imported_functions if f.name]
    out.exports = [f.name for f in binary.exported_functions if f.name]
    return out


def _structure_elftools(data: bytes) -> _Structure:
    elf = ELFFile(io.BytesIO(data))
    out = _Structure(parser="pyelftools")
    for section in elf.iter_sections():
        if isinstance(section, DynamicSection):
            out.libraries.extend(tag.needed for tag in section.iter_tags() if tag.entry.d_tag == "DT_NEEDED")
        if isinstance(section, SymbolTableSection) and section.name == ".dynsym":
            for symbol in section.iter_symbols():
                if not symbol.name:
                    continue
                if symbol["st_shndx"] == "SHN_UNDEF":
                    out.imports.append((symbol.name, None))
                else:
                    out.exports.append(symbol.name)
    return out


def read_structure(data: bytes, fmt: str) -> _Structure:
    """Linked libraries and symbols. Never raises; a failure is a stated note."""
    if _HAVE_LIEF:
        try:
            parsed = _structure_lief(data)
            if parsed is not None:
                return parsed
        except Exception as exc:  # LIEF raises many types on malformed input
            if fmt != "elf" or not _HAVE_ELFTOOLS:
                return _Structure(parser="none", note=f"LIEF could not parse: {type(exc).__name__}")
    if fmt == "elf" and _HAVE_ELFTOOLS:
        try:
            return _structure_elftools(data)
        except Exception as exc:
            return _Structure(parser="none", note=f"pyelftools could not parse: {type(exc).__name__}")
    reason = "LIEF not installed" if not _HAVE_LIEF else "LIEF returned no structure"
    return _Structure(parser="none", note=f"{reason}; byte-level layers only")


# --------------------------------------------------------------------------
# Evidence accumulators
# --------------------------------------------------------------------------


@dataclass
class _LibraryHit:
    lib: kb.Library
    layers: set[str] = field(default_factory=set)
    version: str | None = None
    linkage: str = "dynamic"
    linked_as: str | None = None
    symbols: list[str] = field(default_factory=list)
    refs: list[dict] = field(default_factory=list)


@dataclass
class _AlgorithmHit:
    algorithm: str
    layers: set[str] = field(default_factory=set)
    symbols: list[str] = field(default_factory=list)
    offsets: list[int] = field(default_factory=list)
    constants: list[str] = field(default_factory=list)
    library_id: str | None = None
    extra: dict = field(default_factory=dict)


class _Accumulator:
    """Everything one binary yielded, before it becomes findings."""

    def __init__(self):
        self.libraries: dict[str, _LibraryHit] = {}
        self.algorithms: dict[str, _AlgorithmHit] = {}
        self.certificates: dict[str, dict] = {}
        self.private_keys: list[dict] = []
        self.suites: list[str] = []

    def library(self, lib: kb.Library, layer: str) -> _LibraryHit:
        hit = self.libraries.setdefault(lib.id, _LibraryHit(lib=lib))
        hit.layers.add(layer)
        return hit

    def algorithm(self, name: str, layer: str) -> _AlgorithmHit:
        hit = self.algorithms.setdefault(name, _AlgorithmHit(algorithm=name))
        hit.layers.add(layer)
        return hit


def _match_symbol(name: str):
    for pattern, algorithm, library in rules().symbols:
        if pattern.search(name):
            return True, algorithm, library
    return False, None, None


def _windows(data: bytes, size: int) -> Iterable[tuple[int, bytes]]:
    """(offset, chunk) windows with overlap, so a match on a boundary is not lost."""
    if len(data) <= size:
        yield 0, data
        return
    step = max(size - _WINDOW_OVERLAP, 1)
    for start in range(0, len(data), step):
        yield start, data[start:start + size]


def _find_all(data: bytes, needle: bytes, limit: int) -> list[int]:
    offsets, start = [], 0
    while len(offsets) < limit:
        at = data.find(needle, start)
        if at < 0:
            break
        offsets.append(at)
        start = at + 1
    return offsets


# --------------------------------------------------------------------------
# Layers
# --------------------------------------------------------------------------


def _structure_layers(acc: _Accumulator, structure: _Structure, self_lib: kb.Library | None) -> None:
    r = rules()
    imported_from: dict[str, list[str]] = {}
    for symbol, source in structure.imports:
        matched, algorithm, library_id = _match_symbol(symbol)
        if not matched or not (algorithm or library_id):
            continue
        if source:
            imported_from.setdefault(source.lower(), []).append(symbol)
        if library_id:
            lib = kb.get(library_id)
            if lib is not None:
                hit = acc.library(lib, "symbol")
                if len(hit.symbols) < _MAX_SYMBOLS:
                    hit.symbols.append(symbol)
        if algorithm:
            a = acc.algorithm(algorithm, "symbol")
            a.library_id = a.library_id or library_id
            if len(a.symbols) < _MAX_SYMBOLS:
                a.symbols.append(symbol)

    for name in structure.libraries:
        lib = kb.for_native(name)
        if lib is None:
            continue
        if name.lower() in r.require_symbol_for and not imported_from.get(name.lower()):
            continue
        hit = acc.library(lib, "linked_library")
        hit.linked_as = hit.linked_as or name

    # Exports: a known crypto library's own exports describe what it implements;
    # any other binary exporting crypto symbols carries its own implementation.
    implements: set[str] = set()
    for symbol in structure.exports:
        matched, algorithm, _library_id = _match_symbol(symbol)
        if matched and algorithm:
            implements.add(algorithm)
    if self_lib is not None:
        acc.library(self_lib, "symbol").linkage = "self"
        acc.libraries[self_lib.id].symbols.extend(sorted(implements)[:_MAX_SYMBOLS])
        acc.libraries[self_lib.id].linked_as = None
    else:
        for algorithm in sorted(implements):
            acc.algorithm(algorithm, "symbol").extra["implements"] = True


def _byte_layers(acc: _Accumulator, data: bytes, limits: Limits, structure: _Structure,
                 self_lib: kb.Library | None, is_go: bool) -> None:
    r = rules()
    uses_cng = any(sym.startswith(("BCrypt", "NCrypt")) for sym, _ in structure.imports)
    constant_hits: dict[str, list[int]] = {}

    for base, chunk in _windows(data, limits.max_section_bytes):
        text = chunk.decode("latin-1")
        for lib, version, _matched in kb.banner_matches(text):
            if lib.id == "go-stdlib" and not is_go:
                continue
            hit = acc.library(lib, "version_banner")
            if version and not hit.version:
                hit.version = version
            if self_lib is None and "linked_library" not in hit.layers and lib.id != "go-stdlib":
                hit.linkage = "static"

        for const_id, algorithm, _note, patterns in r.constants:
            for pattern in patterns:
                for at in _find_all(chunk, pattern, _MAX_OFFSETS):
                    constant_hits.setdefault(const_id, []).append(base + at)

        if is_go:
            for pattern, algorithm in r.go_packages:
                if pattern.search(chunk):
                    acc.algorithm(algorithm, "symbol").library_id = "go-stdlib"
                    go_lib = kb.get("go-stdlib")
                    if go_lib is not None:
                        acc.library(go_lib, "symbol")

        if uses_cng:
            for needle, cng_id, algorithm in r.cng_ids:
                at = chunk.find(needle)
                if at >= 0:
                    a = acc.algorithm(algorithm, "cng_algorithm_id")
                    a.library_id = "windows-cng"
                    if len(a.symbols) < _MAX_SYMBOLS and cng_id not in a.symbols:
                        a.symbols.append(cng_id)

        if self_lib is None:
            for match in r.cipher_suite.finditer(chunk):
                suite = match.group(0).decode("ascii")
                if suite not in acc.suites and len(acc.suites) < _MAX_SUITES:
                    acc.suites.append(suite)

        _pem_layers(acc, chunk, base)

    by_id = {c[0]: c for c in r.constants}
    for const_id, offsets in constant_hits.items():
        _cid, algorithm, _note, _patterns = by_id[const_id]
        if self_lib is not None:
            hit = acc.libraries[self_lib.id]
            hit.layers.add("constant")
            continue
        a = acc.algorithm(algorithm, "constant")
        a.constants.append(const_id)
        for at in sorted(set(offsets))[:_MAX_OFFSETS]:
            if len(a.offsets) < _MAX_OFFSETS:
                a.offsets.append(at)


def _pem_layers(acc: _Accumulator, chunk: bytes, base: int) -> None:
    r = rules()
    for at in _find_all(chunk, r.pem_certificate, 64):
        end = chunk.find(b"-----END CERTIFICATE-----", at)
        if end < 0 or end - at > 16384:
            continue
        block = chunk[at:end + len(b"-----END CERTIFICATE-----")]
        cert = _parse_certificate(block)
        if cert and cert["fingerprint_sha256"] not in acc.certificates:
            cert["offset"] = base + at
            acc.certificates[cert["fingerprint_sha256"]] = cert
    for match in r.pem_private_key.finditer(chunk):
        kind = (match.group(1) or b"").decode("ascii").strip() or "PKCS8"
        acc.private_keys.append({"marker_type": kind, "offset": base + match.start()})


def _parse_certificate(block: bytes) -> dict | None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    from collectors.tls_scanner import get_algorithm_details

    try:
        cert = x509.load_pem_x509_certificate(block)
    except ValueError:
        return None
    algorithm, key_size, curve = get_algorithm_details(cert.public_key())
    try:
        signature_algorithm = cert.signature_algorithm_oid._name
    except AttributeError:
        signature_algorithm = "Unknown"
    return {
        "algorithm": algorithm, "key_size": key_size, "curve": curve,
        "signature_algorithm": signature_algorithm,
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "serial": str(cert.serial_number),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


# --------------------------------------------------------------------------
# JAR / class files
# --------------------------------------------------------------------------

_CP_SIZES = {3: 4, 4: 4, 5: 8, 6: 8, 7: 2, 8: 2, 9: 4, 10: 4, 11: 4, 12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}


def class_constants(data: bytes) -> tuple[set[str], list[str]]:
    """(class names referenced, string literals) from a .class constant pool.

    Parses the constant pool only. Raises ValueError on a malformed class.
    """
    if data[:4] != b"\xca\xfe\xba\xbe" or len(data) < 10:
        raise ValueError("not a class file")
    count = struct.unpack(">H", data[8:10])[0]
    utf8: dict[int, str] = {}
    class_refs: list[int] = []
    string_refs: list[int] = []
    pos, index = 10, 1
    while index < count:
        if pos >= len(data):
            raise ValueError("truncated constant pool")
        tag = data[pos]
        pos += 1
        if tag == 1:
            length = struct.unpack(">H", data[pos:pos + 2])[0]
            utf8[index] = data[pos + 2:pos + 2 + length].decode("utf-8", errors="replace")
            pos += 2 + length
        elif tag in _CP_SIZES:
            if tag == 7:
                class_refs.append(struct.unpack(">H", data[pos:pos + 2])[0])
            elif tag == 8:
                string_refs.append(struct.unpack(">H", data[pos:pos + 2])[0])
            pos += _CP_SIZES[tag]
            if tag in (5, 6):
                index += 1  # longs and doubles take two slots
        else:
            raise ValueError(f"unknown constant-pool tag {tag}")
        index += 1
    classes = {utf8[i] for i in class_refs if i in utf8}
    strings = [utf8[i] for i in string_refs if i in utf8]
    return classes, strings


def _jca_layer(acc: _Accumulator, data: bytes, entry: str) -> None:
    r = rules()
    classes, strings = class_constants(data)
    if not classes & r.jca_api_classes:
        return
    for literal in strings:
        for pattern, kind in r.jca_strings:
            match = pattern.match(literal)
            if not match:
                continue
            algorithm, extra = _jca_algorithm(literal, kind, match)
            a = acc.algorithm(algorithm, "jar_constant_pool")
            if len(a.symbols) < _MAX_SYMBOLS and literal not in a.symbols:
                a.symbols.append(literal)
            a.extra.setdefault("classes", [])
            if entry not in a.extra["classes"] and len(a.extra["classes"]) < _MAX_SYMBOLS:
                a.extra["classes"].append(entry)
            for key, value in extra.items():
                a.extra.setdefault(key, value)
            break


def _jca_algorithm(literal: str, kind: str, match: re.Match) -> tuple[str, dict]:
    if kind == "transformation":
        base = {"DESede": "3DES", "TripleDES": "3DES", "ARCFOUR": "RC4"}.get(match.group(1), match.group(1))
        extra = {"mode": match.group(3), "padding": match.group(4)} if match.group(2) else {}
        return base, extra
    if kind == "signature" and "with" in literal:
        digest, scheme = literal.split("with", 1)
        return scheme, {"digest": digest}
    if kind == "digest":
        return {"SHA1": "SHA-1"}.get(literal, literal), {}
    if kind == "pqc":
        name = literal.upper()
        if name.startswith(("KYBER", "ML-KEM")):
            return (literal if "-" in literal[6:] or literal[6:].isdigit() else "ML-KEM-768"), {}
        if name.startswith(("DILITHIUM", "ML-DSA")):
            return (literal if literal.upper().startswith("ML-DSA-") else "ML-DSA-65"), {}
        return "SLH-DSA", {}
    return {"DiffieHellman": "DH", "EC": "ECDSA", "XDH": "X25519"}.get(literal, literal), {}


_JAR_NAME = re.compile(r"(?P<artifact>[A-Za-z0-9_.\-]+?)-(?P<version>\d+(?:\.\d+)*(?:[.\-][A-Za-z0-9]+)?)\.jar$")


def _pom_properties(text: str) -> dict:
    props = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            props[key.strip()] = value.strip()
    return props


def _maven_library(acc: _Accumulator, group: str | None, artifact: str, version: str | None,
                   layer: str, where: str) -> None:
    lib = kb.for_package("maven", f"{group}:{artifact}") if group else None
    if lib is None:
        # A bare jar file name has no group; match on the artifact id alone.
        for (eco, name), lib_id in kb.load()["by_package"].items():
            if eco == "maven" and name.split(":")[-1] == artifact.lower():
                lib = kb.get(lib_id)
                break
    if lib is None:
        return
    hit = acc.library(lib, layer)
    hit.linkage = "bundled"
    hit.version = hit.version or version
    hit.refs.append(evidence(COLLECTOR, where))
    hit.linked_as = f"{group + ':' if group else ''}{artifact}"


def _scan_jar(acc: _Accumulator, data: bytes, location: str, result: CollectResult, depth: int = 0) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        result.fail(location, f"not a readable archive: {exc}")
        return
    with archive:
        for info in archive.infolist():
            name = info.filename
            if info.file_size > _MAX_NESTED_JAR_BYTES:
                result.fail(f"{location}!{name}", "skipped: entry exceeds nested size limit")
                continue
            if name.endswith(".class"):
                try:
                    _jca_layer(acc, archive.read(info), name)
                except (ValueError, struct.error, IndexError) as exc:
                    result.fail(f"{location}!{name}", f"class parse failed: {exc}")
            elif name.endswith("pom.properties") and name.startswith("META-INF/maven/"):
                props = _pom_properties(archive.read(info).decode("utf-8", errors="replace"))
                if props.get("artifactId"):
                    _maven_library(acc, props.get("groupId"), props["artifactId"], props.get("version"),
                                   "jar_constant_pool", f"{location}!{name}")
            elif name.endswith(".jar") and depth == 0:
                match = _JAR_NAME.search(name.rsplit("/", 1)[-1])
                if match:
                    _maven_library(acc, None, match.group("artifact"), match.group("version"),
                                   "jar_constant_pool", f"{location}!{name}")
                _scan_jar(acc, archive.read(info), f"{location}!{name}", result, depth + 1)


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def _details(layers: set[str], location: str, fmt: str, parser: str, extra: dict) -> dict:
    confs = rules().layers
    confidence = max((confs.get(layer, 0.5) for layer in layers), default=0.5)
    details = {
        "discovered_by": COLLECTOR,
        "plane": "built",
        "provenance": "static_analysis",
        "confidence": round(confidence, 2),
        "layers": sorted(layers),
        "binary_format": fmt,
        "parser": parser,
        "evidence_refs": [evidence(COLLECTOR, location)],
    }
    details.update(extra)
    return details



# The mode an entry point names: EVP_aes_256_gcm, EVP_aes_128_cbc_hmac_sha1, EVP_aes_192_cfb128.
_SYMBOL_MODE = re.compile(r"_(gcm|cbc|ctr|ecb|ccm|cfb|ofb)(?:\d*)(?:_|$)", re.I)
_OTHER_MODE = re.compile(r"_(xts|ocb|wrap|siv)(?:_|$)", re.I)


def _symbols_by_mode(symbols: list[str]) -> dict[str, list[str]]:
    """Group a cipher's symbols by the block-cipher mode each one names; empty when none names a mode.

    One binary that links EVP_aes_256_gcm and EVP_aes_256_cbc uses AES-256 in two modes, which are two assets
    in a CBOM. Modes outside CycloneDX's list (XTS, OCB, key wrap) are "other".
    """
    out: dict[str, list[str]] = {}
    for symbol in symbols:
        m = _SYMBOL_MODE.search(symbol)
        if re.search(r"_gcm_siv(?:_|$)", symbol, re.I):
            mode = "gcm-siv"
        else:
            mode = m.group(1).lower() if m else ("other" if _OTHER_MODE.search(symbol) else None)
        if mode:
            out.setdefault(mode, []).append(symbol)
    return out


def _algorithm_finding(name: str, hit: _AlgorithmHit, facts, mode: str | None, symbols: list[str], location: str,
                       fmt: str, parser: str, context: dict, base_name: str) -> RawCryptoFinding:
    label = f"{facts.canonical}-{mode.upper()}" if mode else facts.canonical
    extra = {**context, "display_name": f"{label} in {base_name}"}
    if symbols:
        extra["symbols"] = symbols
    if mode:
        extra["mode"] = mode
    if hit.offsets:
        extra["offsets"] = hit.offsets
    if hit.constants:
        extra["constants"] = sorted(set(hit.constants))
    if hit.library_id:
        extra["via_library"] = hit.library_id
    extra.update(hit.extra)
    m = re.search(r"-(128|192|256)$", name)
    return RawCryptoFinding(
        id=stable_id(COLLECTOR, location, "algorithm", name, *([mode] if mode else [])),
        source_type="binary", source_location=location, asset_class="binary",
        algorithm=name, key_size=int(m.group(1)) if m else None,
        usage=_USAGE_BY_PRIMITIVE.get(facts.primitive, "encryption"),
        tags=["binary-scan"] + [f"layer:{layer}" for layer in sorted(hit.layers)],
        raw_details=_details(hit.layers, location, fmt, parser, extra),
    )

def _to_findings(acc: _Accumulator, location: str, fmt: str, parser: str,
                 context: dict) -> list[RawCryptoFinding]:
    base_name = location.replace("\\", "/").rsplit("/", 1)[-1]
    findings: list[RawCryptoFinding] = []

    for lib_id, hit in sorted(acc.libraries.items()):
        info = kb.details_for(hit.lib, hit.version, "maven" if hit.linkage == "bundled" else None)
        extra = {
            **info, **context,
            "linkage": hit.linkage,
            "display_name": f"{hit.lib.name} {hit.version or '(version unknown)'} in {base_name}",
        }
        if hit.linked_as:
            extra["linked_as"] = hit.linked_as
        if hit.symbols:
            key = "implements" if hit.linkage == "self" else "symbols"
            extra[key] = hit.symbols[:_MAX_SYMBOLS]
        details = _details(hit.layers, location, fmt, parser, extra)
        details["evidence_refs"].extend(hit.refs[:5])
        findings.append(RawCryptoFinding(
            id=stable_id(COLLECTOR, location, "library", lib_id),
            source_type="binary", source_location=location, asset_class="crypto_library",
            algorithm=None, usage="library",
            tags=["binary-scan", "library", f"linkage:{hit.linkage}"],
            raw_details=details,
        ))

    for name, hit in sorted(acc.algorithms.items()):
        facts = classify_algorithm(name)
        by_mode = _symbols_by_mode(hit.symbols)
        for mode, symbols in (by_mode.items() if by_mode else [(None, hit.symbols)]):
            findings.append(_algorithm_finding(name, hit, facts, mode, symbols, location, fmt, parser, context, base_name))

    for suite in acc.suites:
        findings.append(RawCryptoFinding(
            id=stable_id(COLLECTOR, location, "suite", suite),
            source_type="binary", source_location=location, asset_class="tls_cipher_suite",
            cipher_suite=suite, usage="encryption", tags=["binary-scan", "cipher-suite"],
            raw_details=_details({"version_banner"}, location, fmt, parser,
                                 {**context, "display_name": f"{suite} in {base_name}"}),
        ))

    for fingerprint, cert in sorted(acc.certificates.items()):
        details = _details({"embedded_certificate"}, location, fmt, parser, {
            **context, "fingerprint_sha256": fingerprint, "offset": cert["offset"],
            "curve": cert["curve"], "type": "certificate",
        })
        details["provenance"] = "artifact_parsed"
        findings.append(RawCryptoFinding(
            id=stable_id(COLLECTOR, location, "cert", fingerprint),
            source_type="binary", source_location=location, asset_class="embedded_certificate",
            algorithm=cert["algorithm"], key_size=cert["key_size"],
            signature_algorithm=cert["signature_algorithm"], cert_subject=cert["subject"],
            cert_issuer=cert["issuer"], cert_validity_start=cert["not_before"],
            cert_validity_end=cert["not_after"], cert_serial=cert["serial"], usage="signing",
            tags=["binary-scan", "embedded-certificate"], raw_details=details,
        ))

    for marker in acc.private_keys:
        algorithm = {"RSA": "RSA", "EC": "ECDSA", "DSA": "DSA"}.get(marker["marker_type"])
        position = f"{location}@{marker['offset']}"
        findings.append(RawCryptoFinding(
            id=stable_id(COLLECTOR, location, "private-key", marker["offset"]),
            source_type="binary", source_location=location, asset_class="embedded_private_key",
            algorithm=algorithm, usage="signing",
            tags=["binary-scan", "secret-exposure"],
            raw_details=_details({"embedded_private_key"}, location, fmt, parser, {
                **context,
                "private_key_embedded": True,
                "marker_type": marker["marker_type"],
                "offset": marker["offset"],
                # A digest of the marker's position, never of the key body.
                "marker_digest": hashlib.sha256(position.encode("utf-8")).hexdigest(),
                "display_name": f"Embedded {marker['marker_type']} private key in {base_name}",
            }),
        ))
    return findings


def pem_findings(data: bytes, location: str, *, context: dict | None = None) -> list[RawCryptoFinding]:
    """Certificates and private-key markers in a PEM file (a key body is never read)."""
    acc = _Accumulator()
    _pem_layers(acc, data, 0)
    return _to_findings(acc, location, "pem", "none", context or {})


def _learned_finding(data: bytes, fmt: str, location: str, parser: str, context: dict,
                     result: CollectResult) -> RawCryptoFinding | None:
    """Unattributed cryptographic code, selected with conformal FDR control (Pillar 2 of research/)."""
    if os.environ.get("VERA_BINARY_DETECTOR", "1") == "0" or not learned.available():
        return None
    try:
        det = learned.detect(functions_in_bytes(data, fmt))
    except Exception as exc:  # the layer is optional; its failure is reported, never hidden
        result.fail(location, f"learned_function layer failed: {type(exc).__name__}: {exc}")
        return None
    if det is None:
        return None
    if det.skipped:
        result.fail(location, f"learned_function layer skipped: {det.skipped}")
        return None
    result.stats["functions_scored"] = result.stats.get("functions_scored", 0) + det.functions_scored
    if not det.selected:
        return None
    base_name = location.replace("\\", "/").rsplit("/", 1)[-1]
    details = _details({"learned_function"}, location, fmt, parser, {
        **context,
        "display_name": f"Unattributed cryptographic code in {base_name}",
        "detection_method": "learned_function (signature-free) + conformal BH",
        "detection_model": det.model,
        "detection_alpha": det.alpha,
        "detection_q_value": det.min_q,
        "detection_isa": det.arch,
        "detection_boundaries": det.boundary,
        "functions_scored": det.functions_scored,
        "functions_selected": len(det.selected),
        "selected_functions": [{"address": hex(s.address), "name": s.name or None, "q_value": s.q_value}
                               for s in det.selected[:_MAX_SYMBOLS]],
    })
    details["confidence"] = 0.6
    return RawCryptoFinding(
        id=stable_id(COLLECTOR, location, "learned", "functions"),
        source_type="binary", source_location=location, asset_class="binary",
        algorithm=None, usage="unknown",
        tags=["binary-scan", "layer:learned_function", "unattributed"],
        raw_details=details,
    )


def scan_blob(data: bytes, location: str, *, limits: Limits = DEFAULT_LIMITS,
              result: CollectResult | None = None, context: dict | None = None) -> CollectResult:
    """Scan one binary held in memory. Used directly by the container collector."""
    result = result if result is not None else CollectResult()
    fmt = sniff(data[:8], location)
    if fmt is None:
        return result
    result.stats["binaries"] = result.stats.get("binaries", 0) + 1
    acc = _Accumulator()
    parser = "zipfile" if fmt == "jar" else "classfile" if fmt == "class" else "none"
    name = location.replace("\\", "/").rsplit("/", 1)[-1].split("!")[-1]

    if fmt == "jar":
        _scan_jar(acc, data, location, result)
    elif fmt == "class":
        try:
            _jca_layer(acc, data, name)
        except (ValueError, struct.error, IndexError) as exc:
            result.fail(location, f"class parse failed: {exc}")
    else:
        structure = read_structure(data, fmt)
        parser = structure.parser
        if structure.note:
            result.fail(location, f"structure not read: {structure.note}")
        self_lib = kb.for_native(name)
        if self_lib is not None:
            acc.library(self_lib, "linked_library").linkage = "self"
        _structure_layers(acc, structure, self_lib)
        _byte_layers(acc, data, limits, structure, self_lib, is_go=GO_BUILDINFO in data[:limits.max_section_bytes])
        for hit in pqc_tables(data[:limits.max_section_bytes * 4]):
            acc.algorithm(hit.scheme, "pqc_table").offsets.append(hit.offset)
    result.findings.extend(_to_findings(acc, location, fmt, parser, context or {}))
    if fmt in ("elf", "pe") and not acc.algorithms and not acc.libraries:
        found = _learned_finding(data, fmt, location, parser, context or {}, result)
        if found is not None:
            result.findings.append(found)
    return result


class BinaryCollector:
    """Collector-contract wrapper; see `collectors.base.Collector`."""

    name = "binary"
    plane = "built"
    label = "Binaries & libraries"
    description = "ELF / PE / Mach-O / JAR: linked crypto libraries, symbols, banners, constant tables."
    target_kinds = ("path",)

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult:
        result = CollectResult(stats={"files_seen": 0, "binaries": 0, "bytes_read": 0, "skipped": 0,
                                      "parser": "lief" if _HAVE_LIEF else ("pyelftools" if _HAVE_ELFTOOLS else "none")})
        timer = Timer(limits)
        for target in targets:
            for path in walk(Path(target), limits, result):
                if timer.expired:
                    result.fail(target, f"stopped after {limits.timeout_s:.0f}s (timeout)")
                    break
                result.stats["files_seen"] += 1
                try:
                    with path.open("rb") as handle:
                        head = handle.read(8)
                except OSError as exc:
                    result.fail(path, f"read failed: {exc.strerror or exc}")
                    continue
                if sniff(head, path.name) is None:
                    continue
                data = read_capped(path, limits.max_binary_bytes, result)
                if data is None:
                    continue
                scan_blob(data, str(path), limits=limits, result=result)
        result.stats["duration_ms"] = timer.elapsed_ms
        return result


def scan_binaries(paths: list[str]) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Function-style entry point, matching the other collectors."""
    result = BinaryCollector().collect(paths)
    return result.findings, result.failures
