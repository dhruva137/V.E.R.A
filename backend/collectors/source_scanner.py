"""Source collector (plane: built): cryptographic call sites in source code.

HOW
---
Source is parsed with tree-sitter, so a match is a real call, constructor,
constant reference or import in the syntax tree, never text inside a comment
or an unrelated string. Seven language families are covered by rule files in
`rules/source/*.yaml`: Python, Java, Go, C and C++, JavaScript and TypeScript,
Rust, and C#. Each file holds the tree-sitter queries (S-expressions) for its
grammar plus rules that match the captured callee:

    {id, kind: call|new|reference|import, match: <regex on the callee>,
     algorithm | algorithm_from: {arg, kwarg, property, pattern, signature},
     protocol | protocol_from, cipher_suite | cipher_suite_from,
     key_size: {arg, kwarg, property, pattern, template}, mode, usage, confidence}

`algorithm_from` reads the algorithm from a string literal argument
(`Cipher.getInstance("AES/ECB/PKCS5Padding")`, `createHash('md5')`). When the
argument is not a literal - a variable, a config lookup - the finding is
reported with `algorithm: null, unresolved: true` and the expression that
chose it. It is never guessed.

Imports only become findings when the same file has no call site for that
algorithm: `import "crypto/md5"` in a file that also calls `md5.New()` is one
finding, not two.

FALLBACK
--------
If tree-sitter or a grammar cannot load, Python and Java fall back to the
regex ruleset in `collectors.source_regex`, and each finding records which
engine produced it. Other languages are then reported as not scanned.

INPUT
-----
A local path, or a git URL, which is cloned with `--depth 1` into a temporary
directory, scanned, and removed. Locations then read `<url>@<commit>:<path>`.

STATED LIMITATIONS
------------------
- No dataflow: an algorithm chosen through a variable is reported unresolved.
- Wrapper functions hide the call: `my_hash(x)` wrapping `hashlib.md5` is found
  at the wrapper's definition, not at each caller.
- Rules cover the mainstream APIs of each ecosystem; a crypto API not in the
  rules is missed until a rule is added (rules are data).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from collectors import source_regex
from collectors.base import (
    DEFAULT_LIMITS, CollectResult, Limits, Timer, evidence, read_capped, stable_id, walk,
)
from engine.taxonomy import classify_algorithm, classify_protocol
from models.schemas import RawCryptoFinding

try:
    import tree_sitter as ts
    from tree_sitter_language_pack import get_language, get_parser
    _HAVE_TREE_SITTER = True
except ImportError:  # pragma: no cover - exercised only where tree-sitter is absent
    ts = None
    _HAVE_TREE_SITTER = False

COLLECTOR = "source_scanner"
RULES_DIR = Path(__file__).resolve().parent / "rules" / "source"
KINDS = ("call", "new", "reference", "import")
DEFAULT_CONFIDENCE = {"call": 0.70, "new": 0.70, "reference": 0.60, "import": 0.45}
LITERAL_CONFIDENCE = 0.75
UNRESOLVED_CONFIDENCE = 0.35
_SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist", "target",
                        ".tox", ".mypy_cache"})


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    match: re.Pattern
    usage: str
    confidence: float
    spec: dict

    def template(self, key: str, m: re.Match) -> str | None:
        value = self.spec.get(key)
        return None if value is None else _fill(str(value), m)


@dataclass
class LanguageRules:
    language: str
    grammars: dict[str, str]
    strings: frozenset[str]
    queries: dict[str, str]
    rules: dict[str, list[Rule]] = field(default_factory=dict)


@lru_cache(maxsize=1)
def load_rules() -> dict[str, LanguageRules]:
    """Every rule file, keyed by file extension."""
    by_ext: dict[str, LanguageRules] = {}
    for path in sorted(RULES_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        lang = LanguageRules(language=raw["language"], grammars=dict(raw["grammars"]),
                             strings=frozenset(raw.get("strings", [])), queries=dict(raw["queries"]))
        seen: set[str] = set()
        for entry in raw["rules"]:
            if entry["id"] in seen:
                raise ValueError(f"{path.name}: duplicate rule id {entry['id']}")
            seen.add(entry["id"])
            kind = entry["kind"]
            if kind not in KINDS or kind not in lang.queries:
                raise ValueError(f"{path.name}: rule {entry['id']} has kind {kind!r} with no query")
            spec = {k: v for k, v in entry.items() if k not in {"id", "kind", "match", "usage", "confidence"}}
            lang.rules.setdefault(kind, []).append(Rule(
                id=entry["id"], kind=kind, match=re.compile(entry["match"]),
                usage=entry.get("usage", "encryption"),
                confidence=float(entry.get("confidence", DEFAULT_CONFIDENCE[kind])), spec=spec,
            ))
        for ext in lang.grammars:
            by_ext[ext] = lang
    return by_ext


@lru_cache(maxsize=None)
def _parser(grammar: str):
    return get_parser(grammar)


@lru_cache(maxsize=None)
def _query(grammar: str, source: str):
    return ts.Query(get_language(grammar), source)


def grammar_status() -> dict[str, str]:
    """Which grammars load on this host: {grammar: "tree-sitter" | reason}."""
    status = {}
    for lang in {id(v): v for v in load_rules().values()}.values():
        for grammar in sorted(set(lang.grammars.values())):
            if not _HAVE_TREE_SITTER:
                status[grammar] = "tree-sitter not installed"
                continue
            try:
                _parser(grammar)
                status[grammar] = "tree-sitter"
            except Exception as exc:  # the language pack raises LookupError / OSError variants
                status[grammar] = f"grammar unavailable: {type(exc).__name__}"
    return status


# --------------------------------------------------------------------------
# Algorithm names
# --------------------------------------------------------------------------

_HASHES = {"md5": "MD5", "md4": "MD4", "sha1": "SHA-1", "sha-1": "SHA-1", "sha224": "SHA-224",
           "sha-224": "SHA-224", "sha256": "SHA-256", "sha-256": "SHA-256", "sha384": "SHA-384",
           "sha-384": "SHA-384", "sha512": "SHA-512", "sha-512": "SHA-512", "sha3-256": "SHA3-256"}
_KEY_TYPES = {"rsa": "RSA", "ec": "ECDSA", "ecdsa": "ECDSA", "dsa": "DSA", "dh": "DH", "diffiehellman": "DH",
              "ecdh": "ECDH", "ed25519": "Ed25519", "ed448": "Ed448", "x25519": "X25519", "x448": "X448",
              "eddsa": "Ed25519", "xdh": "X25519", "hmac": "HMAC", "hkdf": "HKDF", "pbkdf2": "HKDF",
              "3des": "3DES", "des": "DES", "desede": "3DES", "tripledes": "3DES", "des3": "3DES",
              "rc4": "RC4", "arcfour": "RC4", "blowfish": "Blowfish", "bf": "Blowfish", "aes": "AES",
              "chacha20": "ChaCha20", "chacha20-poly1305": "ChaCha20", "rsa-oaep": "RSA", "rsa-oaep-256": "RSA",
              "rsassa-pkcs1-v1_5": "RSA", "rsa-pss": "RSA", "rsassa-pss": "RSA", "rsa1_5": "RSA",
              "ecdh-es": "ECDH", "ecdsa_p256": "ECDSA", "ecdsa_p384": "ECDSA", "ecdsa_p521": "ECDSA",
              "ecdh_p256": "ECDH", "ecdh_p384": "ECDH", "ecdh_p521": "ECDH", "x9_62_prime256v1": "ECDSA",
              "secp256r1": "ECDSA", "secp384r1": "ECDSA", "prime256v1": "ECDSA", "secp256k1": "ECDSA",
              "p-256": "ECDSA", "p-384": "ECDSA", "p-521": "ECDSA"}
_JOSE = {"rs": "RSA", "ps": "RSA", "es": "ECDSA", "hs": "HMAC"}
# Family names whose parameter set the provider chooses (JDK and .NET default to these).
_PQC_FAMILIES = {"ml-kem": "ML-KEM-768", "kyber": "ML-KEM-768", "ml-dsa": "ML-DSA-65",
                 "dilithium": "ML-DSA-65", "slh-dsa": "SLH-DSA", "sphincs+": "SLH-DSA"}
_PQC = re.compile(r"^(ml[-_]?kem|kyber)[-_]?(512|768|1024)$|^(ml[-_]?dsa)[-_]?(44|65|87)$|^dilithium[-_]?([235])$",
                  re.I)


def normalize_algorithm(literal: str, *, signature: bool = False) -> tuple[str | None, dict]:
    """Map an algorithm string as written in code to (canonical name, extra detail).

    An unrecognised string is returned as-is with `unrecognized: True`, so the
    taxonomy reports it as unknown rather than it being dropped.
    """
    text = literal.strip()
    low = text.lower()
    extra: dict = {}

    m = re.match(r"^([A-Za-z0-9-]+)/([A-Za-z0-9]+)/([A-Za-z0-9]+)$", text)   # JCA transformation
    if m:
        base, extra = normalize_algorithm(m.group(1))
        return base, {**extra, "mode": m.group(2).upper(), "padding": m.group(3)}

    m = re.match(r"^(md5|sha-?\d+)with(rsa|ecdsa|dsa)(andmgf1)?$", low)      # JCA signature names
    if m:
        return _KEY_TYPES[m.group(2)], {"digest": _HASHES.get(m.group(1), m.group(1).upper())}

    m = re.match(r"^(rsa|ecdsa|dsa)-(sha-?\d+|md5)$", low)                   # node createSign('RSA-SHA256')
    if m:
        return _KEY_TYPES[m.group(1)], {"digest": _HASHES.get(m.group(2), m.group(2).upper())}

    m = re.match(r"^(rs|ps|es|hs)(256|384|512)$", low)                        # JOSE algorithm ids
    if m:
        return _JOSE[m.group(1)], {"jose": text.upper()}

    m = re.match(r"^(aes|a)-?(128|192|256)(?:-?([a-z0-9]+))?$", low)          # aes-128-cbc, A256GCM, aes256
    if m and (m.group(1) == "aes" or (m.group(3) or "").startswith(("gcm", "cbc", "kw", "ctr"))):
        return f"AES-{m.group(2)}", ({"mode": m.group(3).upper()} if m.group(3) else {})

    m = re.match(r"^aes-(gcm|cbc|ctr|kw|ecb)$", low)                          # WebCrypto AES-GCM
    if m:
        return "AES", {"mode": m.group(1).upper()}

    m = re.match(r"^(des-ede3|des3|3des|tripledes|desede)(?:-([a-z0-9]+))?$", low)
    if m:
        return "3DES", ({"mode": m.group(2).upper()} if m.group(2) else {})
    m = re.match(r"^(des|bf|blowfish|rc4|rc2)(?:-([a-z0-9]+))?$", low)
    if m and m.group(1) != "rc2":
        return _KEY_TYPES[m.group(1)], ({"mode": m.group(2).upper()} if m.group(2) else {})

    m = _PQC.match(low)
    if m:
        if m.group(1):
            return f"ML-KEM-{m.group(2)}", {}
        if m.group(3):
            return f"ML-DSA-{m.group(4)}", {}
        return {"2": "ML-DSA-44", "3": "ML-DSA-65", "5": "ML-DSA-87"}[m.group(5)], {}

    if low in _PQC_FAMILIES:        # "ML-KEM" alone: the provider's default parameter set
        return _PQC_FAMILIES[low], {"parameter_set": "provider default"}

    m = re.match(r"^(ecdsa|ecdh)_p(256|384|521)$", low)
    if m:
        return _KEY_TYPES[m.group(1)], {"key_size": int(m.group(2))}

    if low in _HASHES:
        name = _HASHES[low]
        if signature:
            return None, {"digest": name, "unresolved_reason": "signature scheme comes from the key, not the name"}
        return name, {}
    if low in _KEY_TYPES:
        return _KEY_TYPES[low], {}
    if low in {"sha1prng"}:
        return None, {"unresolved_reason": "random number generator, not a cipher"}

    facts = classify_algorithm(text)
    if facts.verdict != "unknown":
        return text, {}
    return text, {"unrecognized": True}


_PROTOCOLS_EXACT = {"Tls": "TLSv1.0", "Tls11": "TLSv1.1", "Ssl3": "SSLv3", "Ssl2": "SSLv2"}
_PROTOCOLS = {"sslv2": "SSLv2", "ssl2": "SSLv2", "sslv3": "SSLv3", "ssl3": "SSLv3", "ssl30": "SSLv3",
              "tlsv1": "TLSv1.0", "tls10": "TLSv1.0", "tls1": "TLSv1.0", "tlsv1.0": "TLSv1.0",
              "tlsv1_1": "TLSv1.1", "tls11": "TLSv1.1", "tls1_1": "TLSv1.1", "tlsv1.1": "TLSv1.1",
              "tlsv1.2": "TLSv1.2", "tlsv1_2": "TLSv1.2", "tls12": "TLSv1.2", "tlsv1.3": "TLSv1.3",
              "tls13": "TLSv1.3"}


def normalize_protocol(token: str | None) -> str | None:
    """'TLSv1_1' / 'TLS11' / 'TLS1_1_VERSION' / 'Tls11' -> 'TLSv1.1'. 'TLS' alone is a family, not a version."""
    if not token:
        return None
    token = token.strip().strip("\"'")
    if token in _PROTOCOLS_EXACT:
        return _PROTOCOLS_EXACT[token]
    return _PROTOCOLS.get(re.sub(r"_version$", "", token.lower()))


# --------------------------------------------------------------------------
# Syntax helpers
# --------------------------------------------------------------------------

_QUOTED = re.compile(r'^[A-Za-z@$]*("""|\'\'\'|"|\'|`)(.*)\1$', re.S)


def _text(node) -> str:
    return node.text.decode("utf-8", errors="replace") if node is not None else ""


def _literal(node, lang: LanguageRules) -> str | None:
    """The value of a string literal node, or None if the node is not a plain literal."""
    if node is None or node.type not in lang.strings:
        return None
    if any(child.type in ("interpolation", "template_substitution", "escape_sequence_interpolation")
           for child in node.named_children):
        return None
    m = _QUOTED.match(_text(node).strip())
    if m:
        return m.group(2)
    raw = re.match(r'^R"([^(]*)\((.*)\)\1"$', _text(node), re.S)       # C++ raw string
    return raw.group(2) if raw else None


def _arguments(args) -> tuple[list, dict]:
    """(positional nodes, keyword nodes) of an argument list."""
    positional, keywords = [], {}
    if args is None:
        return positional, keywords
    for child in args.named_children:
        if child.type == "comment":
            continue
        if child.type == "keyword_argument":                            # Python
            name, value = child.child_by_field_name("name"), child.child_by_field_name("value")
            keywords[_text(name)] = value
        elif child.type == "argument":                                  # C#
            name = next((c for c in child.named_children if c.type == "name_colon"), None)
            expr = child.named_children[-1] if child.named_children else child
            if name is not None:
                keywords[_text(name).rstrip(":").strip()] = expr
            else:
                positional.append(expr)
        else:
            positional.append(child)
    return positional, keywords


def _property(node, name: str, lang: LanguageRules):
    """The value of `name` in an object/dict literal node, if present."""
    if node is None:
        return None
    for pair in node.named_children:
        if pair.type in ("pair", "shorthand_property_identifier"):
            key = pair.child_by_field_name("key")
            if key is not None and (_text(key).strip("\"'") == name):
                return pair.child_by_field_name("value")
    return None


def _select(spec: dict, positional: list, keywords: dict, lang: LanguageRules):
    node = None
    if spec.get("kwarg") and spec["kwarg"] in keywords:
        node = keywords[spec["kwarg"]]
    elif spec.get("arg") is not None and spec["arg"] < len(positional):
        node = positional[spec["arg"]]
    if spec.get("property"):
        if node is not None and node.type in lang.strings:
            return node
        target = node if node is not None else next(
            (p for p in positional if _property(p, spec["property"], lang) is not None), None)
        return _property(target, spec["property"], lang)
    return node


def _fill(template: str, m: re.Match) -> str:
    """Substitute `{1}`-style regex groups from the callee match."""
    return re.sub(r"\{(\d)\}", lambda g: m.group(int(g.group(1))) or "", template)


def _key_size(spec: dict | None, positional, keywords, lang, m: re.Match) -> int | None:
    if not spec:
        return None
    if "template" in spec:
        value = _fill(spec["template"], m)
        return int(value) if value.isdigit() else None
    node = _select(spec, positional, keywords, lang)
    text = _text(node)
    if not text:
        return None
    found = re.search(spec["pattern"], text, re.I) if spec.get("pattern") else re.search(r"\b(\d{3,5})\b", text)
    return int(found.group(1)) if found and found.group(1).isdigit() else None


# --------------------------------------------------------------------------
# Scanning one file
# --------------------------------------------------------------------------


@dataclass
class _Hit:
    rule: Rule
    line: int
    column: int
    callee: str
    algorithm: str | None = None
    key_size: int | None = None
    protocol: str | None = None
    cipher_suite: str | None = None
    extra: dict = field(default_factory=dict)
    unresolved: bool = False
    literal: str | None = None


def _callee_text(kind: str, caps: dict) -> str:
    if kind == "call" and "name" in caps:                               # Java: object.name
        obj = _text(caps["obj"][0]) if caps.get("obj") else ""
        name = _text(caps["name"][0])
        return f"{obj}.{name}" if obj else name
    if "callee" in caps:
        text = _text(caps["callee"][0])
    elif "path" in caps:
        text = _text(caps["path"][0])
    else:
        text = _text(caps["site"][0])
    text = re.sub(r"\s+", "", text)
    if kind in ("call", "new"):
        text = re.sub(r"::<[^>]*>", "", text)                           # Rust turbofish
        text = re.sub(r"<[^<>]*>$", "", text)                           # generic type arguments
    return text


def _resolve(rule: Rule, m: re.Match, caps: dict, lang: LanguageRules, site) -> _Hit | None:
    positional, keywords = _arguments(caps["args"][0] if caps.get("args") else None)
    hit = _Hit(rule=rule, line=site.start_point[0] + 1, column=site.start_point[1] + 1, callee=m.string)
    spec = rule.spec

    if "algorithm" in spec:
        hit.algorithm, extra = normalize_algorithm(rule.template("algorithm", m))
        hit.extra.update(extra)
    elif "algorithm_from" in spec:
        source = spec["algorithm_from"]
        node = _select(source, positional, keywords, lang)
        if source.get("pattern"):
            found = re.search(source["pattern"], _text(node), re.I) if node is not None else None
            value = found.group(1) if found else None
        else:
            value = _literal(node, lang)
        if value is None:
            hit.unresolved = True
            hit.extra["argument"] = _text(node)[:80] if node is not None else "(absent)"
        else:
            hit.literal = value
            hit.algorithm, extra = normalize_algorithm(value, signature=bool(source.get("signature")))
            hit.extra.update(extra)
            if hit.algorithm is None:
                hit.unresolved = True
    if "protocol" in spec or "protocol_from" in spec:
        if "protocol" in spec:
            token = rule.template("protocol", m)
        else:
            source = spec["protocol_from"]
            node = _select(source, positional, keywords, lang)
            if source.get("pattern"):
                found = re.search(source["pattern"], _text(node)) if node is not None else None
                token = found.group(1) if found else None
            else:
                token = _literal(node, lang)
        hit.protocol = normalize_protocol(token)
        if hit.protocol is None or classify_protocol(hit.protocol)[0] != "classical":
            return None      # a current protocol version, or a family name, is not a finding
    if "cipher_suite" in spec:
        hit.cipher_suite = rule.template("cipher_suite", m)
    elif "cipher_suite_from" in spec:
        hit.cipher_suite = _literal(_select(spec["cipher_suite_from"], positional, keywords, lang), lang)
        if hit.cipher_suite is None:
            hit.unresolved = True

    size = _key_size(spec.get("key_size"), positional, keywords, lang, m)
    hit.key_size = size or hit.extra.pop("key_size", None)
    if spec.get("mode"):
        mode_spec = spec["mode"]
        if "template" in mode_spec:
            hit.extra["mode"] = _fill(mode_spec["template"], m).upper()
        else:
            node = _select(mode_spec, positional, keywords, lang)
            found = re.search(mode_spec["pattern"], _text(node)) if node is not None else None
            if found:
                hit.extra["mode"] = found.group(1).upper()
    return hit


def scan_tree(data: bytes, grammar: str, lang: LanguageRules) -> list[_Hit]:
    """Every rule hit in one parsed file, with import hits de-duplicated."""
    tree = _parser(grammar).parse(data)
    hits: list[_Hit] = []
    imports: list[_Hit] = []
    for kind in KINDS:
        rules = lang.rules.get(kind)
        if not rules:
            continue
        for _pattern, caps in ts.QueryCursor(_query(grammar, lang.queries[kind])).matches(tree.root_node):
            if "site" not in caps:
                continue
            callee = _callee_text(kind, caps)
            for rule in rules:
                m = rule.match.search(callee)
                if not m:
                    continue
                hit = _resolve(rule, m, caps, lang, caps["site"][0])
                if hit is not None:
                    (imports if kind == "import" else hits).append(hit)
                break
    used = {_IMPORT_FAMILY.get(h.algorithm, h.algorithm) for h in hits if h.algorithm}
    hits.extend(h for h in imports if _IMPORT_FAMILY.get(h.algorithm, h.algorithm) not in used)
    return hits


# An import is only reported when no call site in the file uses the same
# algorithm. One package can serve two names (Go's crypto/des provides DES and
# 3DES), so the comparison is by package family.
_IMPORT_FAMILY = {"3DES": "DES"}


def _finding(hit: _Hit, location: str, lang: LanguageRules, engine: str) -> RawCryptoFinding:
    rule = hit.rule
    confidence = (UNRESOLVED_CONFIDENCE if hit.unresolved else
                  LITERAL_CONFIDENCE if hit.literal is not None and rule.kind == "call" else rule.confidence)
    name = hit.algorithm or hit.cipher_suite or hit.protocol or "unresolved algorithm"
    file_name = location.replace("\\", "/").rsplit("/", 1)[-1]
    details = {
        "type": "api_call",
        "discovered_by": COLLECTOR,
        "plane": "built",
        "provenance": "static_analysis",
        "confidence": confidence,
        "engine": engine,
        "language": lang.language,
        "rule": rule.id,
        "match_kind": rule.kind,
        "api": hit.callee,
        "line": hit.line,
        "column": hit.column,
        "resolved": not hit.unresolved,
        "unresolved": hit.unresolved,
        "evidence_refs": [evidence(COLLECTOR, location, line=hit.line)],
        "display_name": f"{name} via {hit.callee} ({file_name}:{hit.line})",
    }
    if hit.literal is not None:
        details["argument_literal"] = hit.literal
    if hit.unresolved:
        details["note"] = ("The algorithm is chosen at runtime (" + str(hit.extra.get("argument", "expression"))
                           + ") and cannot be resolved statically. Reported, not guessed.")
    if rule.spec.get("note"):
        details["rule_note"] = rule.spec["note"]
    details.update({k: v for k, v in hit.extra.items() if k != "argument" or hit.unresolved})
    return RawCryptoFinding(
        id=stable_id(COLLECTOR, location, hit.line, hit.column, rule.id),
        source_type="source",
        source_location=f"{location}:{hit.line}",
        asset_class="source",
        algorithm=None if hit.unresolved else hit.algorithm,
        key_size=hit.key_size,
        protocol=hit.protocol,
        cipher_suite=hit.cipher_suite,
        usage=rule.usage,
        tags=["source-scan", f"lang:{lang.language}", f"engine:{engine}"] + (["unresolved"] if hit.unresolved else []),
        raw_details=details,
    )


def scan_file_bytes(data: bytes, location: str, suffix: str) -> tuple[list[RawCryptoFinding], str | None]:
    """Findings for one file. Returns (findings, engine used or None if not scanned)."""
    lang = load_rules().get(suffix.lower())
    if lang is None:
        return [], None
    grammar = lang.grammars[suffix.lower()]
    if _HAVE_TREE_SITTER:
        try:
            hits = scan_tree(data, grammar, lang)
            return [_finding(h, location, lang, "tree-sitter") for h in hits], "tree-sitter"
        except (LookupError, OSError, ValueError, RuntimeError):
            pass  # grammar unavailable: fall through to the stated fallback
    if suffix.lower() in source_regex.SUFFIXES:
        return source_regex.scan_text(data.decode("utf-8", errors="replace"), location, lang.language), "regex"
    return [], None


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------

_REPO_URL = re.compile(r"^(https?://|git@|ssh://|git://|file://)|\.git$")


def _clone(url: str, result: CollectResult) -> tuple[Path, str] | None:
    """Shallow-clone a repository into a temp dir. Returns (path, commit) or None on failure."""
    workdir = Path(tempfile.mkdtemp(prefix="vera-src-"))
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, str(workdir)], check=True,
                       capture_output=True, timeout=180, env=env)
        commit = subprocess.run(["git", "-C", str(workdir), "rev-parse", "HEAD"], check=True,
                                capture_output=True, text=True, timeout=30).stdout.strip()
        return workdir, commit
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        stderr = getattr(exc, "stderr", b"") or b""
        detail = stderr.decode(errors="replace").strip()[:200] if isinstance(stderr, bytes) else str(stderr)[:200]
        result.fail(url, f"clone failed: {type(exc).__name__} {detail}".strip())
        shutil.rmtree(workdir, ignore_errors=True)
        return None


class SourceCollector:
    """Collector-contract implementation; see `collectors.base.Collector`."""

    name = "source"
    plane = "built"
    label = "Source code"
    description = "Tree-sitter call sites in Python, Java, Go, C/C++, JS/TS, Rust and C#; git URLs cloned shallow."
    target_kinds = ("path", "repo")

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult:
        result = CollectResult(stats={"files_seen": 0, "source_files": 0, "bytes_read": 0, "skipped": 0,
                                      "by_language": {}, "by_engine": {}, "unresolved": 0, "not_scanned": 0})
        timer = Timer(limits)
        rules = load_rules()
        for target in targets:
            cloned = None
            root, label = Path(target), None
            if _REPO_URL.search(str(target)) and not Path(target).exists():
                cloned = _clone(str(target), result)
                if cloned is None:
                    continue
                root, commit = cloned
                label = f"{target}@{commit[:12]}"
                result.stats.setdefault("repos", []).append({"url": target, "commit": commit})
            try:
                for path in walk(root, limits, result, skip_dirs=_SKIP_DIRS):
                    if timer.expired:
                        result.fail(target, f"stopped after {limits.timeout_s:.0f}s (timeout)")
                        break
                    result.stats["files_seen"] += 1
                    suffix = path.suffix.lower()
                    if suffix not in rules:
                        continue
                    data = read_capped(path, limits.max_text_bytes, result)
                    if data is None:
                        continue
                    result.stats["source_files"] += 1
                    lang = rules[suffix].language
                    location = (f"{label}:{path.relative_to(root).as_posix()}" if label else str(path))
                    findings, engine = scan_file_bytes(data, location, suffix)
                    if engine is None:
                        result.stats["not_scanned"] += 1
                        result.fail(path, f"{lang}: no parser available on this host; not scanned")
                        continue
                    by_lang, by_engine = result.stats["by_language"], result.stats["by_engine"]
                    by_lang[lang] = by_lang.get(lang, 0) + 1
                    by_engine[engine] = by_engine.get(engine, 0) + 1
                    result.stats["unresolved"] += sum(1 for f in findings if f.raw_details.get("unresolved"))
                    result.findings.extend(findings)
            finally:
                if cloned is not None:
                    shutil.rmtree(cloned[0], ignore_errors=True)
        result.stats["duration_ms"] = timer.elapsed_ms
        return result


def scan_source(paths: list[str]) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Function-style entry point, matching the other collectors."""
    result = SourceCollector().collect(paths)
    return result.findings, result.failures
