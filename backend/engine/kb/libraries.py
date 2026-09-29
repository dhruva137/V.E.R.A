"""Crypto-library knowledge base: which library versions block PQC migration.

The KB (`crypto_libraries.yaml`) is data, reviewed by hand, dated, and shipped
offline. This module loads it, resolves what a collector found (a linked DLL, a
version banner, a lockfile package) to an entry, and answers one question per
library finding: *does this version block post-quantum migration?*

Answers are never guessed. An unknown version, or a library whose first
PQC-capable release is not pinned in the KB, yields verdict `unknown` with the
reason. A library that only implements symmetric primitives is inventoried but
is not a PQC blocker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

KB_PATH = Path(__file__).resolve().parent / "crypto_libraries.yaml"


@dataclass(frozen=True)
class Library:
    id: str
    name: str
    role: str
    public_key: bool
    native: tuple[str, ...]
    banners: tuple[re.Pattern, ...]
    packages: dict[str, tuple[str, ...]]
    pqc_native_from: Any          # str | dict[str, str | None] | None
    status: str
    source: str
    note: str
    upgrade: str

    def pqc_from(self, ecosystem: str | None = None) -> str | None:
        value = self.pqc_native_from
        if isinstance(value, dict):
            return value.get(ecosystem or "") if ecosystem else None
        return value


@lru_cache(maxsize=1)
def load() -> dict:
    """The parsed KB: {as_of, libraries: {id: Library}, by_package, by_native}."""
    raw = yaml.safe_load(KB_PATH.read_text(encoding="utf-8"))
    libraries: dict[str, Library] = {}
    by_package: dict[tuple[str, str], str] = {}
    by_native: list[tuple[str, str]] = []
    for entry in raw["libraries"]:
        packages = {eco: tuple(names) for eco, names in (entry.get("packages") or {}).items()}
        lib = Library(
            id=entry["id"],
            name=entry["name"],
            role=entry.get("role", ""),
            public_key=bool(entry.get("public_key", True)),
            native=tuple(entry.get("native") or ()),
            banners=tuple(re.compile(p) for p in entry.get("banners") or ()),
            packages=packages,
            pqc_native_from=entry.get("pqc_native_from"),
            status=entry.get("status", "VERIFY"),
            source=entry.get("source", ""),
            note=entry.get("note", ""),
            upgrade=entry.get("upgrade", ""),
        )
        if lib.id in libraries:
            raise ValueError(f"duplicate library id in KB: {lib.id}")
        libraries[lib.id] = lib
        for eco, names in packages.items():
            for name in names:
                by_package[(eco, name.lower())] = lib.id
        for stem in lib.native:
            by_native.append((stem.lower(), lib.id))
    return {"as_of": str(raw.get("as_of", "")), "libraries": libraries,
            "by_package": by_package, "by_native": by_native}


def get(library_id: str) -> Library | None:
    return load()["libraries"].get(library_id)


def for_package(ecosystem: str, package: str) -> Library | None:
    """KB entry for a package name in an ecosystem (pypi, npm, maven, go, ...)."""
    kb = load()
    lib_id = kb["by_package"].get((ecosystem, package.lower()))
    return kb["libraries"].get(lib_id) if lib_id else None


def for_native(filename: str) -> Library | None:
    """KB entry for a linked native library file name (libssl.so.3, bcrypt.dll, ...)."""
    name = filename.lower().rsplit("/", 1)[-1]
    for stem, lib_id in load()["by_native"]:
        if name == stem or name.startswith(stem + ".") or name.startswith(stem + "-") \
                or name.startswith(stem + "_") or (stem.endswith(".dll") and name == stem):
            return load()["libraries"][lib_id]
    return None


def banner_matches(text: str) -> list[tuple[Library, str | None, str]]:
    """Every (library, version, matched text) whose version banner appears in `text`."""
    out = []
    for lib in load()["libraries"].values():
        for pattern in lib.banners:
            for match in pattern.finditer(text):
                version = match.group(1) if match.groups() else None
                out.append((lib, version, match.group(0)))
    return out


_VERSION_PART = re.compile(r"\d+")


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """'3.0.18' -> (3, 0, 18); '1.1.1w' -> (1, 1, 1); 'go1.22.5' -> (1, 22, 5); '' -> None."""
    if not text:
        return None
    head = re.sub(r"^[^\d]*", "", str(text).strip())
    head = re.split(r"[\s+~-]", head, maxsplit=1)[0]
    parts = [int(p) for p in _VERSION_PART.findall(head)[:4]]
    return tuple(parts) if parts else None


def version_at_least(version: str | None, minimum: str) -> bool | None:
    """True/False when both parse; None when either is unknown. Never guessed."""
    have, need = parse_version(version), parse_version(minimum)
    if have is None or need is None:
        return None
    width = max(len(have), len(need))
    return have + (0,) * (width - len(have)) >= need + (0,) * (width - len(need))


def pqc_status(lib: Library, version: str | None, ecosystem: str | None = None) -> dict:
    """Whether this library at this version can do PQC natively.

    Returns {pqc_capable: bool|None, pqc_native_from, reason}. `pqc_capable` is
    None whenever the KB or the version leaves the answer open.
    """
    if not lib.public_key:
        return {"pqc_capable": True, "pqc_native_from": "any",
                "reason": "Symmetric or hashing only; not a PQC migration blocker."}
    threshold = lib.pqc_from(ecosystem)
    if threshold == "any":
        return {"pqc_capable": True, "pqc_native_from": "any", "reason": "Post-quantum library."}
    if threshold == "never":
        return {"pqc_capable": False, "pqc_native_from": "never",
                "reason": "Implements only classical public-key algorithms; replace the library."}
    if threshold is None:
        return {"pqc_capable": None, "pqc_native_from": None,
                "reason": "First PQC-capable release not pinned in the knowledge base."}
    at_least = version_at_least(version, threshold)
    if at_least is None:
        return {"pqc_capable": None, "pqc_native_from": threshold,
                "reason": f"Version unknown; PQC is native from {threshold}."}
    if at_least:
        return {"pqc_capable": True, "pqc_native_from": threshold,
                "reason": f"{version} is at or above {threshold}, where PQC is native."}
    return {"pqc_capable": False, "pqc_native_from": threshold,
            "reason": f"{version} predates native PQC (from {threshold})."}


def details_for(lib: Library, version: str | None, ecosystem: str | None = None) -> dict:
    """The `raw_details` keys every library finding carries."""
    status = pqc_status(lib, version, ecosystem)
    return {
        "library": lib.name,
        "library_id": lib.id,
        "library_version": version or "unknown",
        "library_role": lib.role,
        "pqc_native_from": status["pqc_native_from"],
        "pqc_capable": status["pqc_capable"],
        "pqc_reason": status["reason"],
        "kb_status": lib.status,
        "kb_source": lib.source,
        "kb_note": lib.note,
        "upgrade_path": lib.upgrade or (
            f"{lib.name} {status['pqc_native_from']} or later"
            if status["pqc_native_from"] not in (None, "any", "never") else ""
        ),
        "public_key": lib.public_key,
    }


def classify(details: dict) -> dict:
    """Taxonomy-shaped verdict for a `crypto_library` asset.

    Answers "is this library a PQC migration blocker?", which is what an
    inventory of libraries is for. Whether the library's PQC is actually *used*
    is a configuration question, answered by the config and TLS collectors.
    """
    name = details.get("library", "library")
    version = details.get("library_version") or "unknown"
    capable = details.get("pqc_capable")
    reason = details.get("pqc_reason", "")
    upgrade = details.get("upgrade_path") or None
    if capable is True:
        verdict, vulnerable = "pqc", False
        rationale = f"{name} {version}: {reason}"
        replacement = None
    elif capable is False:
        verdict, vulnerable = "shor", True
        rationale = (f"{name} {version}: {reason} Public-key operations through it are "
                     "classical and Shor-exposed until it is upgraded or replaced.")
        replacement = upgrade or "Replace with a PQC-capable library"
    else:
        verdict, vulnerable = "unknown", False
        rationale = f"{name} {version}: {reason} Reported, not guessed."
        replacement = upgrade
    return {
        "verdict": verdict,
        "quantum_vulnerable": vulnerable,
        "classically_broken": False,
        "grover_weakened": False,
        "rationale": rationale,
        "primitive": "library",
        "classical_bits": None,
        "nist_quantum_level": 0,
        "pqc_replacement": replacement,
        "curve": None,
        "oid": None,
        "suite": None,
        "components": [{
            "role": "library", "algorithm": f"{name} {version}", "primitive": "library",
            "verdict": verdict, "rationale": rationale, "classical_bits": None,
            "pqc_replacement": replacement,
        }],
    }
