"""Validate CBOM and SARIF output against the official schemas, offline.

The schemas are vendored under `engine/schemas/` (see its README for sources
and hashes). They reference each other by relative name, so a local registry
maps every `$id` and file name to the vendored copy; nothing is fetched at
runtime, which is what lets validation run on an air-gapped review laptop.

Returns a list of errors, each with the JSON path and the schema's message. An
empty list means the document is valid against that schema. JSON Schema cannot
check that a `bom-ref` points at a component that exists, so
`engine.cbom_validate` adds those referential checks on top.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft4Validator, Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4, DRAFT7

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
CYCLONEDX_BASE = "http://cyclonedx.org/schema/"
CYCLONEDX_FILES = {"1.7": "bom-1.7.SNAPSHOT.schema.json", "1.6": "bom-1.6.SNAPSHOT.schema.json"}
SARIF_FILE = "sarif-schema-2.1.0.json"


def _load(name: str) -> dict:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _cyclonedx_registry() -> Registry:
    registry = Registry()
    for path in SCHEMA_DIR.glob("*.SNAPSHOT.schema.json"):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource(contents=contents, specification=DRAFT7)
        registry = registry.with_resource(CYCLONEDX_BASE + path.name, resource)
        if contents.get("$id"):
            registry = registry.with_resource(contents["$id"], resource)
    return registry


@lru_cache(maxsize=4)
def _cyclonedx_validator(spec: str) -> Draft7Validator:
    if spec not in CYCLONEDX_FILES:
        raise ValueError(f"No vendored CycloneDX schema for spec {spec!r}")
    schema = _load(CYCLONEDX_FILES[spec])
    # Anchor relative $refs to the vendored base so they resolve in the registry.
    schema = {**schema, "$id": CYCLONEDX_BASE + CYCLONEDX_FILES[spec]}
    return Draft7Validator(schema, registry=_cyclonedx_registry())


@lru_cache(maxsize=1)
def _sarif_validator() -> Draft4Validator:
    schema = _load(SARIF_FILE)
    registry = Registry().with_resource(schema["id"] if "id" in schema else schema["$id"],
                                        Resource(contents=schema, specification=DRAFT4))
    return Draft4Validator(schema, registry=registry)


def _errors(validator, document: dict, limit: int) -> list[dict]:
    out = []
    for error in sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path)):
        out.append({"path": "/" + "/".join(str(p) for p in error.absolute_path),
                    "message": error.message[:300], "validator": error.validator})
        if len(out) >= limit:
            break
    return out


def _local_ref(uri: str) -> dict:
    """Resolve a cross-file $ref to the vendored copy. Never touches the network."""
    name = uri.split("#", 1)[0].rsplit("/", 1)[-1]
    path = SCHEMA_DIR / name
    if not path.is_file():
        raise ValueError(f"schema reference {uri!r} is not vendored")
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=4)
def _fast_cyclonedx(spec: str):
    """The same schema compiled to Python by fastjsonschema: ~10x faster, first error only."""
    import fastjsonschema

    schema = _load(CYCLONEDX_FILES[spec])
    return fastjsonschema.compile(schema, handlers={"http": _local_ref, "https": _local_ref})


def validate_cyclonedx(document: dict, spec: str | None = None, limit: int = 50) -> list[dict]:
    """Schema errors for a CycloneDX document (spec from the document unless given).

    A compiled validator answers "valid?" quickly on every scan; only when it
    finds a problem does the reference validator run to list every error.
    """
    import fastjsonschema

    spec = spec or str(document.get("specVersion", ""))
    if spec not in CYCLONEDX_FILES:
        raise ValueError(f"No vendored CycloneDX schema for spec {spec!r}")
    try:
        _fast_cyclonedx(spec)(document)
        return []
    except fastjsonschema.JsonSchemaException:
        errors = _errors(_cyclonedx_validator(spec), document, limit)
        # The two validators should agree; if the full one finds nothing, report the fast one's finding.
        return errors or [{"path": "/", "message": "rejected by the compiled schema validator",
                           "validator": "fastjsonschema"}]


def validate_sarif(document: dict, limit: int = 50) -> list[dict]:
    """Schema errors for a SARIF 2.1.0 log."""
    return _errors(_sarif_validator(), document, limit)


def vendored() -> list[dict]:
    """What is vendored, for the Evidence screen."""
    return [{"file": p.name, "bytes": p.stat().st_size} for p in sorted(SCHEMA_DIR.glob("*.json"))]
