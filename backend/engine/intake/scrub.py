"""Structural scrub — drop anything that could be key material.

WHY THIS EXISTS
---------------
Adapters read native key-manager shapes. Those shapes occasionally include
fields that *would* carry secret material if a careless export ever put it
there. Scrubbing is a structural refuse, not a content heuristic: if the
attribute name is on the forbidden list it is dropped at any depth, before a
finding is built. That is the claim that lets a bank run the collector at all.
"""

from __future__ import annotations

from typing import Any

# Attribute names that would carry secret material. Shared with every adapter
# and with the vault collector facade — one list, one refuse path.
FORBIDDEN = {
    "CKA_VALUE", "CKA_PRIVATE_EXPONENT", "CKA_PRIME_1", "CKA_PRIME_2",
    "CKA_EXPONENT_1", "CKA_EXPONENT_2", "CKA_COEFFICIENT",
    "private_key", "private_key_pem", "key_material", "secret", "d", "p", "q",
}


def scrub(payload: dict) -> dict:
    """Drop anything that could be key material, at any depth."""
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        if key in FORBIDDEN:
            continue
        clean[key] = scrub(value) if isinstance(value, dict) else value
    return clean
