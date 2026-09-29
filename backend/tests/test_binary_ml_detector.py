"""The learned_function layer on real stripped, statically linked binaries (tests/fixtures/learned/).

Fixtures are prebuilt with zig cc (commands in each .c file), so these tests need no cross-compiler.
"""
from pathlib import Path

import pytest

from collectors.binary_scanner import scan_blob
from engine.binary_ml import detector
from engine.cbom import _vera_properties
from models.schemas import CryptoAsset

FIX = Path(__file__).parent / "fixtures" / "learned"
pytestmark = pytest.mark.skipif(not detector.available(), reason="detector model not exported")


def _scan(name):
    path = FIX / f"{name}.elf"
    return scan_blob(path.read_bytes(), str(path))


@pytest.mark.parametrize("arch,address", [("x86_64", "0x1002240"), ("aarch64", "0x101151c")])
def test_siphash_in_a_stripped_static_binary_is_certified(arch, address):
    # SipHash has no table constants and the binary has no symbols: only the learned layer can see it.
    res = _scan(f"siphash_{arch}")
    learned = [f for f in res.findings if "layer:learned_function" in f.tags]
    assert len(learned) == 1
    d = learned[0].raw_details
    assert d["detection_q_value"] <= d["detection_alpha"] == 0.1
    assert [s["address"] for s in d["selected_functions"]] == [address]
    assert d["detection_boundaries"] == "call-targets"
    assert learned[0].algorithm is None          # it says *that* it is crypto, not *which*


def test_cipher_inlined_into_main_is_a_known_miss():
    # Documented v1 limitation (research/README.md): the cipher is inlined into main next to argument
    # parsing and printf, so the recovered region looks like orchestration. The layer ran and certified
    # nothing, which is the correct outcome for a detector that cannot tell.
    res = _scan("proprietary_cipher_x86_64")
    assert res.stats["functions_scored"] > 0
    assert not [f for f in res.findings if "layer:learned_function" in f.tags]


def test_layer_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("VERA_BINARY_DETECTOR", "0")
    res = _scan("siphash_x86_64")
    assert not [f for f in res.findings if "layer:learned_function" in f.tags]


def test_q_value_reaches_the_cbom_properties():
    finding = [f for f in _scan("siphash_aarch64").findings if "layer:learned_function" in f.tags][0]
    asset = CryptoAsset(**finding.model_dump(), name=finding.raw_details["display_name"])
    props = {p["name"]: p["value"] for p in _vera_properties(asset)}
    assert float(props["vera:detection-q-value"]) <= 0.1
    assert props["vera:detection-isa"] == "aarch64"
