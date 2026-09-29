"""The dependency graph links what the evidence links: key pairs and algorithms reached through a library."""

from __future__ import annotations

from engine.dependencies import build_graph
from models.schemas import CryptoAsset


def _asset(id, **kw):
    base = {"id": id, "name": id, "source_type": "binary", "source_location": f"loc/{id}", "asset_class": "binary",
            "raw_details": {}}
    base.update(kw)
    return CryptoAsset(**base)


def _edges(graph):
    return {(e["source"], e["target"], e["kind"]) for e in graph["edges"]}


def test_a_held_key_and_the_certificate_presenting_it_are_one_key_pair():
    fp = "ab" * 32
    key = _asset("hsm-key", asset_class="hsm_key", source_type="config", raw_details={"public_key_sha256": fp})
    cert = _asset("tls-cert", asset_class="tls_certificate", source_type="tls", cert_subject="CN=pay",
                  raw_details={"public_key_sha256": fp.upper()})
    other = _asset("other", asset_class="hsm_key", raw_details={"public_key_sha256": "cd" * 32})
    assert ("hsm-key", "tls-cert", "same-key-pair") in _edges(build_graph([key, cert, other]))
    assert not any("other" in e[:2] for e in _edges(build_graph([key, cert, other])))


def test_an_algorithm_found_through_a_library_depends_on_that_library_in_the_same_image():
    lib = _asset("openssl", asset_class="crypto_library", source_location="img!/usr/lib/libssl.so.3",
                 raw_details={"library_id": "openssl", "image_digest": "sha256:1"})
    aes = _asset("aes", source_location="img!/usr/sbin/nginx",
                 raw_details={"via_library": "openssl", "image_digest": "sha256:1"})
    elsewhere = _asset("aes-other-image", source_location="img2!/usr/sbin/nginx",
                       raw_details={"via_library": "openssl", "image_digest": "sha256:2"})
    edges = _edges(build_graph([lib, aes, elsewhere]))
    assert ("aes", "openssl", "uses-library") in edges
    assert not any(e[0] == "aes-other-image" for e in edges)      # a library in another image is not this one
