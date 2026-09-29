"""WP4: tree-sitter source collector over seven language families.

One fixture per language, each asserting (line, algorithm, key size / mode /
protocol) for the call sites it must find, plus the behaviours that separate a
parser from grep: comments are not findings, runtime-chosen algorithms are
unresolved rather than guessed, and the regex fallback is reported by name.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from collectors import source_scanner as ss
from collectors.registry import REGISTRY

FIXTURES = {
    "pay.py": ("python", '''
        import hashlib
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        eck = ec.generate_private_key(ec.SECP384R1())
        h = hashlib.md5(b"x")  # hashlib.sha1() in a comment must not count
        algo = config["hash"]
        g = hashlib.new(algo)
        token = jwt.encode(payload, secret, algorithm="RS256")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        doc = "call hashlib.sha1() in a string"
        '''),
    "Pay.java": ("java", '''
        class Pay { void f(String alg) throws Exception {
          Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
          Signature s = Signature.getInstance("SHA1withRSA");
          KeyPairGenerator g = KeyPairGenerator.getInstance(alg);
          SSLContext ctx = SSLContext.getInstance("TLSv1");
          SSLContext ok = SSLContext.getInstance("TLS");
          KEM k = KEM.getInstance("ML-KEM");
          var spec = new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4);
          String j = Jwts.builder().signWith(key, Jwts.SIG.RS256).compact();
        }}
        '''),
    "main.go": ("go", '''
        package main
        import ("crypto/rsa"; "crypto/md5"; "crypto/tls"; "crypto/mlkem"; "crypto/des")
        func main() {
            k, _ := rsa.GenerateKey(rand.Reader, 2048)
            _ = md5.New()
            c := &tls.Config{MinVersion: tls.VersionTLS10, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
            dk, _ := mlkem.GenerateKey768()
        }
        '''),
    "gw.c": ("c", '''
        #include <openssl/rsa.h>
        #include <openssl/des.h>
        void f() {
          RSA_generate_key_ex(r, 1024, e, NULL);
          const EVP_MD *m = EVP_md5();
          EVP_CIPHER *c = EVP_aes_128_ecb();
          EVP_PKEY *p = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)4096);
          SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
          OQS_KEM *k = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
          EVP_PKEY_CTX *x = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
        }
        '''),
    "api.ts": ("javascript", '''
        import crypto from "crypto";
        const h = crypto.createHash("sha1");
        const { publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
        const c = crypto.createCipheriv("des-ede3-cbc", key, iv);
        const k = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
        const t = jwt.sign(payload, key, { algorithm: "ES256" });
        const kem = ml_kem768.keygen();
        const d = crypto.createHash(algorithmFromConfig);
        '''),
    "lib.rs": ("rust", '''
        use rsa::RsaPrivateKey;
        use ml_kem::MlKem768;
        use des::Des;
        fn f() {
            let k = RsaPrivateKey::new(&mut rng, 2048);
            let r = Rsa::generate(4096).unwrap();
            let h = Md5::new();
            let (dk, ek) = MlKem768::generate(&mut rng);
        }
        '''),
    "Svc.cs": ("csharp", '''
        using System.Security.Cryptography;
        class Svc { void F() {
            var r = RSA.Create(2048);
            var m = MD5.Create();
            var p = new RSACryptoServiceProvider(1024);
            var e = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
            var proto = SslProtocols.Tls11;
        } }
        '''),
}

# file -> list of (line, algorithm, extra checks)
EXPECTED = {
    "pay.py": [(3, "RSA", {"key_size": 2048}), (4, "ECDSA", {"key_size": 384}), (5, "MD5", {}),
               (7, None, {"unresolved": True}), (8, "RSA", {"argument_literal": "RS256"}),
               (9, None, {"protocol": "TLSv1.0"})],
    "Pay.java": [(2, "AES", {"mode": "ECB", "padding": "PKCS5Padding"}), (3, "RSA", {"digest": "SHA-1"}),
                 (4, None, {"unresolved": True}), (5, None, {"protocol": "TLSv1.0"}),
                 (7, "ML-KEM-768", {}), (8, "RSA", {"key_size": 3072}), (9, "RSA", {})],
    "main.go": [(4, "RSA", {"key_size": 2048}), (5, "MD5", {}), (6, None, {"protocol": "TLSv1.0"}),
                (6, "X25519MLKEM768", {}), (7, "ML-KEM-768", {}), (2, "DES", {"match_kind": "import"})],
    "gw.c": [(4, "RSA", {"key_size": 1024}), (5, "MD5", {}), (6, "AES-128", {"mode": "ECB"}),
             (7, "RSA", {"key_size": 4096}), (8, None, {"protocol": "TLSv1.1"}), (9, "ML-KEM-768", {}),
             (10, "ML-DSA-65", {}), (2, "DES", {"match_kind": "import"})],
    "api.ts": [(2, "SHA-1", {}), (3, "RSA", {"key_size": 2048}), (4, "3DES", {"mode": "CBC"}),
               (5, "ECDSA", {}), (6, "ECDSA", {"jose": "ES256"}), (7, "ML-KEM-768", {}),
               (8, None, {"unresolved": True})],
    "lib.rs": [(5, "RSA", {"key_size": 2048}), (6, "RSA", {"key_size": 4096}), (7, "MD5", {}),
               (8, "ML-KEM-768", {}), (3, "DES", {"match_kind": "import"})],
    "Svc.cs": [(3, "RSA", {"key_size": 2048}), (4, "MD5", {}), (5, "RSA", {"key_size": 1024}),
               (6, "ECDSA", {"key_size": 256}), (7, "ML-KEM-768", {}), (8, None, {"protocol": "TLSv1.1"})],
}


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    root = tmp_path_factory.mktemp("repo")
    for name, (_lang, text) in FIXTURES.items():
        (root / name).write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return root


@pytest.fixture(scope="module")
def scanned(tree):
    return ss.SourceCollector().collect([str(tree)])


def _at(findings, name, line):
    return [f for f in findings if f.source_location.endswith(f"{name}:{line}")]


def _value(finding, key):
    if key in ("key_size", "protocol", "algorithm"):
        return getattr(finding, key)
    return finding.raw_details.get(key)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_language_fixture_finds_every_expected_site(scanned, name):
    for line, algorithm, checks in EXPECTED[name]:
        candidates = [f for f in _at(scanned.findings, name, line) if f.algorithm == algorithm]
        candidates = [f for f in candidates if all(_value(f, k) == v for k, v in checks.items())]
        assert candidates, (f"{name}:{line} expected {algorithm} {checks}; got "
                            f"{[(f.algorithm, f.key_size, f.protocol, f.raw_details.get('api')) for f in _at(scanned.findings, name, line)]}")


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_no_unexpected_findings(scanned, name):
    found = [f for f in scanned.findings if f.source_location.rsplit(":", 1)[0].endswith(name)]
    assert len(found) == len(EXPECTED[name]), [(f.source_location, f.algorithm) for f in found]


def test_all_seven_language_families_parsed_by_tree_sitter(scanned):
    assert set(scanned.stats["by_language"]) == {"python", "java", "go", "c", "javascript", "rust", "csharp"}
    assert scanned.stats["by_engine"] == {"tree-sitter": 7}
    assert scanned.failures == []


def test_comments_and_strings_are_not_findings(scanned):
    assert not [f for f in scanned.findings if f.algorithm == "SHA-1" and "pay.py" in f.source_location]


def test_family_name_and_current_tls_are_not_findings(scanned):
    """SSLContext.getInstance("TLS") names a family, not a deprecated version."""
    assert not _at(scanned.findings, "Pay.java", 6)


def test_unresolved_sites_record_the_expression_not_a_guess(scanned):
    unresolved = [f for f in scanned.findings if f.raw_details["unresolved"]]
    assert len(unresolved) == 3 == scanned.stats["unresolved"]
    for f in unresolved:
        assert f.algorithm is None
        assert f.raw_details["confidence"] == pytest.approx(ss.UNRESOLVED_CONFIDENCE)
        assert "cannot be resolved statically" in f.raw_details["note"]
    assert {f.raw_details["argument"] for f in unresolved} == {"algo", "alg", "algorithmFromConfig"}


def test_literal_arguments_raise_confidence(scanned):
    aes = _at(scanned.findings, "Pay.java", 2)[0]
    md5 = _at(scanned.findings, "pay.py", 5)[0]
    assert aes.raw_details["confidence"] == pytest.approx(ss.LITERAL_CONFIDENCE)
    assert md5.raw_details["confidence"] == pytest.approx(0.70)


def test_import_only_reported_without_a_call_site(scanned):
    go = [f for f in scanned.findings if "main.go" in f.source_location and f.raw_details["match_kind"] == "import"]
    assert [f.algorithm for f in go] == ["DES"]  # rsa/md5/mlkem have call sites, des does not


def test_no_source_text_beyond_the_callee_is_stored(scanned):
    """A call's arguments can hold secrets; only the callee and the algorithm literal are kept."""
    jwt = _at(scanned.findings, "pay.py", 8)[0]
    assert "secret" not in str(jwt.raw_details) and "payload" not in str(jwt.raw_details)


def test_findings_are_deterministic(tree):
    first = sorted(f.id for f in ss.SourceCollector().collect([str(tree)]).findings)
    second = sorted(f.id for f in ss.SourceCollector().collect([str(tree)]).findings)
    assert first == second


def test_regex_fallback_is_reported_by_name(tree, monkeypatch):
    monkeypatch.setattr(ss, "_HAVE_TREE_SITTER", False)
    result = ss.SourceCollector().collect([str(tree)])
    assert result.stats["by_engine"] == {"regex": 2}          # Python and Java only
    assert result.stats["not_scanned"] == 5
    assert all(f.raw_details["engine"] == "regex" for f in result.findings)
    assert any("no parser available" in f["reason"] for f in result.failures)


@pytest.mark.parametrize("literal,expected", [
    ("AES/GCM/NoPadding", ("AES", {"mode": "GCM", "padding": "NoPadding"})),
    ("SHA256withECDSA", ("ECDSA", {"digest": "SHA-256"})),
    ("aes-256-gcm", ("AES-256", {"mode": "GCM"})),
    ("des-ede3-cbc", ("3DES", {"mode": "CBC"})),
    ("RSA-OAEP", ("RSA", {})),
    ("PS384", ("RSA", {"jose": "PS384"})),
    ("ml_kem_1024", ("ML-KEM-1024", {})),
    ("Dilithium3", ("ML-DSA-65", {})),
    ("ECDSA_P384", ("ECDSA", {"key_size": 384})),
    ("frobnicate", ("frobnicate", {"unrecognized": True})),
])
def test_algorithm_name_normalisation(literal, expected):
    assert ss.normalize_algorithm(literal) == expected


def test_signature_names_that_are_only_digests_stay_unresolved():
    algorithm, extra = ss.normalize_algorithm("SHA256", signature=True)
    assert algorithm is None and extra["digest"] == "SHA-256"


@pytest.mark.parametrize("token,expected", [
    ("TLSv1", "TLSv1.0"), ("TLS1_1_VERSION", "TLSv1.1"), ("Tls11", "TLSv1.1"), ("SSL30", "SSLv3"),
    ("TLS", None), ("TLSv1.3", "TLSv1.3"),
])
def test_protocol_normalisation(token, expected):
    assert ss.normalize_protocol(token) == expected


def test_rule_files_load_and_every_grammar_is_available():
    rules = ss.load_rules()
    assert {r.language for r in rules.values()} == {"python", "java", "go", "c", "javascript", "rust", "csharp"}
    assert all(status == "tree-sitter" for status in ss.grammar_status().values())


def test_git_url_input_is_cloned_shallow_and_labelled(tmp_path, tree):
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    repo = tmp_path / "origin"
    shutil.copytree(tree, repo)
    run = lambda *args: subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("-c", "user.email=t@example.com", "-c", "user.name=t", "add", ".")
    run("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "fixture")
    url = repo.resolve().as_uri()
    result = ss.SourceCollector().collect([url])
    assert result.stats["repos"][0]["url"] == url
    commit = result.stats["repos"][0]["commit"]
    assert len(commit) == 40
    assert result.findings and all(f.source_location.startswith(f"{url}@{commit[:12]}:") for f in result.findings)


def test_unreachable_repo_is_a_reported_failure():
    result = ss.SourceCollector().collect(["file:///definitely/not/a/repo.git"])
    assert result.findings == [] and "clone failed" in result.failures[0]["reason"]


def test_registered_in_the_collector_registry():
    assert isinstance(REGISTRY["source"], ss.SourceCollector)
