"""WP2: dependency collector across nine ecosystems, matched to the library KB."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from collectors.dependency_scanner import (
    DependencyCollector, packages_in_text, parse_yarn_lock,
)
from collectors.registry import REGISTRY


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip("\n"), encoding="utf-8")
    return path


def _scan(root: Path):
    result = DependencyCollector().collect([str(root)])
    return result, {(f.raw_details["ecosystem"], f.raw_details["package"]): f for f in result.findings}


FIXTURES = {
    # ecosystem: (file, content, (ecosystem, package), expected version, expected pqc_capable)
    "requirements": ("py/requirements.txt", """
        # payments service
        cryptography==41.0.7
        rsa==4.9
        requests>=2.31
        pyjwt[crypto]>=2.8  ; python_version > "3.8"
        """, ("pypi", "rsa"), "4.9", False),
    "pipfile": ("pipenv/Pipfile.lock", json.dumps({
        "default": {"ecdsa": {"version": "==0.18.0"}, "flask": {"version": "==3.0.0"}}, "develop": {}}),
        ("pypi", "ecdsa"), "0.18.0", False),
    "poetry": ("poetry/poetry.lock", """
        [[package]]
        name = "liboqs-python"
        version = "0.10.0"

        [[package]]
        name = "click"
        version = "8.1.7"
        """, ("pypi", "liboqs-python"), "0.10.0", True),
    "pyproject": ("pep621/pyproject.toml", """
        [project]
        name = "svc"
        dependencies = ["PyCryptodome==3.20.0", "fastapi>=0.110"]
        """, ("pypi", "pycryptodome"), "3.20.0", None),
    "dist_info": ("venvlike/site/ecdsa-0.19.0.dist-info/METADATA", """
        Metadata-Version: 2.1
        Name: ecdsa
        Version: 0.19.0

        long description
        """, ("pypi", "ecdsa"), "0.19.0", False),
    "package_lock": ("web/package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"node-forge": "^1.3.1"}},
            "node_modules/node-forge": {"version": "1.3.1"},
            "node_modules/elliptic": {"version": "6.5.4"},
            "node_modules/left-pad": {"version": "1.3.0"},
        }}), ("npm", "elliptic"), "6.5.4", False),
    "yarn": ("yarnapp/yarn.lock", """
        # yarn lockfile v1

        "@noble/post-quantum@^0.2.0":
          version "0.2.1"
          resolved "https://registry.yarnpkg.com/x"

        tweetnacl@^1.0.3, tweetnacl@1.0.3:
          version "1.0.3"
        """, ("npm", "@noble/post-quantum"), "0.2.1", True),
    "pnpm": ("pnpmapp/pnpm-lock.yaml", """
        lockfileVersion: '9.0'
        packages:
          jsonwebtoken@9.0.2:
            resolution: {integrity: sha512-x}
          '@noble/curves@1.4.0':
            resolution: {integrity: sha512-y}
        """, ("npm", "@noble/curves"), "1.4.0", False),
    "pom": ("java/pom.xml", """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <properties>
            <bc.version>1.78.1</bc.version>
            <maven.compiler.release>17</maven.compiler.release>
          </properties>
          <dependencies>
            <dependency>
              <groupId>org.bouncycastle</groupId>
              <artifactId>bcprov-jdk18on</artifactId>
              <version>${bc.version}</version>
            </dependency>
          </dependencies>
        </project>
        """, ("maven", "org.bouncycastle:bcprov-jdk18on"), "1.78.1", False),
    "gradle": ("gradleapp/build.gradle.kts", """
        plugins { java }
        java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
        dependencies {
            implementation("org.bouncycastle:bcprov-jdk18on:1.80")
            implementation("io.jsonwebtoken:jjwt-api:0.12.5")
        }
        """, ("maven", "org.bouncycastle:bcprov-jdk18on"), "1.80", True),
    "gradle_lock": ("gradlelock/gradle.lockfile", """
        # This is a Gradle generated file
        com.nimbusds:nimbus-jose-jwt:9.37.3=runtimeClasspath
        empty=
        """, ("maven", "com.nimbusds:nimbus-jose-jwt"), "9.37.3", None),
    "go_mod": ("goapp/go.mod", """
        module example.com/gateway

        go 1.22

        toolchain go1.22.5

        require (
            golang.org/x/crypto v0.24.0
            github.com/cloudflare/circl v1.3.9 // indirect
        )
        """, ("runtime", "go-stdlib"), "1.22.5", False),
    "go_sum": ("gosum/go.sum", """
        github.com/golang-jwt/jwt/v5 v5.2.1 h1:abc=
        github.com/golang-jwt/jwt/v5 v5.2.1/go.mod h1:def=
        """, ("go", "github.com/golang-jwt/jwt/v5"), "5.2.1", None),
    "cargo": ("rustapp/Cargo.lock", """
        version = 3

        [[package]]
        name = "ring"
        version = "0.17.8"

        [[package]]
        name = "ml-kem"
        version = "0.2.1"
        """, ("cargo", "ml-kem"), "0.2.1", True),
    "packages_lock": ("dotnet/packages.lock.json", json.dumps({
        "version": 1,
        "dependencies": {"net8.0": {
            "BouncyCastle.Cryptography": {"type": "Direct", "resolved": "2.4.0"},
            "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}}}}),
        ("runtime", "dotnet"), "8", False),
    "csproj": ("dotnetproj/Api.csproj", """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup>
          <ItemGroup>
            <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.5.1" />
          </ItemGroup>
        </Project>
        """, ("runtime", "dotnet"), "10", True),
    "composer": ("php/composer.lock", json.dumps({
        "packages": [{"name": "phpseclib/phpseclib", "version": "3.0.37"}],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.0"}]}),
        ("composer", "phpseclib/phpseclib"), "3.0.37", None),
    "gemfile": ("ruby/Gemfile.lock", """
        GEM
          remote: https://rubygems.org/
          specs:
            jwt (2.8.1)
              base64
            rbnacl (7.1.1)
              ffi

        PLATFORMS
          ruby
        """, ("gem", "rbnacl"), "7.1.1", None),
    "vcpkg": ("cpp/vcpkg.json", json.dumps({
        "name": "edge", "dependencies": ["openssl", {"name": "liboqs"}],
        "overrides": [{"name": "openssl", "version": "3.0.13"}]}),
        ("vcpkg", "openssl"), "3.0.13", False),
    "conan": ("cppconan/conanfile.txt", """
        [requires]
        openssl/3.5.0
        zlib/1.3.1

        [generators]
        CMakeDeps
        """, ("conan", "openssl"), "3.5.0", True),
}


@pytest.mark.parametrize("fixture", sorted(FIXTURES))
def test_each_ecosystem_parses_and_resolves(tmp_path, fixture):
    rel, text, key, version, capable = FIXTURES[fixture]
    _write(tmp_path, rel, text)
    result, found = _scan(tmp_path)
    assert not result.failures, result.failures
    assert key in found, f"{key} not found; got {sorted(found)}"
    details = found[key].raw_details
    assert details["library_version"] == version
    assert details["pqc_capable"] is capable
    assert found[key].source_type == "dependency"
    assert found[key].asset_class == "crypto_library"


def test_all_nine_ecosystems_in_one_tree(tmp_path):
    for rel, text, *_ in FIXTURES.values():
        _write(tmp_path, rel, text)
    result, found = _scan(tmp_path)
    ecosystems = {eco for eco, _ in found} - {"runtime"}
    assert ecosystems >= {"pypi", "npm", "maven", "go", "cargo", "nuget", "composer", "gem"}
    assert ecosystems & {"vcpkg", "conan"}
    assert result.stats["packages_seen"] > result.stats["crypto_packages"] > 0


def test_non_crypto_packages_are_counted_not_reported(tmp_path):
    _write(tmp_path, "requirements.txt", "flask==3.0.0\nrequests==2.31.0\n")
    result, found = _scan(tmp_path)
    assert found == {}
    assert result.stats["packages_seen"] == 2


def test_ranges_are_never_turned_into_versions(tmp_path):
    _write(tmp_path, "requirements.txt", "cryptography>=41\n")
    _write(tmp_path, "java/pom.xml", """
        <project><dependencies><dependency>
          <groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId>
          <version>${undefined.prop}</version>
        </dependency></dependencies></project>
        """)
    _, found = _scan(tmp_path)
    crypto = found[("pypi", "cryptography")].raw_details
    assert crypto["library_version"] == "unknown"
    assert crypto["version_spec"] == ">=41"
    assert crypto["confidence"] == pytest.approx(0.60)
    bc = found[("maven", "org.bouncycastle:bcprov-jdk18on")].raw_details
    assert bc["library_version"] == "unknown" and bc["pqc_capable"] is None


def test_lockfile_version_wins_over_manifest_range(tmp_path):
    _write(tmp_path, "web/package.json", json.dumps({"dependencies": {"node-forge": "^1.3.0"}}))
    _write(tmp_path, "web/package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {"": {"dependencies": {"node-forge": "^1.3.0"}},
                     "node_modules/node-forge": {"version": "1.3.1"}}}))
    result, found = _scan(tmp_path)
    forge = [f for f in result.findings if f.raw_details["package"] == "node-forge"]
    assert len(forge) == 1
    details = forge[0].raw_details
    assert details["library_version"] == "1.3.1"
    assert details["confidence"] == pytest.approx(0.75)
    assert len(details["manifests"]) == 2


def test_go_indirect_marked_transitive(tmp_path):
    rel, text, *_ = FIXTURES["go_mod"]
    _write(tmp_path, rel, text)
    _, found = _scan(tmp_path)
    assert found[("go", "github.com/cloudflare/circl")].raw_details["dependency_scope"] == "transitive"
    assert found[("go", "golang.org/x/crypto")].raw_details["dependency_scope"] == "direct"


def test_java_runtime_from_pom(tmp_path):
    rel, text, *_ = FIXTURES["pom"]
    _write(tmp_path, rel, text)
    _, found = _scan(tmp_path)
    jdk = found[("runtime", "openjdk")].raw_details
    assert jdk["library_version"] == "17"
    assert jdk["pqc_capable"] is False
    assert "24" in jdk["upgrade_path"]


def test_upgrade_path_hint_for_old_library(tmp_path):
    rel, text, *_ = FIXTURES["vcpkg"]
    _write(tmp_path, rel, text)
    _, found = _scan(tmp_path)
    assert found[("vcpkg", "openssl")].raw_details["upgrade_path"] == "OpenSSL 3.5 LTS"


def test_malformed_manifest_is_a_reported_failure(tmp_path):
    _write(tmp_path, "bad/package-lock.json", "{ not json")
    result, _ = _scan(tmp_path)
    assert any("manifest parse failed" in f["reason"] for f in result.failures)


def test_yarn_berry_format():
    text = textwrap.dedent('''
        __metadata:
          version: 6

        "jose@npm:^5.2.0":
          version: 5.2.3
          resolution: "jose@npm:5.2.3"
        ''').lstrip("\n")
    pkgs = parse_yarn_lock(Path("yarn.lock"), text)
    assert [(p.name, p.version) for p in pkgs] == [("jose", "5.2.3")]


def test_node_modules_is_not_walked(tmp_path):
    _write(tmp_path, "app/node_modules/elliptic/package.json", json.dumps({"dependencies": {"bn.js": "4.0.0"}}))
    result, found = _scan(tmp_path)
    assert found == {} and result.stats["manifests"] == 0


def test_findings_are_deterministic(tmp_path):
    for rel, text, *_ in FIXTURES.values():
        _write(tmp_path, rel, text)
    first = [(f.id, f.source_location) for f in DependencyCollector().collect([str(tmp_path)]).findings]
    second = [(f.id, f.source_location) for f in DependencyCollector().collect([str(tmp_path)]).findings]
    assert first == second


def test_registered_in_the_collector_registry():
    assert REGISTRY["dependency"].plane == "built"


def test_packages_in_text_ignores_unknown_files():
    assert packages_in_text(Path("README.md"), "cryptography==1.0") == []
