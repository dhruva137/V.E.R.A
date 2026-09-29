"""Dependency collector (plane: built): which crypto libraries a project ships.

The PS lists "libraries" as an artefact class and "libraries" again as a scan
target. A lockfile is the most precise statement of what a build contains, so
this collector reads manifests and lockfiles in nine ecosystems, keeps only the
packages the crypto-library knowledge base knows, and asks the KB whether each
version blocks post-quantum migration (engine/kb/libraries.py).

    Python   requirements*.txt, Pipfile.lock, poetry.lock, pyproject.toml, *.dist-info/METADATA
    Node     package.json, package-lock.json (v1-v3), yarn.lock (classic + berry), pnpm-lock.yaml
    Java     pom.xml (with ${property} substitution), build.gradle(.kts), gradle.lockfile
    Go       go.mod (plus `go` / `toolchain` directives), go.sum
    Rust     Cargo.lock
    .NET     packages.lock.json, *.csproj PackageReference (plus TargetFramework)
    PHP      composer.lock
    Ruby     Gemfile.lock
    C/C++    vcpkg.json, conanfile.txt
    OS       /var/lib/dpkg/status (Debian/Ubuntu), /lib/apk/db/installed (Alpine)

Runtime declarations count too: `go 1.22` in go.mod, a Java release in pom.xml
or Gradle, and `net8.0` in a .csproj each say which standard library the build
gets, and Go 1.24, JDK 24 and .NET 10 are where PQC becomes native.

VERSIONS ARE NEVER GUESSED
--------------------------
An exact pin (lockfile, `==`, a bare Maven version) is a version. A range
(`>=41`, `^3.0.0`) is recorded as `version_spec` and the version stays
"unknown", so the PQC answer stays "unknown" too. When the same package appears
in a manifest and a lockfile in one directory, the lockfile's exact version
wins and both files are kept as evidence.

STATED LIMITATIONS
------------------
- Only packages in the KB become findings; everything else is counted, not
  reported. A crypto library missing from the KB is missed until it is added.
- Transitive dependencies are seen only when a lockfile lists them.
- Maven parent POMs and Gradle version catalogs outside the tree are not
  resolved; an unresolved `${property}` leaves the version unknown.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import yaml

from collectors.base import (
    DEFAULT_LIMITS, CollectResult, Limits, Timer, evidence, read_capped, stable_id, walk,
)
from engine.kb import libraries as kb
from models.schemas import RawCryptoFinding

COLLECTOR = "dependency_scanner"
CONFIDENCE_EXACT = 0.75   # a lockfile or pinned manifest: the build contains this version
CONFIDENCE_RANGE = 0.60   # a manifest range: the build contains *some* version of it


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str | None
    spec: str | None
    path: Path
    line: int | None = None
    scope: str = "unknown"          # direct | transitive | unknown
    runtime: bool = False           # a language runtime, not a package

    @property
    def exact(self) -> bool:
        return self.version is not None


_PEP503 = re.compile(r"[-_.]+")


def _pypi(name: str) -> str:
    return _PEP503.sub("-", name).lower()


def _line_of(text: str, needle: str) -> int | None:
    at = text.find(needle)
    return text.count("\n", 0, at) + 1 if at >= 0 else None


_EXACT = re.compile(r"^v?\d+(\.\d+)*([.\-+][0-9A-Za-z.\-]+)?$")


def _exact_or_none(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip().strip("\"'")
    value = value[2:] if value.startswith("==") else value
    value = value[1:] if value.startswith("=") and not value.startswith("==") else value
    return value.lstrip("v") if _EXACT.match(value) else None


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[[^\]]*\])?\s*([=<>!~]=?=?[^;#]*)?")


def parse_requirements(path: Path, text: str) -> list[Package]:
    out = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        spec = (m.group(3) or "").strip() or None
        version = spec[2:].strip() if spec and spec.startswith("==") and "," not in spec else None
        out.append(Package("pypi", _pypi(m.group(1)), _exact_or_none(version), spec, path, number, "direct"))
    return out


def parse_pipfile_lock(path: Path, text: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            out.append(Package("pypi", _pypi(name), _exact_or_none(info.get("version")), info.get("version"),
                               path, _line_of(text, f'"{name}"'), "unknown"))
    return out


def parse_toml_lock(ecosystem: str):
    def parse(path: Path, text: str) -> list[Package]:
        data = tomllib.loads(text)
        norm = _pypi if ecosystem == "pypi" else (lambda n: n)
        return [Package(ecosystem, norm(p["name"]), _exact_or_none(p.get("version")), p.get("version"), path,
                        _line_of(text, f'name = "{p["name"]}"'), "unknown")
                for p in data.get("package", []) if "name" in p]
    return parse


def parse_pyproject(path: Path, text: str) -> list[Package]:
    data = tomllib.loads(text)
    out = []
    for dep in (data.get("project") or {}).get("dependencies") or []:
        for pkg in parse_requirements(path, dep):
            pkg.line = _line_of(text, dep)
            out.append(pkg)
    for name, spec in ((data.get("tool") or {}).get("poetry") or {}).get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        spec_text = spec if isinstance(spec, str) else (spec or {}).get("version")
        out.append(Package("pypi", _pypi(name), _exact_or_none(spec_text), spec_text, path,
                           _line_of(text, name), "direct"))
    return out


def parse_dist_info(path: Path, text: str) -> list[Package]:
    name = version = None
    for line in text.splitlines():
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
        elif not line.strip():
            break
    if not name:
        return []
    return [Package("pypi", _pypi(name), _exact_or_none(version), version, path, 1, "installed")]


# --------------------------------------------------------------------------
# Node
# --------------------------------------------------------------------------


def parse_package_json(path: Path, text: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            out.append(Package("npm", name, _exact_or_none(spec), spec, path, _line_of(text, f'"{name}"'), "direct"))
    return out


def parse_package_lock(path: Path, text: str) -> list[Package]:
    data = json.loads(text)
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2 / v3
        root = packages.get("", {})
        direct = set((root.get("dependencies") or {})) | set((root.get("devDependencies") or {}))
        for key, info in packages.items():
            if not key.startswith("node_modules/") and "/node_modules/" not in key:
                continue
            name = key.rsplit("node_modules/", 1)[1]
            out.append(Package("npm", name, _exact_or_none(info.get("version")), info.get("version"), path,
                               _line_of(text, f'"{key}"'), "direct" if name in direct else "transitive"))
        return out

    def walk_v1(deps: dict, depth: int):
        for name, info in (deps or {}).items():
            out.append(Package("npm", name, _exact_or_none(info.get("version")), info.get("version"), path,
                               _line_of(text, f'"{name}"'), "direct" if depth == 0 else "transitive"))
            walk_v1(info.get("dependencies") or {}, depth + 1)

    walk_v1(data.get("dependencies") or {}, 0)
    return out


_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?', re.M)


def _split_npm_spec(entry: str) -> str:
    entry = entry.strip().strip('"')
    at = entry.rfind("@")
    return entry[:at] if at > 0 else entry


def parse_yarn_lock(path: Path, text: str) -> list[Package]:
    out = []
    blocks = re.split(r"\n(?=\S)", text)
    for block in blocks:
        header, _, body = block.partition("\n")
        if not header.rstrip().endswith(":") or header.startswith(("#", "__metadata")):
            continue
        names = {_split_npm_spec(part) for part in header.rstrip(":").split(",")}
        version = _YARN_VERSION.search(body)
        for name in names:
            out.append(Package("npm", name, _exact_or_none(version.group(1) if version else None),
                               version.group(1) if version else None, path, _line_of(text, header), "unknown"))
    return out


def parse_pnpm_lock(path: Path, text: str) -> list[Package]:
    data = yaml.safe_load(text) or {}
    out = []
    for key in (data.get("packages") or {}):
        entry = str(key).lstrip("/").split("(", 1)[0]
        at = entry.rfind("@")
        if at <= 0:
            continue
        name, version = entry[:at], entry[at + 1:]
        out.append(Package("npm", name, _exact_or_none(version), version, path, _line_of(text, str(key)), "unknown"))
    return out


# --------------------------------------------------------------------------
# Java
# --------------------------------------------------------------------------


def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def parse_pom(path: Path, text: str) -> list[Package]:
    root = ET.fromstring(text)
    _strip_ns(root)
    props = {el.tag: (el.text or "").strip() for el in root.findall("./properties/*")}
    project_version = (root.findtext("version") or "").strip()
    if project_version:
        props.setdefault("project.version", project_version)

    def resolve(value: str | None) -> str | None:
        if not value:
            return None
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value.strip())

    out = []
    for dep in root.iter("dependency"):
        group, artifact = dep.findtext("groupId"), dep.findtext("artifactId")
        if not group or not artifact:
            continue
        spec = resolve(dep.findtext("version"))
        version = _exact_or_none(spec) if spec and "${" not in spec and not spec.startswith(("[", "(")) else None
        out.append(Package("maven", f"{group.strip()}:{artifact.strip()}", version, spec, path,
                           _line_of(text, f"<artifactId>{artifact.strip()}</artifactId>"), "direct"))
    java = next((props[k] for k in ("maven.compiler.release", "java.version", "maven.compiler.source",
                                    "maven.compiler.target") if props.get(k)), None)
    if java:
        out.append(Package("runtime", "openjdk", _exact_or_none(java.replace("1.8", "8")), java, path,
                           _line_of(text, java), "direct", runtime=True))
    return out


_GRADLE_DEP = re.compile(
    r"""\b(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation|annotationProcessor)\s*\(?\s*["']([^:"'\s]+):([^:"'\s]+):([^"'@\s]+)["']""")
_GRADLE_JAVA = re.compile(
    r"""(?:JavaLanguageVersion\.of\(\s*(\d+)\s*\)|JavaVersion\.VERSION_(\d+)(?:_(\d+))?|jvmTarget\s*=\s*["'](\d+(?:\.\d+)?)["'])""")


def parse_gradle(path: Path, text: str) -> list[Package]:
    out = [Package("maven", f"{m.group(1)}:{m.group(2)}", _exact_or_none(m.group(3)), m.group(3), path,
                   text.count("\n", 0, m.start()) + 1, "direct") for m in _GRADLE_DEP.finditer(text)]
    java = _GRADLE_JAVA.search(text)
    if java:
        groups = [g for g in java.groups() if g]
        release = groups[1] if groups[0] == "1" and len(groups) > 1 else groups[0]
        out.append(Package("runtime", "openjdk", _exact_or_none(release), java.group(0), path,
                           text.count("\n", 0, java.start()) + 1, "direct", runtime=True))
    return out


def parse_gradle_lockfile(path: Path, text: str) -> list[Package]:
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        coordinate = line.split("=", 1)[0].strip()
        parts = coordinate.split(":")
        if len(parts) == 3 and not line.startswith("#"):
            out.append(Package("maven", f"{parts[0]}:{parts[1]}", _exact_or_none(parts[2]), parts[2], path,
                               number, "unknown"))
    return out


# --------------------------------------------------------------------------
# Go, Rust, .NET, PHP, Ruby, C/C++
# --------------------------------------------------------------------------


def parse_go_mod(path: Path, text: str) -> list[Package]:
    out = []
    in_block = False
    toolchain = re.search(r"^toolchain\s+go(\S+)", text, re.M)
    go_directive = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", text, re.M)
    runtime = toolchain or go_directive
    if runtime:
        out.append(Package("runtime", "go-stdlib", _exact_or_none(runtime.group(1)), runtime.group(0), path,
                           text.count("\n", 0, runtime.start()) + 1, "direct", runtime=True))
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        body = line[len("require "):] if line.startswith("require ") else (line if in_block else "")
        parts = body.split()
        if len(parts) >= 2:
            scope = "transitive" if "// indirect" in raw else "direct"
            out.append(Package("go", parts[0], _exact_or_none(parts[1]), parts[1], path, number, scope))
    return out


def parse_go_sum(path: Path, text: str) -> list[Package]:
    seen, out = set(), []
    for number, line in enumerate(text.splitlines(), 1):
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod") and (parts[0], parts[1]) not in seen:
            seen.add((parts[0], parts[1]))
            out.append(Package("go", parts[0], _exact_or_none(parts[1]), parts[1], path, number, "unknown"))
    return out


def _dotnet_runtime(framework: str, path: Path, text: str) -> Package | None:
    m = re.match(r"net(\d+)\.\d+", framework.strip())
    if not m:
        return None
    return Package("runtime", "dotnet", m.group(1), framework, path, _line_of(text, framework), "direct",
                   runtime=True)


def parse_packages_lock(path: Path, text: str) -> list[Package]:
    data = json.loads(text)
    out = []
    for framework, deps in (data.get("dependencies") or {}).items():
        runtime = _dotnet_runtime(framework, path, text)
        if runtime:
            out.append(runtime)
        for name, info in (deps or {}).items():
            scope = "direct" if info.get("type") == "Direct" else "transitive"
            out.append(Package("nuget", name, _exact_or_none(info.get("resolved")), info.get("resolved"), path,
                               _line_of(text, f'"{name}"'), scope))
    return out


def parse_csproj(path: Path, text: str) -> list[Package]:
    root = ET.fromstring(text)
    _strip_ns(root)
    out = []
    for ref in root.iter("PackageReference"):
        name = ref.get("Include") or ref.get("Update")
        if not name:
            continue
        spec = ref.get("Version") or ref.findtext("Version")
        out.append(Package("nuget", name, _exact_or_none(spec), spec, path, _line_of(text, name), "direct"))
    frameworks = (root.findtext(".//TargetFramework") or root.findtext(".//TargetFrameworks") or "")
    for framework in filter(None, frameworks.split(";")):
        runtime = _dotnet_runtime(framework, path, text)
        if runtime:
            out.append(runtime)
    return out


def parse_composer_lock(path: Path, text: str) -> list[Package]:
    data = json.loads(text)
    return [Package("composer", p["name"], _exact_or_none(p.get("version")), p.get("version"), path,
                    _line_of(text, f'"{p["name"]}"'), "unknown")
            for section in ("packages", "packages-dev") for p in data.get(section) or [] if "name" in p]


_GEM_SPEC = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$")


def parse_gemfile_lock(path: Path, text: str) -> list[Package]:
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        m = _GEM_SPEC.match(line)
        if m:
            version = m.group(2).split("-", 1)[0]
            out.append(Package("gem", m.group(1), _exact_or_none(version), m.group(2), path, number, "unknown"))
    return out


def parse_vcpkg(path: Path, text: str) -> list[Package]:
    data = json.loads(text)
    overrides = {o.get("name"): o.get("version") for o in data.get("overrides") or [] if isinstance(o, dict)}
    out = []
    for dep in data.get("dependencies") or []:
        name = dep if isinstance(dep, str) else dep.get("name")
        if not name:
            continue
        pinned = overrides.get(name)
        spec = pinned or (None if isinstance(dep, str) else dep.get("version>="))
        out.append(Package("vcpkg", name, _exact_or_none(pinned), spec, path, _line_of(text, f'"{name}"'), "direct"))
    return out


def parse_conanfile(path: Path, text: str) -> list[Package]:
    out, section = [], None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("["):
            section = line
            continue
        if section in ("[requires]", "[tool_requires]") and "/" in line:
            name, _, rest = line.partition("/")
            version = rest.split("@", 1)[0]
            out.append(Package("conan", name, _exact_or_none(version), version, path, number, "direct"))
    return out


def _upstream(version: str | None) -> str | None:
    """'1:3.0.11-1~deb12u2' -> '3.0.11'; '3.1.4-r5' -> '3.1.4'. Distro revisions dropped."""
    if not version:
        return None
    version = version.split(":", 1)[-1]
    version = re.sub(r"-r\d+$", "", version)
    if "-" in version:
        version = version.rsplit("-", 1)[0]
    return _exact_or_none(version.split("+", 1)[0])


def parse_dpkg_status(path: Path, text: str) -> list[Package]:
    out = []
    for block in text.split("\n\n"):
        fields = dict(re.findall(r"^(Package|Version|Status): (.+)$", block, re.M))
        if fields.get("Package") and "installed" in fields.get("Status", "installed"):
            out.append(Package("deb", fields["Package"], _upstream(fields.get("Version")), fields.get("Version"),
                               path, _line_of(text, f"Package: {fields['Package']}\n"), "installed"))
    return out


def parse_apk_installed(path: Path, text: str) -> list[Package]:
    out = []
    for block in text.split("\n\n"):
        fields = dict(re.findall(r"^([PV]):(.+)$", block, re.M))
        if fields.get("P"):
            out.append(Package("apk", fields["P"], _upstream(fields.get("V")), fields.get("V"), path,
                               _line_of(text, f"P:{fields['P']}\n"), "installed"))
    return out


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

_BY_NAME = {
    "Pipfile.lock": parse_pipfile_lock, "poetry.lock": parse_toml_lock("pypi"),
    "pyproject.toml": parse_pyproject, "package.json": parse_package_json,
    "package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock, "pnpm-lock.yaml": parse_pnpm_lock, "pom.xml": parse_pom,
    "build.gradle": parse_gradle, "build.gradle.kts": parse_gradle, "gradle.lockfile": parse_gradle_lockfile,
    "go.mod": parse_go_mod, "go.sum": parse_go_sum, "Cargo.lock": parse_toml_lock("cargo"),
    "packages.lock.json": parse_packages_lock, "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock, "vcpkg.json": parse_vcpkg, "conanfile.txt": parse_conanfile,
}

MANIFEST_NAMES = frozenset(_BY_NAME)


def parser_for(path: Path):
    name = path.name
    if name in _BY_NAME:
        return _BY_NAME[name]
    if name.startswith("requirements") and name.endswith((".txt", ".in")):
        return parse_requirements
    if name.endswith(".csproj"):
        return parse_csproj
    if name == "METADATA" and path.parent.name.endswith(".dist-info"):
        return parse_dist_info
    posix = path.as_posix()
    if posix.endswith("var/lib/dpkg/status"):
        return parse_dpkg_status
    if posix.endswith("lib/apk/db/installed"):
        return parse_apk_installed
    return None


def _lookup(pkg: Package) -> kb.Library | None:
    if pkg.runtime:
        return kb.get(pkg.name)
    if pkg.ecosystem == "pypi":
        for (eco, name), lib_id in kb.load()["by_package"].items():
            if eco == "pypi" and _pypi(name) == pkg.name:
                return kb.get(lib_id)
        return None
    return kb.for_package(pkg.ecosystem, pkg.name)


def _better(a: Package, b: Package) -> Package:
    """The more precise of two sightings of one package in one directory."""
    if a.exact != b.exact:
        return a if a.exact else b
    if (a.scope == "direct") != (b.scope == "direct"):
        return a if a.scope == "direct" else b
    return a


def packages_in_text(path: Path, text: str) -> list[Package]:
    """Parse one manifest's text. Used directly by the container collector."""
    parser = parser_for(path)
    return parser(path, text) if parser else []


def findings_from_packages(packages: list[Package], context: dict | None = None,
                           location_prefix: str = "") -> tuple[list[RawCryptoFinding], int]:
    """Crypto-library findings from parsed packages; returns (findings, crypto_count)."""
    groups: dict[tuple, list[Package]] = {}
    for pkg in packages:
        lib = _lookup(pkg)
        if lib is None:
            continue
        project = pkg.path.parent.as_posix()
        groups.setdefault((project, pkg.ecosystem, pkg.name, lib.id), []).append(pkg)

    findings = []
    for (project, ecosystem, name, lib_id), sightings in sorted(groups.items()):
        best = sightings[0]
        for other in sightings[1:]:
            best = _better(best, other)
        lib = kb.get(lib_id)
        info = kb.details_for(lib, best.version, ecosystem if ecosystem != "runtime" else None)
        location = f"{location_prefix}{best.path.as_posix()}"
        refs = []
        for s in sightings:
            ref = evidence(COLLECTOR, f"{location_prefix}{s.path.as_posix()}", line=s.line)
            if ref not in refs:
                refs.append(ref)
        version_label = best.version or (f"{best.spec} (range)" if best.spec else "(version unknown)")
        details = {
            **info,
            **(context or {}),
            "discovered_by": COLLECTOR,
            "plane": "built",
            "provenance": "static_analysis",
            "confidence": CONFIDENCE_EXACT if best.exact else CONFIDENCE_RANGE,
            "ecosystem": ecosystem,
            "package": name,
            "version_spec": best.spec,
            "dependency_scope": best.scope,
            "runtime": best.runtime,
            "project": f"{location_prefix}{project}",
            "manifests": sorted({r["location"] for r in refs}),
            "evidence_refs": refs[:10],
            "display_name": (f"{lib.name} {version_label} (runtime)" if best.runtime
                             else f"{name} {version_label} ({ecosystem})"),
        }
        findings.append(RawCryptoFinding(
            id=stable_id(COLLECTOR, location_prefix, project, ecosystem, name),
            source_type="dependency",
            source_location=f"{location}:{best.line}" if best.line else location,
            asset_class="crypto_library",
            usage="library",
            tags=["dependency-scan", f"ecosystem:{ecosystem}"] + (["runtime"] if best.runtime else []),
            raw_details=details,
        ))
    return findings, len(groups)


class DependencyCollector:
    """Collector-contract implementation; see `collectors.base.Collector`."""

    name = "dependency"
    plane = "built"
    label = "Dependencies & runtimes"
    description = "Manifests and lockfiles in 9 ecosystems, matched to the crypto-library knowledge base."
    target_kinds = ("path", "repo")

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult:
        result = CollectResult(stats={"files_seen": 0, "manifests": 0, "packages_seen": 0,
                                      "crypto_packages": 0, "bytes_read": 0, "skipped": 0,
                                      "by_ecosystem": {}})
        timer = Timer(limits)
        packages: list[Package] = []
        for target in targets:
            # node_modules and virtualenvs are skipped by `walk`: the lockfile is
            # the precise statement of what they contain.
            for path in walk(Path(target), limits, result):
                if timer.expired:
                    result.fail(target, f"stopped after {limits.timeout_s:.0f}s (timeout)")
                    break
                result.stats["files_seen"] += 1
                if parser_for(path) is None:
                    continue
                raw = read_capped(path, limits.max_text_bytes * 8, result)
                if raw is None:
                    continue
                result.stats["manifests"] += 1
                try:
                    found = packages_in_text(path, raw.decode("utf-8", errors="replace"))
                except (ValueError, KeyError, TypeError, ET.ParseError, tomllib.TOMLDecodeError,
                        yaml.YAMLError) as exc:
                    result.fail(path, f"manifest parse failed: {type(exc).__name__}: {exc}")
                    continue
                packages.extend(found)
                for pkg in found:
                    eco = result.stats["by_ecosystem"]
                    eco[pkg.ecosystem] = eco.get(pkg.ecosystem, 0) + 1
        result.stats["packages_seen"] = len(packages)
        findings, crypto = findings_from_packages(packages)
        result.findings.extend(findings)
        result.stats["crypto_packages"] = crypto
        result.stats["duration_ms"] = timer.elapsed_ms
        return result


def scan_dependencies(paths: list[str]) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Function-style entry point, matching the other collectors."""
    result = DependencyCollector().collect(paths)
    return result.findings, result.failures
