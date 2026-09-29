"""Dress rehearsal: check every beat of the 7-minute demo against the running API.

    python scripts/rehearse.py [--api http://127.0.0.1:8000] [--user NAME]

Runs each beat of the demo (docs/DEMO_SCRIPT.md) in order, against the server the judges will
see, and prints PASS or FAIL with the numbers to say on stage. It uses only the
standard library, so it runs on the demo laptop as-is. It changes the agent's
mode for one beat and puts it back, so it signs in as an admin: the password is
read from VERA_REHEARSE_PASSWORD, or asked for.

Exit code 0 means every beat will work; anything else names the beat that won't.
"""

from __future__ import annotations

import argparse
import getpass
import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request

RESULTS: list[tuple[str, bool, str]] = []
SCAN: dict = {}  # the discovery beat's job result, read by later beats
# Keeps the session cookie between calls.
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def call(api: str, path: str, body: dict | None = None, timeout: float = 300) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(f"{api}{path}", data=data, method="POST" if body is not None else "GET",
                                     headers={"Content-Type": "application/json"})
    with OPENER.open(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def sign_in(api: str, user: str) -> str | None:
    """None when signed in (or sign-in is off); otherwise what to fix."""
    status = call(api, "/api/auth/status")
    if not status["auth"]:
        return None
    if status["bootstrap_required"]:
        return "Sign-in is on and no admin exists yet: open the dashboard and create the first admin."
    password = os.environ.get("VERA_REHEARSE_PASSWORD") or getpass.getpass(f"Password for {user}: ")
    try:
        role = call(api, "/api/auth/login", {"username": user, "password": password})["user"]["role"]
    except urllib.error.HTTPError as exc:
        return f"Sign-in as {user!r} failed ({exc.code})."
    return None if role == "admin" else f"{user!r} is {role}; the agent beat changes a setting and needs an admin."


def beat(name: str):
    def wrap(fn):
        def run(api: str) -> None:
            started = time.perf_counter()
            try:
                ok, say = fn(api)
            except (urllib.error.URLError, KeyError, StopIteration, ValueError, AssertionError) as exc:
                ok, say = False, f"{type(exc).__name__}: {exc}"
            took = time.perf_counter() - started
            RESULTS.append((name, ok, say))
            print(f"  {'PASS' if ok else 'FAIL'}  {name}  ({took:.1f} s)\n        {say}", flush=True)
        return run
    return wrap


@beat("0:00 Status line: offline, local model, read-only")
def status(api):
    s = call(api, "/api/ntro-mode")
    return s["ntro_mode"], s["line"]


@beat("0:30 Scan: full scan of the demo estate, streamed per surface")
def discovery(api):
    job = call(api, "/api/scan/full", {"estate": "demo", "wait": True})
    log = call(api, f"/api/scan/jobs/{job['job_id']}")["event_log"]
    surfaces = sorted({e["collector"] for e in log if e["type"] == "collector_finished" and e["findings"]})
    failed = [e for e in log if e["type"] == "collector_failed"]
    r = job["result"]
    SCAN.update(r)
    return (job["status"] == "done" and not failed,
            f"{r['assets']} assets, {r['quantum_vulnerable']} quantum-vulnerable, from {len(surfaces)} surfaces: "
            f"{', '.join(surfaces)}")


@beat("1:00 Overview: verdict, DST milestones, CERT-In conformance, cost")
def overview(api):
    o = call(api, "/api/overview")
    foundation = o["milestones"][0]
    sourced = all(f["source"] for f in o["figures"])
    cost = o["cost"]
    return sourced and len(o["do_next"]) == 5, (
        f"{o['verdict']['sentence']} Next: {foundation['label']} by {foundation['year']} "
        f"({foundation['days_left']} days, CBOM {foundation['readiness_pct']}% of CERT-In elements); "
        f"{cost['changes']} changes, {cost['person_days']} person-days")


@beat("1:30 Inventory: one asset, several planes")
def inventory(api):
    cross = SCAN["cross_plane_assets"]
    return cross > 0, f"{cross} assets are backed by evidence from more than one plane"


@beat("2:15 Risk, policy drift: TLS 1.0 forbidden in config, negotiated on the wire")
def drift(api):
    records = call(api, "/api/drift")["records"]
    d1 = next(r for r in records if r["rule"] == "D1")
    return True, f"{d1['subject']}: declared '{d1['declared']['summary']}', observed '{d1['observed']['summary']}'"


@beat("3:00 Risk, quantum exposure: P-256 breaks earlier than RSA-3072, with a citation")
def risk(api):
    view = call(api, "/api/risk")
    rows = {p["id"]: p for p in view["primitives"]}
    p256, rsa3072 = rows["ecdlp-p256"], rows["rsa-3072"]
    earlier = p256["z_calendar"]["median"] < rsa3072["z_calendar"]["median"]
    return earlier, (f"median CRQC for P-256 {p256['z_calendar']['median']} vs RSA-3072 "
                     f"{rsa3072['z_calendar']['median']} ({p256['source']})")


@beat("4:00 Plan, actions: NIST vs CNSA, measured cost, OpenSSL upgrade")
def recommendations(api):
    commercial = call(api, "/api/recommendations?profile=commercial")
    cnsa = call(api, "/api/recommendations?profile=cnsa")
    kex = lambda doc: next(i for i in doc["items"] if i["need"] == "key_exchange")  # noqa: E731
    upgrade = next((i for i in commercial["items"] if i["need"] == "library_upgrade"
                    and "openssl" in str(i.get("recommended", "")).lower()), None)
    latency = kex(commercial).get("cost", {}).get("latency") or []
    measured = ", ".join(f"{l['algorithm']} {l['operation']} {l['microseconds']} us" for l in latency[:2])
    return (bool(upgrade) and kex(commercial)["recommended"] != kex(cnsa)["recommended"],
            f"key exchange: {kex(commercial)['recommended']} (commercial) vs {kex(cnsa)['recommended']} (CNSA); "
            f"measured {measured or 'not measured'}; upgrade: {upgrade['recommended'] if upgrade else 'none'}")


@beat("5:00 Plan, suppliers: vendor-gated HSM and its procurement clause")
def gated(api):
    register = call(api, "/api/vendor-gated")["register"]
    clauses = call(api, "/api/procurement-clauses")["clauses"]
    hsm = next(g for g in register if g["kind"] == "vendor_firmware_gated")
    return bool(clauses), f"{hsm['who']}: {hsm['count']} assets wait on firmware; {len(clauses)} clause drafts"


@beat("5:45 Evidence: CBOM valid, manifest signed with ML-DSA-65, audit chain intact")
def evidence(api):
    cbom = call(api, "/api/cbom/validate")
    manifest = call(api, "/api/manifest")
    check = call(api, "/api/manifest/verify", {"manifest": manifest})
    chain = call(api, "/api/audit/verify")
    ok = cbom["valid"] and check["valid"] and check["alg"] == "ML-DSA-65" and chain["valid"]
    return ok, (f"CBOM {cbom['spec_version']} {cbom['rules_passed']}/{cbom['rules_total']} rules; manifest "
                f"{check['alg']} {check['reason']}; audit chain {chain['entries']} entries, intact={chain['valid']}")


@beat("6:30 Agent: read-only refuses; with approval, 'migrate 200 assets' hits the blast-radius cap")
def agent(api):
    before = call(api, "/api/agent/status")["settings"]["mode"]
    ask = lambda: call(api, "/api/chat", {"messages": [{"role": "user", "content": "migrate 200 assets"}]})  # noqa: E731
    result = lambda turn: next(m for m in turn["messages"] if m["role"] == "tool")["content"]  # noqa: E731
    try:
        call(api, "/api/agent/settings", {"mode": "read_only"})
        read_only = result(ask())
        call(api, "/api/agent/settings", {"mode": "approval"})
        capped = result(ask())
    finally:
        call(api, "/api/agent/settings", {"mode": before})
    ok = "read-only" in read_only and "limit" in capped
    return ok, f"read-only: {json.loads(read_only)['error'][:70]} | approval: {json.loads(capped)['error'][:90]}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--user", default=os.environ.get("VERA_REHEARSE_USER", "admin"))
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # the status line has non-ASCII separators
    print("VERA demo rehearsal\n", flush=True)
    problem = sign_in(args.api, args.user)
    if problem:
        print(f"  FAIL  sign-in\n        {problem}")
        return 1
    for run in (status, discovery, overview, inventory, drift, risk, recommendations, gated, evidence, agent):
        run(args.api)
    failed = [name for name, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} beats ready" + (f"; fix: {', '.join(failed)}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
