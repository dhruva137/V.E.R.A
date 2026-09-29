# Architecture

How one scan becomes an inventory, a risk ranking, recommendations and signed evidence. Each stage names the code
that does it, so every number on screen can be traced back through these files.

```
estate register ──► collectors ──► identity resolution ──► drift ──► scoring ──► recommendations ──► outputs
(estate.yaml)      11 surfaces     one asset per key/cert   D1–D8     Mosca per   target, cost,        CBOM · SARIF
                   4 planes                                            primitive  owner, clauses       manifest · audit
                                          ▲                                                    │
                                          └────────── governed agent (30 tools, router first) ◄┘
```

## 1. Collect: `backend/collectors/`
Every collector implements one contract (`collectors/base.py`): `collect(targets, limits) -> CollectResult`
with findings, failures, stats and declarations. `collectors/registry.py` lists the 11 collectors and their plane:

| Plane | Collectors |
|---|---|
| declared | configuration (nginx, Apache, HAProxy, OpenSSH, OpenSSL, strongSwan, Terraform) |
| built | source (7 languages, tree-sitter), dependencies (9 ecosystems), binaries (ELF/PE/Mach-O/JAR), container images, secrets |
| held | keystores and certificates, vault / HSM / KMIP / cloud-KMS metadata |
| observed | TLS and SSH (live probe or recorded capture) |

Metadata only. Private-key bodies are never read; see `engine/intake/scrub.py`. A failure (unreadable file,
malformed image, refused connection) is returned with its reason, never dropped.

`engine/scan_job.py` runs the collectors a target needs as one job and streams each step as server-sent events
(`/api/scan/jobs/{id}/events`). The estate register (`engine/estate.py`) binds targets to systems with exposure,
criticality and data classes.

## 2. Resolve and reconcile: `engine/core/resolution.py`, `engine/drift.py`
- **Identity resolution** merges findings that are the same object: by fingerprint, then serial and issuer, then
  public key, endpoint, key id, and library-in-scope, falling back to location. It is conservative: possible
  duplicates are linked, not merged.
- **Corroboration** (`engine/core/corroboration.py`) takes the maximum within a plane and combines planes by noisy-OR.
- **Drift**: rules D1–D8 (`engine/rules/drift.yaml`) compare declared with built, held and observed, for example
  "TLS 1.0 forbidden in config but negotiated on the wire". Each record carries both pieces of evidence.

## 3. Score: `engine/mosca.py`, `engine/quantum_resources.py`, `engine/qirs.py`
- **Z (CRQC arrival).** A survival ensemble fitted to the GRI Quantum Threat Timeline (7th ed.), measured from the
  report date. Each primitive is then shifted by δ = D·log2(L_p / L_RSA-2048), using published logical-qubit estimates.
  Rows without a verified estimate use δ = 0 and say so.
- **X (shelf life)** comes from the declared data classes (`engine/kb/data_classes.yaml`). **Y (migration time)**
  includes vendor lead time when an HSM or provider must ship PQC first.
- **Mosca category** (exposed / likely / possibly / clear) from the margin under each reading. Assets are ranked by
  category, then margin, then QIRS.
- The threat model is versioned (`engine/kb/threat_model_versions.json`). The resources table is hash-pinned, so a
  score cannot move without a version change. The Risk screen's doubling-time slider is a what-if and is never stored.

## 4. Recommend: `engine/recommendations.py`, `engine/kb/recommendations.yaml`
Each asset gets a need (key exchange, long-lived signature, library upgrade, …). Its target comes from the
commercial (NIST) or CNSA 2.0 profile. Cost is FIPS sizes plus latency **measured on this host**
(`bench/pqc_bench.json`); without a measurement, the latency is shown as "not measured". Ownership (the owning
team, the HSM vendor, the cloud provider, a third party) produces the vendor-gated register and procurement
clause drafts for legal review.

## 5. Prove: `engine/cbom.py`, `engine/sarif.py`, `engine/manifest.py`, `engine/audit_chain.py`
- CycloneDX 1.7 (and 1.6), validated offline against the vendored official schemas (`engine/schemas/`), plus
  referential checks. The output is byte-identical for the same scan.
- SARIF 2.1.0 for CI gates.
- The manifest binds each collector's output hash, the CBOM and SARIF hashes, the threat-model version and the
  policy. It is signed with ML-DSA-65 via OpenSSL 3.5; Ed25519 is used only as a labelled fallback. Verify it offline
  with `python -m engine.manifest verify`.
- The audit chain is SHA-256 hash-chained, with append-only triggers. It records scans, exports, setting changes and
  every agent action.

## 6. Govern: `engine/agent.py`, `engine/agent_router.py`, `engine/agent_control.py`
- **30 tools**, all reading the engine's own objects, so the agent cannot disagree with the dashboard.
- A deterministic router picks the tool when the verb names it. It asks the user to pick when an asset reference
  is ambiguous, and still goes through the control plane.
- The control plane enforces read-only / approval / autonomous modes, a rate limit, a blast-radius cap and an
  iteration budget. Every call is audited.
- **NTRO mode** (`engine/ntro_mode.py`, `engine/offline.py`): read-only, a local model, and an offline socket guard.
