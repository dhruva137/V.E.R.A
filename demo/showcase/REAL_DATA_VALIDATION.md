# Real-data ranking validation

Validates that V.E.R.A.’s two-axis QIRS ranking holds on **public TLS handshakes**,
not only on `demo/vault/` synthetics.

| Field | Value |
|---|---|
| Collected | 2026-08-30T17:55:29Z (`demo/live/out/manifest.json`) |
| Method | `python demo/live/collect.py` → `scan_vault(demo/live/out)` → `score_assets` |
| Endpoints | `cloudflare.com:443`, `www.google.com:443`, `github.com:443` |
| Objects | 9 (3 endpoints × cert + cipher suite + key exchange) |
| Synthetic | **false** (`key_material_present: false`) |

---

## Verdict

**Ranking holds on real data.** On every endpoint, X25519 `tls_key_exchange`
outranks the leaf `tls_certificate`, which outranks the AES-GCM
`tls_cipher_suite`. No classically broken crypto. No `change_blocked` (that
flag is an HSM/firmware fact; public TLS leaves are actionable).

A family-colouring scanner that paints “all ECC red the same” (or “all RSA
red the same”) cannot express this split: here KX and cert share a Shor-breakable
elliptic-curve story, yet QIRS separates harvest-now (KX, HNDL) from short-lived
identity (cert).

---

## Ranked scores (priority_rank)

| Rank | QIRS | HNDL | TNFL | Class | Detail | Host |
|---|---:|---:|---:|---|---|---|
| 1 | **0.1657** | 0.331 | 0.0003 | `tls_key_exchange` | X25519 | github.com:443 |
| 2 | **0.1657** | 0.331 | 0.0003 | `tls_key_exchange` | X25519 | www.google.com:443 |
| 3 | **0.1657** | 0.331 | 0.0003 | `tls_key_exchange` | X25519 | cloudflare.com:443 |
| 4 | 0.1308 | 0.253 | 0.0085 | `tls_certificate` | ECDSA P-256 | cloudflare.com:443 |
| 5 | 0.1308 | 0.253 | 0.0085 | `tls_certificate` | ECDSA P-256 | github.com:443 |
| 6 | 0.1308 | 0.253 | 0.0085 | `tls_certificate` | ECDSA P-256 | www.google.com:443 |
| 7 | 0.0000 | 0.000 | 0.0000 | `tls_cipher_suite` | TLS_AES_128_GCM_SHA256 | github.com:443 |
| 8 | 0.0000 | 0.000 | 0.0000 | `tls_cipher_suite` | TLS_AES_256_GCM_SHA384 | www.google.com:443 |
| 9 | 0.0000 | 0.000 | 0.0000 | `tls_cipher_suite` | TLS_AES_256_GCM_SHA384 | cloudflare.com:443 |

Per-endpoint invariant (all three hosts):

| Host | KX QIRS | Cert QIRS | Suite QIRS | KX > Cert |
|---|---:|---:|---:|---|
| github.com:443 | 0.1657 | 0.1308 | 0.0 | **yes** |
| www.google.com:443 | 0.1657 | 0.1308 | 0.0 | **yes** |
| cloudflare.com:443 | 0.1657 | 0.1308 | 0.0 | **yes** |

Delta KX − cert = **0.0349** on every host (policy profiles: KX `x_c=10`,
cert `x_c=7`).

---

## Structural checks

| Check | Result |
|---|---|
| Key exchange present | yes — 3 × X25519 |
| Scores deterministic | yes — two `score_assets` passes identical `(id, qirs)` |
| PEM / key material in findings | **none** |
| `classically_broken` | **0 / 9** (modern TLS 1.3; no 3DES/RC4/MD5) |
| `change_blocked` | **0 / 9** (no HSM mechanism list in this estate) |
| Cipher-suite QIRS | **0.0** (AES-GCM; Grover residual only on AES-128 at github) |
| Unmeasured gaps named | pkcs11, kmip, cloud_kms:aws (drivers not installed) |

Policy inputs observed on live assets:

| Class | x_c | x_i | y | s | e | c | verdict |
|---|---:|---:|---:|---:|---:|---:|---|
| `tls_key_exchange` | 10.0 | 0.02 | 0.25 | 0.85 | 1.0 | 0.15 | shor |
| `tls_certificate` | 7.0 | 1.5 | 0.25 | 0.7 | 1.0 | 0.35 | shor |
| `tls_cipher_suite` | 7.0 | 0.02 | 0.15 | 0.6 | 1.0 | 0.1 | pqc / grover |

---

## vs family-colouring

Family-colouring (paint by algorithm family) would treat every Shor-breakable
ECC surface the same: X25519 KX and ECDSA leaf would both be “red ECC.” V.E.R.A.
does not:

1. **Axis split** — KX dominates **HNDL** (harvest-now); cert carries a little
   **TNFL** (identity / re-issue). Same family, different jobs.
2. **Symmetric bulk** — AES-GCM scores **0**, not “another crypto finding.”
3. **RSA-red analogy** — On the synthetic vault, many RSA objects share a
   family colour yet diverge on QIRS (firmware signing vs leaf cert vs CVK).
   Live public TLS here is ECDSA/X25519, but the failure mode is identical:
   colour collapses what rank separates.

---

## Reproduce

```bash
# targets already at demo/live/targets.yaml (public hosts only)
python demo/live/collect.py

cd backend
python -c "from pathlib import Path; from collectors.vault_collector import scan_vault; from engine.qirs import score_assets; from engine.threat_model import ThreatModel; from models.schemas import CryptoAsset; f,_=scan_vault(Path('../demo/live/out')); a=score_assets([CryptoAsset(**x.model_dump(), name=x.id) for x in f], ThreatModel()); print([(round(x.qirs,4), x.asset_class, x.key_exchange or x.algorithm or x.cipher_suite, x.source_location) for x in sorted(a, key=lambda z: -z.qirs)])"
```

Or via API: `POST /api/scan/vault?vault_root=demo/live/out`

Automated gate: `backend/tests/test_live_ranking_validation.py` (skips if
`demo/live/out/tls.json` is absent).
