# V.E.R.A. showcase — CISO operator script

Ten minutes. No Azure, no AWS, no bank network. The estate is `demo/vault/` —
native PKCS#11 / KMIP / cloud-KMS / keystore / X.509 **shapes**, synthetic, no
key material.

Offline check (no server): `python demo/showcase/run_demo.py`

Live path below assumes the API on `http://localhost:8000`. From the repo root:

```bash
cd backend && python main.py
```

**Boot trap:** `VERA_AUTOLOAD_DEMO=1` loads the **~195-asset** synthetic estate, not
this vault. For the CISO script use either:

```bash
VERA_AUTOLOAD_VAULT=1 python main.py
```

or start plain and run the vault curl in §1. Expect **23** assets after vault ingest.

---

## 0 · Open (90 seconds)

Two-axis rank. Metadata only. Rank-1 cannot be acted on today.

Do not say: live Razorpay connector, SSO, SOC 2, Synechron endorsement, customers.

---

## 1 · Load the vault

```bash
curl -s -X POST "http://localhost:8000/api/scan/vault?org_persona=Banking"
curl -s http://localhost:8000/api/vault/summary
curl -s http://localhost:8000/api/dashboard
```

```python
python -c "import json,urllib.request as u; print(json.load(u.urlopen(u.Request('http://localhost:8000/api/scan/vault?org_persona=Banking', method='POST'))))"
```

Expect **23 assets** from 26 raw objects (three certificates seen twice).
`key_material_present: false`. Blind spots named: ICSF, vendor SaaS signing,
runtime-derived keys.

---

## 2 · HNDL ≠ TNFL

```bash
curl -s "http://localhost:8000/api/axis-extremes?count=5"
```

Top confidentiality (HNDL) is a **TLS leaf** (E=1.0, harvestable). Top integrity
(TNFL) is **Tejomaya Root CA G3**. `overlap_count` on the heads is not the
same population.

Say: a family-colouring tool shows you one of these lists and mislabels the other.

This vault has no live handshake. Public TLS (X25519 outranking the cert) is
`demo/live/` — optional, needs network. The two-axis split already holds offline.

---

## 3 · Rank-1 is change-blocked (firmware)

```bash
curl -s "http://localhost:8000/api/assets?limit=5"
curl -s http://localhost:8000/api/dashboard
```

Two numbers, both true:

| Sort | What you get | Change blocked |
|---|---|---|
| QIRS (dashboard `top_risk_asset_id`) | `atm-firmware-sign` on ATM-HSM-01, QIRS ~0.191 | **yes — firmware 7.8.4, no CKM_ML_DSA / CKM_ML_KEM** |
| Migration backlog (`priority_rank`) | often `card-verify-cvk` on PAYMENT-HSM-01 (CII slack) | **yes — same firmware fact** |

The product: ranking it first is correct; **acting** on it first is not. It
needs a vendor firmware plan. Start the next actionable asset meanwhile.

Point at `raw_details.change_blocked` and `hsm_pqc_note`.

---

## 4 · Adapter coverage / blind spots

```bash
curl -s http://localhost:8000/api/adapters
curl -s http://localhost:8000/api/discovery/plugins
curl -s http://localhost:8000/api/vault/summary
```

Five adapters: `pkcs11` `kmip` `cloud_kms` `tls` `keystore`. Each card has
`coverage_contract.cannot_prove`. PKCS#11 / KMIP / cloud KMS / keystore are
**measurable via file dump** on this vault. TLS is **not measured** here (no
`tls.json`) — that is honest, not a missing feature.

Live PKCS#11 session, live Azure tenant, ICSF, SWIFT: still **blind spots**.
A dump on disk is not a connected HSM.

---

## 5 · Pack unplug (payments)

```bash
curl -s http://localhost:8000/api/packs/resolved/payments
curl -s -X POST http://localhost:8000/api/packs/pack.payments/toggle -H "Content-Type: application/json" -d "{\"enabled\":false}"
curl -s http://localhost:8000/api/packs/resolved/payments
curl -s http://localhost:8000/api/dashboard
curl -s -X POST http://localhost:8000/api/packs/pack.payments/toggle -H "Content-Type: application/json" -d "{\"enabled\":true}"
```

After unplug: `packs_applied` is `[pack.baseline]`, PCI language gone, controls
remain (universal ones). Dashboard **QIRS / H / T / asset count do not move**.
Packs are what is *said*; the engine does not branch on sector.

---

## 6 · Agent — one question that must call `inspect_key`

Needs a model in Settings. The question:

> Inspect the ATM firmware signing key. Which HSM token holds it, and does
> that firmware advertise ML-KEM or ML-DSA? Can we migrate it in place?

```bash
curl -s -X POST http://localhost:8000/api/chat -H "Content-Type: application/json" -d "{\"messages\":[{\"role\":\"user\",\"content\":\"Inspect the ATM firmware signing key. Which HSM token holds it, and does that firmware advertise ML-KEM or ML-DSA? Can we migrate it in place?\"}]}"
```

Watch the tool-call card for `inspect_key`. Guidance must say it cannot be
migrated in place.

No model — same facts, no LLM:

```bash
curl -s "http://localhost:8000/api/assets?search=firmware"
```

```python
python -c "import json,urllib.request as u; a=json.load(u.urlopen('http://localhost:8000/api/assets?search=firmware'))[0]; d=a['raw_details']; print(a['name'], d.get('hsm_token'), d.get('hsm_firmware'), d.get('change_blocked'), d.get('hsm_pqc_note','')[:120])"
```

---

## If the room has no Wi-Fi

```bash
python demo/showcase/make_all.py
python demo/showcase/run_demo.py
```

Prints adapter contracts, top HNDL, top TNFL, blocked count. Exits non-zero
if key material appears or correlation is insane. CI: `backend/tests/test_showcase_demo.py`.

Regenerate vault only: `python demo/vault/make_vault.py`

---

## Do not claim

Live Azure / AWS credentials. Production PKCS#11. ICSF. SWIFT. A Razorpay
connector. That file-dump PKCS#11 is a connected nShield.
