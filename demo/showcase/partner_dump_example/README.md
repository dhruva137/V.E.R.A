# Partner dump example (redacted attributes only)

Drop a **metadata-only** export here. V.E.R.A. scores the dump **offline** — no live
HSM, no key unwrap, no network to your estate.

## What to copy in

| Source | Put here as |
|---|---|
| SoftHSM / `pkcs11-tool --list-objects` (+ mechanisms) mapped to SoftHSM-shaped JSON | `hsm_pkcs11.json` |
| KMIP `GetAttributes` / Locate export (never `Get`) | `kmip.json` |

Start from `sample_pkcs11_snippet.json` (2 objects). Rename or copy to the
collector filename:

```bash
cp demo/showcase/partner_dump_example/sample_pkcs11_snippet.json \
   demo/showcase/partner_dump_example/hsm_pkcs11.json
```

Then:

```bash
curl -X POST "http://localhost:8000/api/scan/vault?vault_root=demo/showcase/partner_dump_example"
```

## Never include

- Private exponents, `CKA_VALUE`, PEM private keys, wrap/extract outputs
- SO / read-write PINs, production secrets, unredacted serials you cannot share

Attributes + mechanism list are enough. If a field looks like key material, delete
it before handoff. See `demo/vault/SOFTHSM.md` for the SoftHSM2 mapping.
