# The demo key vault — what enterprise key metadata actually looks like

*Synthetic. No host, key, certificate or fingerprint here is real.*

This folder answers the question every CISO asks in the first five minutes:
**"where are these keys, and what exactly do you read off them?"**

Each file reproduces the *native response shape* of the system it stands in for,
so the demo path and the production path are the same code — only the transport
differs. `backend/collectors/vault_collector.py` reads these; pointing it at a
real export of the same shape needs no change.

Regenerate with:

```bash
python demo/vault/make_vault.py
```

---

## The rule that makes this deployable

**No key material. Anywhere. Ever.**

| What we read | What we never read |
|---|---|
| Algorithm, key size, curve | The private exponent, the secret value |
| Label, ID, usage flags | `CKA_VALUE`, `CKA_PRIVATE_EXPONENT`, primes |
| Validity window, lifecycle state | Any PEM body |
| SHA-256 of the **public** half | The key itself |
| The token's **mechanism list** | — |

This is not a limitation of the demo. It is how these systems work: an HSM
private object reports `CKA_EXTRACTABLE: false` and the HSM will refuse a read.
An inventory does not need the key — it needs the key's parameters.

`backend/tests/test_vault_collector.py` asserts this adversarially: it builds a
vault that *does* contain a PEM private key and requires the collector to drop
it. 36 tests cover this file.

---

## 1. HSM over PKCS#11 — `hsm_pkcs11.json`

The shape of `C_GetSlotList` → `C_GetTokenInfo` → `C_FindObjects` →
`C_GetAttributeValue`. Attribute names are the real `CKA_*` constants
(SoftHSM2-compatible). The file **is** the demo — no SoftHSM install on
Windows. How to swap in a live `pkcs11-tool --list-objects` dump later:
`SOFTHSM.md`.

**Per token (slot):**

- `slot_id`, `token_label` — e.g. `PAYMENT-HSM-01`
- `manufacturer`, `model` — Entrust nShield Connect XC, Thales Luna 7
- `firmware_version` — **the field that decides everything**
- `serial_number`
- `fips_mode` — FIPS 140-2/3 Level 3
- `mechanisms[]` — `CKM_RSA_PKCS`, `CKM_ECDSA`, `CKM_AES_GCM`, …
- `pqc_mechanisms_present[]` — `CKM_ML_DSA` / `CKM_ML_KEM` if the firmware has them
- `pqc_ready` — **derived by reading the mechanism list, not asked of the vendor**
- `pqc_readiness_note` — why, in words

**Per key object:**

- `CKA_CLASS` — `CKO_PRIVATE_KEY` / `CKO_PUBLIC_KEY` / `CKO_SECRET_KEY`
- `CKA_KEY_TYPE` — `CKK_RSA` / `CKK_EC` / `CKK_AES` / `CKK_DES3`
- `CKA_LABEL` — `atm-firmware-sign` (the only intent signal an HSM object carries)
- `CKA_ID` — hex handle
- `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_MODIFIABLE`, `CKA_DERIVE`
- `CKA_SENSITIVE: true`, **`CKA_EXTRACTABLE: false`**
- `CKA_MODULUS_BITS` + `CKA_PUBLIC_EXPONENT` (RSA)
- `CKA_EC_PARAMS` + `CKA_EC_CURVE_NAME` (EC) — OID `06082A8648CE3D030107` = secp256r1
- `CKA_VALUE_LEN` (symmetric, **in bytes** — ×8 for bits; 3DES 24 → 192)
- Usage flags: `CKA_SIGN` `CKA_VERIFY` `CKA_ENCRYPT` `CKA_DECRYPT` `CKA_WRAP` `CKA_UNWRAP`
- `CKA_START_DATE` / `CKA_END_DATE`
- `public_key_sha256` — fingerprint of the public half only
- Context: `application`, `pci_scope`, `verifier_fleet_size`, `field_rotatable`

> **Why the mechanism list is the most valuable field in the vault.** It answers
> *"can this HSM even do ML-DSA yet?"* without a vendor call. In this estate both
> tokens report no PQC mechanism, so all five HSM keys are marked
> `change_blocked` — including the estate's **rank-1 asset**. A ranking that
> ignores whether anything can be done about its top entry is not a plan.

---

## 2. Key manager over KMIP 2.1 — `kmip.json`

The shape of `Locate` → `GetAttributes`.

- `Unique Identifier` — `KMIP-0001`
- `Name`, `Object Group`
- `Object Type` — Symmetric Key / Private Key / Public Key / Certificate
- `Cryptographic Algorithm` — AES / RSA / ECDSA / DES3
- `Cryptographic Length` — in bits
- `Cryptographic Usage Mask` — Sign, Verify, Encrypt, Decrypt, WrapKey
- `State` — **PreActive / Active / Deactivated / Compromised / Destroyed**
- `Initial Date`, `Activation Date`, `Deactivation Date`
- `Protection Storage Mask`

> `State` is the field people miss. A **Deactivated** 3DES key is not in use —
> but it is still required to decrypt everything it ever wrapped. That is a
> different problem from an Active key, and it does not go away by ignoring it.

---

## 3. Cloud KMS — `cloud_kms.json`

Three providers, each in its own native shape. None returns key material for a
managed key.

**AWS KMS** (`DescribeKey`): `KeyId` · `Arn` · `Description` · `KeyUsage`
(ENCRYPT_DECRYPT / SIGN_VERIFY) · `KeySpec` (SYMMETRIC_DEFAULT, RSA_2048,
ECC_NIST_P256) · `KeyState` · `Origin` (AWS_KMS / EXTERNAL / AWS_CLOUDHSM) ·
`KeyManager` · `MultiRegion` · `CreationDate` · **`RotationEnabled`** ·
`EncryptionAlgorithms[]` / `SigningAlgorithms[]`

**Azure Key Vault**: `kid` · `kty` (RSA/EC) · `key_size` or `crv` · `key_ops[]` ·
`managed` · `attributes{enabled, created, updated, exp, nbf, recoveryLevel}` ·
`rotation_policy`

**GCP KMS** (`CryptoKeyVersion`): `name` · `state` · `algorithm`
(`EC_SIGN_P256_SHA256`, `GOOGLE_SYMMETRIC_ENCRYPTION`) ·
**`protectionLevel`** (SOFTWARE / HSM / EXTERNAL) · `createTime` · `attestation`

> `protectionLevel` and `Origin` matter: a SOFTWARE key and an HSM-backed key
> are not the same asset even when the algorithm is identical.

---

## 4. Keystores — `keystores.json`

The shape of `keytool -list -v`, for JKS and PKCS#12.

- `path`, `type` (JKS / PKCS12), `host`
- Per entry: `alias` · `entry_type` (**PrivateKeyEntry** / TrustedCertEntry /
  SecretKeyEntry) · `creation_date` · `key_algorithm` · `key_size` ·
  `signature_algorithm` · `certificate_chain_length` · `subject_dn` ·
  `issuer_dn` · `valid_from` · `valid_until` · `sha256_fingerprint` ·
  `private_key_exported: false`

---

## 5. Certificates — `certificates.json`

Chain metadata as an X.509 parser returns it.

- `subject` / `issuer` (full DN) — **these two resolve the hierarchy**
- `serial_number` · `not_before` / `not_after` · `days_remaining`
- `signature_algorithm` · `public_key_algorithm` · `public_key_size`
- `basic_constraints_ca` · `path_length`
- `subject_alt_names[]` · `key_usage[]` · `extended_key_usage[]`
- `sha256_fingerprint` · `self_signed`

> Issuer/subject pairs are what produce the dependency graph. Nothing is
> inferred: if a certificate names an issuer whose subject is another asset in
> the estate, that is an observed signing relationship.

---

## What the vault produces

26 raw metadata objects → **23 assets** after correlation.

Three merge because the same certificate is seen by two sensors (a keystore
entry *and* the parsed chain). That is one certificate observed twice, not two
certificates — double-counting would make every downstream total wrong.
Corroboration raises confidence to 0.90 but **never above the ceiling of the
strongest single method**: two weak sensors agreeing does not manufacture an
observation.

### Provenance grades carried into the engine

| Source | Provenance | Confidence | Proves | Cannot prove |
|---|---|---|---|---|
| HSM PKCS#11 | `declared` | 0.85 | The object, its parameters, PQC firmware readiness | That anything calls it |
| KMIP | `declared` | 0.85 | Attributes and lifecycle state | Use |
| Cloud KMS | `declared` | 0.85 | Key spec, usage, rotation, protection level | Which workload holds a grant |
| Keystore | `artifact_parsed` | 0.90 | Key and chain on disk | That the process loaded it |
| Certificate | `artifact_parsed` | 0.90 | Identity, validity, hierarchy | That it is served anywhere |

### Blind spots, stated rather than hidden

- Mainframe (ICSF) cryptography — no sensor reaches it
- Vendor-managed SaaS signing — visible only in a contract
- Anything an application derives at runtime and never persists

---

## Load it

```bash
# as its own estate
curl -X POST "http://localhost:8000/api/scan/vault?org_persona=Banking"

# folded into an estate already loaded
curl -X POST "http://localhost:8000/api/scan/vault?merge=true"

# what it holds, and what it cannot see
curl http://localhost:8000/api/vault/summary
```

Or ask the agent: *"scan the key vault"* → `scan_key_vault`.

### The ranking it produces (Banking persona)

| # | QIRS | Asset | Change blocked |
|---|---|---|---|
| 1 | 0.1910 | `atm-firmware-sign` (ATM-HSM-01) | **yes — no PQC firmware** |
| 2 | 0.1740 | `tejomaya-root-g3` (JKS) | no |
| 3 | 0.1652 | `card-verify-cvk` (PAYMENT-HSM-01) | **yes — no PQC firmware** |

The top asset in the estate is one nobody can act on today. Saying so is the
product.
