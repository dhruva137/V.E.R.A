# SoftHSM2-shaped PKCS#11 dump

The committed file `hsm_pkcs11.json` **is** the demo. It uses SoftHSM2-compatible
PKCS#11 v2.40 attribute names (`CKA_*`, `CKM_*`, `CKO_*`, `CKK_*`) in the shape
of a read-only attribute listing: slot list, token info, find objects, get
attribute values.

You do **not** need to install SoftHSM2 (or any PKCS#11 module) on Windows to
run V.E.R.A.. Point the collector at this folder. A live token is a later swap of
the same JSON, not a second code path.

---

## What the file already matches

| JSON field | PKCS#11 / SoftHSM2 |
|---|---|
| `slots[].slot_id` | slot id |
| `token_label` | token label |
| `manufacturer`, `model`, `serial_number`, `firmware_version` | token info |
| `mechanisms[]` | mechanism list (`CKM_*`) |
| `pqc_mechanisms_present` / `pqc_ready` | Derived from that list (e.g. ML-DSA / ML-KEM mechanism names) |
| Per object `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_LABEL`, `CKA_ID` | object attributes |
| `CKA_SENSITIVE`, `CKA_EXTRACTABLE` | Never request the secret value |
| `CKA_MODULUS_BITS`, `CKA_PUBLIC_EXPONENT` | RSA public parameters only |
| `CKA_EC_PARAMS` / `CKA_EC_CURVE_NAME` | EC parameters, not the private scalar |
| `CKA_VALUE_LEN` | Symmetric length **in bytes** (×8 for bits) |
| Usage booleans | sign / verify / encrypt / decrypt / wrap / unwrap flags |

`CKA_EXTRACTABLE: false` on private/secret objects is structural: SoftHSM2 and
production HSMs refuse to export those objects. The collector also scrubs
secret-bearing fields if a dump ever includes them.

---

## Replacing the file later with a live dump

When you have SoftHSM2 (Linux, WSL, or a lab VM) and a read-only slot PIN, list
slots, mechanisms, and objects with the vendor's PKCS#11 tool in **list-only**
mode (OpenSC `pkcs11-tool` style: `--list-slots`, `--list-mechanisms`,
`--list-objects`). Do not use extract / read-object flags.

That listing is **text**, not this JSON. Map it, then overwrite `hsm_pkcs11.json`
(or drop the JSON next to a live collector out-dir):

| List-objects style line | Put in JSON |
|---|---|
| Private Key Object; RSA 2048 bits | `CKA_CLASS=CKO_PRIVATE_KEY`, `CKA_KEY_TYPE=CKK_RSA`, `CKA_MODULUS_BITS=2048` |
| Secret Key Object; AES length 32 | `CKO_SECRET_KEY`, `CKK_AES`, `CKA_VALUE_LEN=32` |
| Secret Key Object; generic secret / DES3 | `CKK_DES3` or `CKK_GENERIC_SECRET` + `CKA_VALUE_LEN` |
| `label:` | `CKA_LABEL` |
| `ID:` | `CKA_ID` (hex) |
| `Usage: sign, verify` | set the matching `CKA_*` booleans true |
| `Access: never extractable` | `CKA_EXTRACTABLE: false` |
| `Access: sensitive` | `CKA_SENSITIVE: true` |

Keep `mechanisms[]` from the mechanism listing. Set `pqc_ready` iff a PQC
`CKM_*` name appears. Extra demo fields (`application`, `pci_scope`, …) are
optional; the parser ignores unknown keys on the object.

**Preferred live path** (same JSON, no hand mapping): `demo/live/collect.py`
with a PKCS#11 Python binding, read-only session. That already writes
`hsm_pkcs11.json` in this shape. Then load with `vault_root=demo/live/out`.

---

## What never goes in the dump

- Secret value attributes, private exponents, primes, PEM bodies
- Extract / unwrap / derive operations that would export key material
- A read-write session or SO PIN

If key-shaped text appears, delete the file and re-dump. The collector will
scrub secrets, but a clean export is the operating rule.
