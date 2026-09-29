# Live collection — point V.E.R.A. at real infrastructure

`demo/vault/` is a synthetic estate that proves the *shapes*. This directory
collects the same shapes from **real** systems, so the demo path and the
production path are the same code and only the transport differs.

```bash
cp demo/live/targets.example.yaml demo/live/targets.yaml
$EDITOR demo/live/targets.yaml
python demo/live/collect.py
```

Then load what it collected:

```bash
curl -X POST "http://localhost:8000/api/scan/vault?vault_root=demo/live/out"
```

`targets.yaml` and `out/` are gitignored. Never commit real hostnames,
credentials or collected estates.

---

## The three guarantees

**1. Metadata only.** It reads algorithms, key sizes, curves, validity windows,
usage flags and mechanism lists. It never reads key material. For an HSM or a
cloud KMS it could not even if it tried — those systems do not export managed
keys, which is the entire point of owning one. Before writing anything, the
collector re-scans its own output for key-shaped content and **refuses to write
if it finds any**.

**2. Read-only.** Every call is a list, describe, get-attribute or handshake.
Nothing is created, rotated or deleted. The PKCS#11 session is opened `rw=False`
and expects a read-only slot credential.

**3. It never invents a source.** A driver that is not installed, a credential
that is not set, a host that did not answer — each is reported as an
**unmeasured gap with the exact command that fixes it**, never silently skipped
and never faked:

```
UNMEASURED — these are gaps in coverage, not absences of risk:
   pkcs11 (HSM)               no PKCS#11 driver installed.
                                -> pip install python-pkcs11
   cloud_kms:aws              boto3 is not installed.
                                -> pip install boto3
```

An inventory that quietly omits the HSM is more dangerous than one that says the
HSM was never asked.

---

## What works with no extra install

| Source | Needs | What it proves |
|---|---|---|
| **TLS endpoints** | nothing | The cryptography is **live**. A real handshake reads the negotiated protocol, cipher suite, key-exchange group and chain. The only sensor that proves use rather than presence. |
| **Certificates on disk** | nothing | Identity, validity and the issuing hierarchy. Issuer/subject pairs are what build the dependency graph. |
| **PKCS#12 keystores** | nothing | The key and chain are on disk with these parameters. Parsing stops at the certificate. |

`cryptography` is already an V.E.R.A. dependency, so these three run today.

## What needs a driver

| Source | Install | Why it is worth it |
|---|---|---|
| **HSM (PKCS#11)** | `pip install python-pkcs11` | Reads the token's **mechanism list** — how you establish PQC firmware readiness without asking the vendor. If no `CKM_ML_DSA`/`CKM_ML_KEM` is advertised, every key on that token is change-blocked no matter how it ranks. |
| **KMIP key manager** | `pip install PyKMIP` | Managed-object attributes and lifecycle state. A *Deactivated* key is still needed to decrypt whatever it wrapped. |
| **AWS KMS** | `pip install boto3` | Key spec, usage, origin, rotation. Needs `kms:ListKeys` + `kms:DescribeKey`. |
| **Azure Key Vault** | `pip install azure-keyvault-keys azure-identity` | Key type, size, ops, expiry. Needs Key *List* and *Get*. |
| **GCP KMS** | `pip install google-cloud-kms` | Algorithm and **protection level** (SOFTWARE vs HSM). Needs `cryptoKeyVersions.list`. |
| **JKS keystores** | `pip install pyjks` | Or convert: `keytool -importkeystore -srckeystore x.jks -destkeystore x.p12 -deststoretype PKCS12` |

Credentials come from each provider's own default chain (environment, profile,
managed identity). Passwords and PINs are read from **environment variables**
named in `targets.yaml` — never from the file itself.

---

## Verified run

Against three public endpoints, with no optional driver installed:

```
Measured:
   tls (live handshake)           9 object(s)

UNMEASURED — these are gaps in coverage, not absences of risk:
   pkcs11 (HSM)               no PKCS#11 driver installed.  -> pip install python-pkcs11
   kmip                       no KMIP driver installed.     -> pip install PyKMIP
   cloud_kms:aws              boto3 is not installed.       -> pip install boto3
```

Ingested and scored:

| QIRS | HNDL | Class | Asset |
|---|---|---|---|
| 0.1657 | 0.331 | `tls_key_exchange` | cloudflare.com:443 — X25519 |
| 0.1657 | 0.331 | `tls_key_exchange` | github.com:443 — X25519 |
| 0.1308 | 0.253 | `tls_certificate` | cloudflare.com |
| 0.0000 | 0.000 | `tls_cipher_suite` | TLS_AES_256_GCM_SHA384 |

The **key exchange outranks the certificate** on every endpoint. That is the
two-axis model on real data: X25519 is the harvest-now-decrypt-later surface,
while AES-256-GCM is symmetric and scores zero. A tool that coloured by
algorithm family would rank these three identically.

---

## Only scan what you are authorised to scan

A TLS probe is the same traffic a browser generates, but scanning hosts you do
not operate may still be unauthorised. The HSM, KMIP and cloud paths require
credentials you must be entitled to hold. Get permission in writing before
pointing this at anything you do not own.
