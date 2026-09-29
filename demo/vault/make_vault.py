"""Generate the VERA demo key vault.

WHAT THIS IS
------------
A deterministic, synthetic reproduction of the *metadata surfaces* an enterprise
actually exposes when you ask it "what cryptography do you hold, and where?".

It is not a pile of CSV rows. Each file here is shaped exactly like the real API
or library response it stands in for, because the point of the demo is that the
ingestion path is real: the same normaliser that reads this reads a live HSM.

    hsm_pkcs11.json     PKCS#11 C_FindObjects + C_GetAttributeValue, per slot
    kmip.json           KMIP 2.1 Locate + GetAttributes managed objects
    cloud_kms.json      AWS KMS DescribeKey / Azure Key Vault / GCP KMS versions
    keystores.json      JKS + PKCS#12 entry listings (keytool -list -v shape)
    certificates.json   X.509 chain metadata as a parser returns it
    manifest.json       what each source is, and what it can and cannot prove

THE RULE THIS FILE EXISTS TO DEMONSTRATE
----------------------------------------
**No key material. Anywhere. Ever.**

Every private/secret object carries `CKA_EXTRACTABLE: false` and
`CKA_SENSITIVE: true`, and the only key-derived value recorded is a SHA-256
fingerprint of the *public* half. That is not a limitation of the demo — it is
how HSMs work, and it is the reason a bank can run this. An inventory does not
need the key; it needs the key's parameters.

Run:  python demo/vault/make_vault.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timedelta
from pathlib import Path

OUT = Path(__file__).parent
TODAY = date(2026, 8, 29)          # pinned so the demo is stable between runs
EPOCH = datetime(2026, 8, 29, 9, 0, 0)


def _fp(*parts: str) -> str:
    """SHA-256 fingerprint, colon-grouped, of the PUBLIC half only."""
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, 32, 2))


def _iso(days_from_today: int) -> str:
    return (TODAY + timedelta(days=days_from_today)).isoformat()


def _stamp(days: int) -> str:
    return (EPOCH + timedelta(days=days)).isoformat() + "Z"


# ---------------------------------------------------------------------------
# 1. HSM — PKCS#11
#
# Shape: what a PKCS#11 module returns for C_GetSlotList -> C_GetTokenInfo ->
# C_FindObjects -> C_GetAttributeValue. Attribute names are the real CKA_*
# constants; a Luna/nShield/CloudHSM enumeration looks like this.
#
# The mechanism list is the single most valuable field in the whole vault: it is
# how you answer "can this HSM even do ML-DSA yet?" without asking the vendor.
# ---------------------------------------------------------------------------

def hsm_pkcs11() -> dict:
    def key(label, cka_id, key_type, cls, usage, bits=None, curve=None,
            created=-900, expires=None, extra=None):
        obj = {
            "CKA_CLASS": cls,
            "CKA_KEY_TYPE": key_type,
            "CKA_LABEL": label,
            "CKA_ID": cka_id,
            "CKA_TOKEN": True,
            "CKA_PRIVATE": cls == "CKO_PRIVATE_KEY",
            # The two attributes that make this safe to inventory.
            "CKA_SENSITIVE": cls != "CKO_PUBLIC_KEY",
            "CKA_EXTRACTABLE": False,
            "CKA_MODIFIABLE": False,
            "CKA_DERIVE": False,
            "CKA_START_DATE": _iso(created),
            "CKA_END_DATE": _iso(expires) if expires is not None else "",
        }
        obj.update(usage)
        if bits is not None:
            obj["CKA_MODULUS_BITS"] = bits
            obj["CKA_PUBLIC_EXPONENT"] = "010001"
        if curve is not None:
            obj["CKA_EC_PARAMS"] = curve["params"]
            obj["CKA_EC_CURVE_NAME"] = curve["name"]
        obj["public_key_sha256"] = _fp(label, cka_id, key_type)
        if extra:
            obj.update(extra)
        return obj

    sign = {"CKA_SIGN": True, "CKA_VERIFY": True,
            "CKA_ENCRYPT": False, "CKA_DECRYPT": False,
            "CKA_WRAP": False, "CKA_UNWRAP": False}
    wrap = {"CKA_SIGN": False, "CKA_VERIFY": False,
            "CKA_ENCRYPT": True, "CKA_DECRYPT": True,
            "CKA_WRAP": True, "CKA_UNWRAP": True}

    P256 = {"params": "06082A8648CE3D030107", "name": "secp256r1"}

    return {
        "source": "pkcs11",
        "collected_at": _stamp(0),
        "module": "/opt/nfast/toolkits/pkcs11/libcknfast.so",
        "attribute_profile": (
            "PKCS#11 v2.40 / SoftHSM2-compatible CKA_* JSON (see SOFTHSM.md)"
        ),
        "note": (
            "Enumerated read-only through a login-limited slot credential. Key "
            "material was never requested and could not have been returned: "
            "every private object reports CKA_EXTRACTABLE=false. Attribute names "
            "and booleans match SoftHSM2 C_GetAttributeValue; replace this file "
            "later with a pkcs11-tool --list-objects mapping or demo/live/"
            "collect.py output — installing SoftHSM on Windows is not required "
            "for the demo."
        ),
        "slots": [
            {
                "slot_id": 0,
                "token_label": "PAYMENT-HSM-01",
                "manufacturer": "Entrust nShield",
                "model": "nShield Connect XC",
                "firmware_version": "12.72.1",
                "serial_number": "4A1C-9F02-8831",
                "fips_mode": "FIPS 140-3 Level 3",
                # PQC readiness, read rather than assumed.
                "mechanisms": [
                    "CKM_RSA_PKCS", "CKM_RSA_PKCS_PSS", "CKM_SHA256_RSA_PKCS",
                    "CKM_ECDSA", "CKM_ECDSA_SHA256", "CKM_AES_GCM",
                    "CKM_AES_CBC", "CKM_DES3_CBC", "CKM_SHA256_HMAC",
                ],
                "pqc_mechanisms_present": [],
                "pqc_ready": False,
                "pqc_readiness_note": (
                    "No CKM_ML_DSA / CKM_ML_KEM mechanism is advertised by this "
                    "firmware. Keys on this token cannot be migrated in place; "
                    "migration requires a vendor firmware release, so every "
                    "asset here is change-blocked regardless of its rank."
                ),
                "objects": [
                    key("card-verify-cvk", "0A11", "CKK_RSA", "CKO_PRIVATE_KEY",
                        sign, bits=2048, created=-1310, expires=420,
                        extra={"application": "PIN verification",
                               "pci_scope": True}),
                    key("pin-translate-legacy", "0A12", "CKK_DES3",
                        "CKO_SECRET_KEY", wrap, created=-2600, expires=120,
                        extra={"CKA_VALUE_LEN": 24,
                               "application": "PIN block translation",
                               "pci_scope": True,
                               "note": "Two-key 3DES. Classically broken."}),
                    key("issuer-master-key", "0A13", "CKK_AES",
                        "CKO_SECRET_KEY", wrap, created=-800, expires=900,
                        extra={"CKA_VALUE_LEN": 32,
                               "application": "EMV issuer master key"}),
                    key("emv-arqc-mac", "0A14", "CKK_AES", "CKO_SECRET_KEY",
                        wrap, created=-780, expires=760,
                        extra={"CKA_VALUE_LEN": 16,
                               "application": "EMV ARQC/ARPC MAC",
                               "pci_scope": True}),
                    key("pin-zone-master-zmk", "0A15", "CKK_AES",
                        "CKO_SECRET_KEY", wrap, created=-1100, expires=300,
                        extra={"CKA_VALUE_LEN": 32,
                               "application": "Zone master key (ZMK)",
                               "pci_scope": True}),
                    key("card-verify-cvk-2019", "0A16", "CKK_RSA",
                        "CKO_PRIVATE_KEY", sign, bits=2048, created=-2400,
                        expires=60,
                        extra={"application": "PIN verification (legacy, pending retirement)",
                               "pci_scope": True}),
                ],
            },
            {
                "slot_id": 1,
                "token_label": "ATM-HSM-01",
                "manufacturer": "Thales",
                "model": "Luna Network HSM 7",
                "firmware_version": "7.8.4",
                "serial_number": "77B3-2E10-0459",
                "fips_mode": "FIPS 140-2 Level 3",
                "mechanisms": [
                    "CKM_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_ECDSA",
                    "CKM_ECDSA_SHA256", "CKM_AES_GCM", "CKM_AES_KWP",
                ],
                "pqc_mechanisms_present": [],
                "pqc_ready": False,
                "pqc_readiness_note": (
                    "Firmware 7.8.4 predates Luna's PQC firmware track. The "
                    "firmware-signing key below signs a fleet that verifies in "
                    "hardware, so it cannot be rotated without a field visit."
                ),
                "objects": [
                    key("atm-firmware-sign", "0B21", "CKK_RSA",
                        "CKO_PRIVATE_KEY", sign, bits=3072, created=-1900,
                        expires=3200,
                        extra={"application": "ATM firmware signing",
                               "verifier_fleet_size": 4200,
                               "field_rotatable": False,
                               "note": "Trust anchor for 4,200 terminals."}),
                    key("atm-device-ca", "0B22", "CKK_EC", "CKO_PRIVATE_KEY",
                        sign, curve=P256, created=-1500, expires=1800,
                        extra={"application": "ATM device identity issuance"}),
                    key("atm-message-mac", "0B23", "CKK_AES", "CKO_SECRET_KEY",
                        wrap, created=-1400, expires=540,
                        extra={"CKA_VALUE_LEN": 16,
                               "application": "ATM message MAC"}),
                    key("atm-pin-verify", "0B24", "CKK_RSA", "CKO_PRIVATE_KEY",
                        sign, bits=2048, created=-1600, expires=200,
                        extra={"application": "ATM PIN verification",
                               "pci_scope": True}),
                ],
            },
            {
                # A newer token on the PQC firmware track. Its keys are the
                # ones the engine can actually action today - the contrast with
                # the blocked tokens above is the whole point of showing both.
                "slot_id": 2,
                "token_label": "GENERAL-HSM-02",
                "manufacturer": "Thales",
                "model": "Luna Network HSM 7",
                "firmware_version": "7.13.0",
                "serial_number": "91D4-7A22-1180",
                "fips_mode": "FIPS 140-3 Level 3",
                "mechanisms": [
                    "CKM_RSA_PKCS", "CKM_RSA_PKCS_PSS", "CKM_SHA256_RSA_PKCS",
                    "CKM_ECDSA", "CKM_ECDSA_SHA256", "CKM_AES_GCM",
                    "CKM_AES_KWP", "CKM_ML_DSA_44", "CKM_ML_KEM_768",
                ],
                "pqc_mechanisms_present": ["CKM_ML_DSA_44", "CKM_ML_KEM_768"],
                "pqc_ready": True,
                "pqc_readiness_note": (
                    "Firmware 7.13.0 advertises ML-DSA and ML-KEM. Keys on this "
                    "token can be migrated in place, so they are actionable now "
                    "rather than blocked on a vendor release."
                ),
                "objects": [
                    key("db-tde-signing", "0C31", "CKK_RSA", "CKO_PRIVATE_KEY",
                        sign, bits=3072, created=-500, expires=400,
                        extra={"application": "Database TDE key-signing"}),
                    key("api-mtls-issuer", "0C32", "CKK_EC", "CKO_PRIVATE_KEY",
                        sign, curve=P256, created=-300, expires=900,
                        extra={"application": "Internal mTLS issuing key"}),
                    key("doc-store-kek", "0C33", "CKK_AES", "CKO_SECRET_KEY",
                        wrap, created=-260, expires=1200,
                        extra={"CKA_VALUE_LEN": 32,
                               "application": "Document store KEK"}),
                ],
            },
            {
                "slot_id": 3,
                "token_label": "ISSUANCE-HSM-03",
                "manufacturer": "Thales",
                "model": "payShield 10K",
                "firmware_version": "1.4a",
                "serial_number": "5C88-3B41-9927",
                "fips_mode": "FIPS 140-2 Level 3",
                "mechanisms": [
                    "CKM_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_ECDSA",
                    "CKM_ECDSA_SHA256", "CKM_AES_GCM", "CKM_DES3_CBC",
                ],
                "pqc_mechanisms_present": [],
                "pqc_ready": False,
                "pqc_readiness_note": (
                    "Payment-issuance firmware with no PQC mechanism. These keys "
                    "sign card and token cryptograms verified across the network, "
                    "so migration is a scheme-coordinated programme, not a rotate."
                ),
                "objects": [
                    key("card-perso-master", "0D41", "CKK_AES",
                        "CKO_SECRET_KEY", wrap, created=-1000, expires=700,
                        extra={"CKA_VALUE_LEN": 32,
                               "application": "Card personalisation master",
                               "pci_scope": True}),
                    key("issuer-cert-signing", "0D42", "CKK_RSA",
                        "CKO_PRIVATE_KEY", sign, bits=2048, created=-1700,
                        expires=1500,
                        extra={"application": "EMV issuer certificate signing"}),
                    key("token-cryptogram", "0D43", "CKK_EC",
                        "CKO_PRIVATE_KEY", sign, curve=P256, created=-600,
                        expires=450,
                        extra={"application": "Network tokenisation cryptogram"}),
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# 2. Key manager — KMIP 2.1
#
# Shape: Locate -> GetAttributes. State is the field that matters; a
# Deactivated key still present is a different problem from an Active one.
# ---------------------------------------------------------------------------

def kmip() -> dict:
    def obj(uid, name, otype, algo, length, state, usage,
            created=-700, activated=-690, deactivated=None, group=""):
        return {
            "Unique Identifier": uid,
            "Name": name,
            "Object Type": otype,
            "Cryptographic Algorithm": algo,
            "Cryptographic Length": length,
            "Cryptographic Usage Mask": usage,
            "State": state,
            "Initial Date": _stamp(created),
            "Activation Date": _stamp(activated),
            "Deactivation Date": _stamp(deactivated) if deactivated else None,
            "Object Group": group,
            "Protection Storage Mask": ["Software"],
            "Fresh": False,
            "public_key_sha256": _fp(uid, name, algo),
        }

    return {
        "source": "kmip",
        "collected_at": _stamp(0),
        "endpoint": "kmip://keymanager.tejomaya.internal:5696",
        "protocol_version": "2.1",
        "note": (
            "Authenticated with a read-only client certificate. Only attributes "
            "were fetched; no Get operation for key material was issued."
        ),
        "objects": [
            obj("KMIP-0001", "tde-master-corebank", "Symmetric Key", "AES", 256,
                "Active", ["Encrypt", "Decrypt"], group="database-tde"),
            obj("KMIP-0002", "backup-archive-master", "Symmetric Key", "AES",
                256, "Active", ["Encrypt", "Decrypt"], group="backup",
                created=-1500, activated=-1490),
            obj("KMIP-0003", "tape-archive-legacy", "Symmetric Key", "DES3",
                168, "Deactivated", ["Decrypt"], created=-3000,
                activated=-2990, deactivated=-200, group="backup"),
            obj("KMIP-0004", "netbanking-jwt-signing", "Private Key", "RSA",
                2048, "Active", ["Sign"], group="identity", created=-620,
                activated=-615),
            obj("KMIP-0005", "mq-broker-tls", "Private Key", "RSA", 2048,
                "Active", ["Sign", "Decrypt"], group="messaging"),
            obj("KMIP-0006", "payments-code-signing", "Private Key", "RSA",
                3072, "Active", ["Sign"], group="signing", created=-800,
                activated=-790),
            obj("KMIP-0007", "settlement-envelope-kek", "Symmetric Key", "AES",
                256, "Active", ["Encrypt", "Decrypt"], group="settlement",
                created=-540, activated=-535),
            obj("KMIP-0008", "api-hmac-shared", "Symmetric Key", "HMAC-SHA256",
                256, "Active", ["MACGenerate", "MACVerify"], group="api",
                created=-410, activated=-405),
            obj("KMIP-0009", "tde-master-cards", "Symmetric Key", "AES", 256,
                "Active", ["Encrypt", "Decrypt"], group="database-tde",
                created=-900, activated=-880),
            obj("KMIP-0010", "legacy-file-transfer", "Symmetric Key", "DES3",
                168, "Active", ["Encrypt", "Decrypt"], group="legacy",
                created=-2200, activated=-2190),
            obj("KMIP-0011", "statements-jwt-signing", "Private Key", "RSA",
                2048, "Active", ["Sign"], group="identity", created=-500,
                activated=-495),
            obj("KMIP-0012", "kafka-broker-tls", "Private Key", "EC", 256,
                "Active", ["Sign", "Decrypt"], group="messaging", created=-350,
                activated=-345),
            obj("KMIP-0013", "archive-2018-master", "Symmetric Key", "AES", 128,
                "Deactivated", ["Decrypt"], group="backup", created=-3200,
                activated=-3190, deactivated=-400),
        ],
    }


# ---------------------------------------------------------------------------
# 3. Cloud KMS — AWS / Azure / GCP, each in its own native response shape
# ---------------------------------------------------------------------------

def cloud_kms() -> dict:
    return {
        "source": "cloud_kms",
        "collected_at": _stamp(0),
        "note": (
            "Read-only list/describe calls. Cloud KMS never returns key "
            "material for a managed key; only metadata was available to fetch."
        ),
        "aws_kms": {
            "region": "ap-south-1",
            "keys": [
                {
                    "KeyId": "3f2a9c11-77bd-4e0a-9c1e-8a4d2b7f0011",
                    "Arn": "arn:aws:kms:ap-south-1:210987654321:key/3f2a9c11-77bd-4e0a-9c1e-8a4d2b7f0011",
                    "Description": "Settlement file envelope encryption",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyState": "Enabled",
                    "Origin": "AWS_KMS",
                    "KeyManager": "CUSTOMER",
                    "MultiRegion": False,
                    "CreationDate": _stamp(-540),
                    "RotationEnabled": True,
                    "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
                },
                {
                    "KeyId": "b81f4d20-1c66-4a52-91ff-2ee7c5a30042",
                    "Arn": "arn:aws:kms:ap-south-1:210987654321:key/b81f4d20-1c66-4a52-91ff-2ee7c5a30042",
                    "Description": "Partner payload signing (asymmetric)",
                    "KeyUsage": "SIGN_VERIFY",
                    "KeySpec": "RSA_2048",
                    "KeyState": "Enabled",
                    "Origin": "AWS_KMS",
                    "KeyManager": "CUSTOMER",
                    "MultiRegion": False,
                    "CreationDate": _stamp(-410),
                    "RotationEnabled": False,
                    "SigningAlgorithms": [
                        "RSASSA_PSS_SHA_256", "RSASSA_PKCS1_V1_5_SHA_256",
                    ],
                },
                {
                    "KeyId": "c93e5a71-2f18-4b6d-8a0c-1de9f4c72055",
                    "Arn": "arn:aws:kms:ap-south-1:210987654321:key/c93e5a71-2f18-4b6d-8a0c-1de9f4c72055",
                    "Description": "Log archive envelope encryption",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyState": "Enabled",
                    "Origin": "AWS_KMS",
                    "KeyManager": "CUSTOMER",
                    "MultiRegion": False,
                    "CreationDate": _stamp(-300),
                    "RotationEnabled": True,
                    "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
                },
                {
                    "KeyId": "e4771b39-90ac-4d21-bb84-5c6620fa3097",
                    "Arn": "arn:aws:kms:ap-south-1:210987654321:key/e4771b39-90ac-4d21-bb84-5c6620fa3097",
                    "Description": "Mobile JWT signing (asymmetric)",
                    "KeyUsage": "SIGN_VERIFY",
                    "KeySpec": "ECC_NIST_P256",
                    "KeyState": "Enabled",
                    "Origin": "AWS_KMS",
                    "KeyManager": "CUSTOMER",
                    "MultiRegion": False,
                    "CreationDate": _stamp(-180),
                    "RotationEnabled": False,
                    "SigningAlgorithms": ["ECDSA_SHA_256"],
                },
                {
                    "KeyId": "a1552d84-6b0f-41e7-9f33-70c8e1a4b028",
                    "Arn": "arn:aws:kms:ap-south-1:210987654321:key/a1552d84-6b0f-41e7-9f33-70c8e1a4b028",
                    "Description": "S3 backup bucket envelope key",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "KeySpec": "SYMMETRIC_DEFAULT",
                    "KeyState": "Enabled",
                    "Origin": "AWS_KMS",
                    "KeyManager": "CUSTOMER",
                    "MultiRegion": True,
                    "CreationDate": _stamp(-620),
                    "RotationEnabled": True,
                    "EncryptionAlgorithms": ["SYMMETRIC_DEFAULT"],
                },
            ],
        },
        "azure_key_vault": {
            "vault": "https://tejomaya-prod-kv.vault.azure.net",
            "keys": [
                {
                    "kid": "https://tejomaya-prod-kv.vault.azure.net/keys/api-gateway-signing/9c2f",
                    "kty": "RSA",
                    "key_size": 2048,
                    "key_ops": ["sign", "verify"],
                    "managed": False,
                    "attributes": {
                        "enabled": True,
                        "created": _stamp(-300),
                        "updated": _stamp(-300),
                        "exp": _stamp(240),
                        "recoveryLevel": "Recoverable+Purgeable",
                    },
                    "rotation_policy": {"expiryTime": "P2Y", "enabled": False},
                    "public_key_sha256": _fp("azure", "api-gateway-signing"),
                },
                {
                    "kid": "https://tejomaya-prod-kv.vault.azure.net/keys/doc-encrypt-ec/1b70",
                    "kty": "EC",
                    "crv": "P-256",
                    "key_ops": ["sign", "verify"],
                    "managed": False,
                    "attributes": {
                        "enabled": True,
                        "created": _stamp(-150),
                        "updated": _stamp(-150),
                        "exp": None,
                        "recoveryLevel": "Recoverable+Purgeable",
                    },
                    "public_key_sha256": _fp("azure", "doc-encrypt-ec"),
                },
                {
                    "kid": "https://tejomaya-prod-kv.vault.azure.net/keys/partner-webhook-signing/7d21",
                    "kty": "RSA",
                    "key_size": 3072,
                    "key_ops": ["sign", "verify"],
                    "managed": False,
                    "attributes": {
                        "enabled": True,
                        "created": _stamp(-260),
                        "updated": _stamp(-260),
                        "exp": _stamp(470),
                        "recoveryLevel": "Recoverable+Purgeable",
                    },
                    "rotation_policy": {"expiryTime": "P2Y", "enabled": True},
                    "public_key_sha256": _fp("azure", "partner-webhook-signing"),
                },
                {
                    "kid": "https://tejomaya-prod-kv.vault.azure.net/keys/disk-encryption-rsa/4e88",
                    "kty": "RSA",
                    "key_size": 2048,
                    "key_ops": ["wrapKey", "unwrapKey"],
                    "managed": True,
                    "attributes": {
                        "enabled": True,
                        "created": _stamp(-330),
                        "updated": _stamp(-330),
                        "exp": _stamp(20),
                        "recoveryLevel": "Recoverable+Purgeable",
                    },
                    "rotation_policy": {"expiryTime": "P1Y", "enabled": False},
                    "public_key_sha256": _fp("azure", "disk-encryption-rsa"),
                },
            ],
        },
        "gcp_kms": {
            "project": "tejomaya-prod",
            "location": "asia-south1",
            "crypto_key_versions": [
                {
                    "name": "projects/tejomaya-prod/locations/asia-south1/keyRings/core/cryptoKeys/log-signing/cryptoKeyVersions/4",
                    "state": "ENABLED",
                    "algorithm": "EC_SIGN_P256_SHA256",
                    "protectionLevel": "HSM",
                    "createTime": _stamp(-220),
                    "generateTime": _stamp(-220),
                    "attestation": {"format": "CAVIUM_V2_COMPRESSED"},
                },
                {
                    "name": "projects/tejomaya-prod/locations/asia-south1/keyRings/core/cryptoKeys/pii-envelope/cryptoKeyVersions/2",
                    "state": "ENABLED",
                    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                    "protectionLevel": "SOFTWARE",
                    "createTime": _stamp(-95),
                    "generateTime": _stamp(-95),
                },
                {
                    "name": "projects/tejomaya-prod/locations/asia-south1/keyRings/core/cryptoKeys/report-signing/cryptoKeyVersions/3",
                    "state": "ENABLED",
                    "algorithm": "EC_SIGN_P384_SHA384",
                    "protectionLevel": "HSM",
                    "createTime": _stamp(-140),
                    "generateTime": _stamp(-140),
                    "attestation": {"format": "CAVIUM_V2_COMPRESSED"},
                },
                {
                    "name": "projects/tejomaya-prod/locations/asia-south1/keyRings/analytics/cryptoKeys/warehouse-envelope/cryptoKeyVersions/1",
                    "state": "ENABLED",
                    "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                    "protectionLevel": "SOFTWARE",
                    "createTime": _stamp(-70),
                    "generateTime": _stamp(-70),
                },
            ],
        },
    }


# ---------------------------------------------------------------------------
# 4. Keystores — JKS / PKCS#12, as `keytool -list -v` reports them
# ---------------------------------------------------------------------------

def keystores() -> dict:
    def entry(alias, etype, algo, size, subject, issuer, valid_days,
              created=-500, chain=2, sig="SHA256withRSA"):
        return {
            "alias": alias,
            "entry_type": etype,
            "creation_date": _iso(created),
            "key_algorithm": algo,
            "key_size": size,
            "signature_algorithm": sig,
            "certificate_chain_length": chain,
            "subject_dn": subject,
            "issuer_dn": issuer,
            "valid_from": _iso(created),
            "valid_until": _iso(valid_days),
            "sha256_fingerprint": _fp(alias, subject),
            "private_key_exported": False,
        }

    return {
        "source": "keystore",
        "collected_at": _stamp(0),
        "note": (
            "Parsed with the store password supplied by the operator. Entries "
            "were listed; no private key was exported and none is recorded."
        ),
        "stores": [
            {
                "path": "/opt/tomcat/conf/keystore.jks",
                "type": "JKS",
                "host": "corebank-api.tejomaya.internal",
                "entries": [
                    entry("corebank-api", "PrivateKeyEntry", "RSA", 2048,
                          "CN=corebank-api.tejomaya.internal,O=Tejomaya Bank,C=IN",
                          "CN=Tejomaya Issuing CA - Services,O=Tejomaya Bank,C=IN",
                          valid_days=88, created=-640),
                    entry("tejomaya-root-g3", "TrustedCertEntry", "RSA", 4096,
                          "CN=Tejomaya Root CA G3,O=Tejomaya Bank,C=IN",
                          "CN=Tejomaya Root CA G3,O=Tejomaya Bank,C=IN",
                          valid_days=4300, created=-2900, chain=1,
                          sig="SHA256withRSA"),
                ],
            },
            {
                "path": "/opt/mq/ssl/mq.p12",
                "type": "PKCS12",
                "host": "mq-broker.tejomaya.internal",
                "entries": [
                    entry("mq-broker", "PrivateKeyEntry", "RSA", 2048,
                          "CN=mq-broker.tejomaya.internal,O=Tejomaya Bank,C=IN",
                          "CN=Tejomaya Issuing CA - Services,O=Tejomaya Bank,C=IN",
                          valid_days=21, created=-700),
                    entry("partner-clearing", "TrustedCertEntry", "RSA", 2048,
                          "CN=clearing.partnerbank.example,O=Partner Bank,C=IN",
                          "CN=Partner Bank Issuing CA,O=Partner Bank,C=IN",
                          valid_days=310, created=-400, chain=2),
                ],
            },
            {
                "path": "/opt/app/internetbanking.p12",
                "type": "PKCS12",
                "host": "internetbanking.tejomaya.internal",
                "entries": [
                    entry("internetbanking-web", "PrivateKeyEntry", "RSA", 2048,
                          "CN=internetbanking.tejomaya.internal,O=Tejomaya Bank,C=IN",
                          "CN=Tejomaya Issuing CA - TLS,O=Tejomaya Bank,C=IN",
                          valid_days=17, created=-710),
                ],
            },
            {
                "path": "/etc/nginx/ssl/edge.jks",
                "type": "JKS",
                "host": "api-gateway.tejomaya.internal",
                "entries": [
                    entry("api-gateway", "PrivateKeyEntry", "RSA", 2048,
                          "CN=api-gateway.tejomaya.internal,O=Tejomaya Bank,C=IN",
                          "CN=Tejomaya Issuing CA - TLS,O=Tejomaya Bank,C=IN",
                          valid_days=54, created=-560),
                    entry("edge-waf", "PrivateKeyEntry", "EC", 256,
                          "CN=waf.tejomaya.internal,O=Tejomaya Bank,C=IN",
                          "CN=Tejomaya Issuing CA - TLS,O=Tejomaya Bank,C=IN",
                          valid_days=200, created=-300, sig="SHA256withECDSA"),
                ],
            },
            {
                "path": "/opt/ci/codesign.p12",
                "type": "PKCS12",
                "host": "build.tejomaya.internal",
                "entries": [
                    entry("build-code-signing", "PrivateKeyEntry", "RSA", 3072,
                          "CN=Tejomaya Build Code Signing,O=Tejomaya Bank,C=IN",
                          "CN=Tejomaya Issuing CA - Services,O=Tejomaya Bank,C=IN",
                          valid_days=430, created=-330),
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# 5. Certificates — chain metadata as an X.509 parser returns it
# ---------------------------------------------------------------------------

def certificates() -> dict:
    def cert(cn, issuer_cn, algo, size, sig, valid_days, created,
             is_ca=False, path_len=None, sans=None, eku=None, serial=""):
        return {
            "subject": f"CN={cn},O=Tejomaya Bank,C=IN",
            "issuer": f"CN={issuer_cn},O=Tejomaya Bank,C=IN",
            "serial_number": serial or _fp(cn)[:23],
            "not_before": _iso(created),
            "not_after": _iso(valid_days),
            "days_remaining": valid_days,
            "signature_algorithm": sig,
            "public_key_algorithm": algo,
            "public_key_size": size,
            "basic_constraints_ca": is_ca,
            "path_length": path_len,
            "subject_alt_names": sans or [],
            "key_usage": (["keyCertSign", "cRLSign"] if is_ca
                          else ["digitalSignature", "keyEncipherment"]),
            "extended_key_usage": eku or ([] if is_ca else ["serverAuth"]),
            "sha256_fingerprint": _fp(cn, issuer_cn),
            "self_signed": cn == issuer_cn,
        }

    return {
        "source": "certificate",
        "collected_at": _stamp(0),
        "note": (
            "Chain metadata only. Issuer/subject pairs resolve the hierarchy, "
            "which is what produces the dependency graph."
        ),
        "certificates": [
            cert("Tejomaya Root CA G3", "Tejomaya Root CA G3", "RSA", 4096,
                 "SHA256withRSA", 4300, -2900, is_ca=True, path_len=2),
            cert("Tejomaya Issuing CA - Services", "Tejomaya Root CA G3",
                 "RSA", 3072, "SHA256withRSA", 1650, -1400, is_ca=True,
                 path_len=0),
            cert("Tejomaya Issuing CA - Devices", "Tejomaya Root CA G3",
                 "RSA", 3072, "SHA256withRSA", 1650, -1400, is_ca=True,
                 path_len=0),
            cert("corebank-api.tejomaya.internal",
                 "Tejomaya Issuing CA - Services", "RSA", 2048,
                 "SHA256withRSA", 88, -640,
                 sans=["corebank-api.tejomaya.internal"]),
            cert("mq-broker.tejomaya.internal",
                 "Tejomaya Issuing CA - Services", "RSA", 2048,
                 "SHA256withRSA", 21, -700,
                 sans=["mq-broker.tejomaya.internal"]),
            cert("upi-switch.tejomaya.internal",
                 "Tejomaya Issuing CA - Services", "ECDSA", 256,
                 "SHA256withECDSA", 260, -400,
                 sans=["upi-switch.tejomaya.internal"]),
        ] + _service_fleet(cert),
    }


# ---------------------------------------------------------------------------
# Service fleet — the long tail of leaf certificates a real bank runs.
#
# A payments estate is dozens of internal service certs under a few issuing
# CAs, not a handful. This list gives the dependency graph its shape and the
# TLS-edge zone its population, with a realistic spread of algorithms and
# expiry windows — several inside 30 days, a couple already expired — so the
# "expiring" and "behind" signals on the dashboard are real, not staged.
#
# (host, issuer_suffix, algo, size, sig, valid_days, created)
# ---------------------------------------------------------------------------

_FLEET_HOSTS = [
    ("internetbanking-portal.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", 22, -700),
    ("mobile-api.tejomaya.internal", "Services", "ECDSA", 256, "SHA256withECDSA", 300, -400),
    ("imps-gateway.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 640, -300),
    ("neft-gateway.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 12, -720),
    ("rtgs-gateway.tejomaya.internal", "Services", "RSA", 3072, "SHA256withRSA", 500, -350),
    ("card-auth.tejomaya.internal", "Services", "ECDSA", 256, "SHA256withECDSA", 210, -420),
    ("fraud-scoring.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 730, -200),
    ("ledger-core.tejomaya.internal", "Services", "RSA", 3072, "SHA256withRSA", 400, -300),
    ("statements.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", -8, -740),
    ("notifications.tejomaya.internal", "TLS", "ECDSA", 256, "SHA256withECDSA", 160, -420),
    ("kyc-service.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 90, -600),
    ("aml-screening.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 27, -690),
    ("forex-rates.tejomaya.internal", "TLS", "ECDSA", 256, "SHA256withECDSA", 800, -100),
    ("loan-origination.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 340, -380),
    ("deposits-api.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 610, -260),
    ("wallet-service.tejomaya.internal", "Services", "ECDSA", 256, "SHA256withECDSA", 55, -650),
    ("merchant-onboarding.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", 480, -300),
    ("settlement-api.tejomaya.internal", "Services", "RSA", 3072, "SHA256withRSA", 5, -760),
    ("recon-engine.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 290, -420),
    ("reporting-api.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", 900, -80),
    ("admin-portal.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", 130, -520),
    ("partner-gateway.tejomaya.internal", "Services", "RSA", 3072, "SHA256withRSA", 420, -330),
    ("webhook-dispatch.tejomaya.internal", "TLS", "ECDSA", 256, "SHA256withECDSA", 250, -410),
    ("otp-service.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 18, -700),
    ("esign-service.tejomaya.internal", "Services", "RSA", 2048, "SHA256withRSA", 360, -360),
    ("jwt-issuer.tejomaya.internal", "Services", "ECDSA", 256, "SHA256withECDSA", 540, -260),
    ("document-store.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", 700, -150),
    ("audit-log.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", 320, -400),
    ("config-service.tejomaya.internal", "TLS", "ECDSA", 256, "SHA256withECDSA", 610, -200),
    ("firmware-update.tejomaya.internal", "Devices", "RSA", 3072, "SHA256withRSA", 1100, -300),
    ("pos-terminal-leaf.tejomaya.internal", "Devices", "ECDSA", 256, "SHA256withECDSA", 480, -350),
    ("code-sign-portal.tejomaya.internal", "Services", "RSA", 3072, "SHA256withRSA", 260, -300),
    ("grafana-internal.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", -19, -800),
    ("kafka-connect.tejomaya.internal", "TLS", "RSA", 2048, "SHA256withRSA", 210, -430),
    ("service-mesh-gw.tejomaya.internal", "TLS", "ECDSA", 384, "SHA384withECDSA", 380, -300),
]


def _service_fleet(cert) -> list:
    """The TLS issuing CA plus the service leaf certs that chain to it."""
    fleet = [
        cert("Tejomaya Issuing CA - TLS", "Tejomaya Root CA G3", "RSA", 3072,
             "SHA256withRSA", 1650, -1400, is_ca=True, path_len=0),
    ]
    for host, issuer_suffix, algo, size, sig, valid_days, created in _FLEET_HOSTS:
        fleet.append(
            cert(host, f"Tejomaya Issuing CA - {issuer_suffix}", algo, size,
                 sig, valid_days, created, sans=[host])
        )
    return fleet


# ---------------------------------------------------------------------------
# Manifest — what each source proves, and what it does not
# ---------------------------------------------------------------------------

def manifest() -> dict:
    return {
        "vault": "VERA demo key vault",
        "generated": _stamp(0),
        "synthetic": True,
        "warning": (
            "Entirely synthetic. No host, key, certificate or fingerprint here "
            "corresponds to real infrastructure. Generated by make_vault.py and "
            "deterministic between runs."
        ),
        "key_material_present": False,
        "sources": [
            {
                "file": "hsm_pkcs11.json",
                "provenance": "declared",
                "confidence": 0.85,
                "proves": "The object exists, its parameters, and whether the "
                          "token's firmware can do PQC at all.",
                "cannot_prove": "That the key is in active use. An HSM object "
                                "is present whether or not anything calls it.",
            },
            {
                "file": "kmip.json",
                "provenance": "declared",
                "confidence": 0.85,
                "proves": "Managed object attributes and lifecycle state.",
                "cannot_prove": "Use. A Deactivated key may still be needed to "
                                "decrypt archived data.",
            },
            {
                "file": "cloud_kms.json",
                "provenance": "declared",
                "confidence": 0.85,
                "proves": "Key spec, usage, rotation and protection level.",
                "cannot_prove": "Which workload holds a grant on it.",
            },
            {
                "file": "keystores.json",
                "provenance": "artifact_parsed",
                "confidence": 0.90,
                "proves": "The key and chain are on disk with these parameters.",
                "cannot_prove": "That the running process loaded this store.",
            },
            {
                "file": "certificates.json",
                "provenance": "artifact_parsed",
                "confidence": 0.90,
                "proves": "Identity, validity window and the issuing hierarchy.",
                "cannot_prove": "That the certificate is served anywhere.",
            },
        ],
        "blind_spots": [
            "Mainframe (ICSF) cryptography — no sensor reaches it.",
            "Vendor-managed SaaS signing — visible only in a contract.",
            "Anything an application derives at runtime and never persists.",
        ],
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    files = {
        "hsm_pkcs11.json": hsm_pkcs11(),
        "kmip.json": kmip(),
        "cloud_kms.json": cloud_kms(),
        "keystores.json": keystores(),
        "certificates.json": certificates(),
        "manifest.json": manifest(),
    }
    for name, payload in files.items():
        path = OUT / name
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(OUT.parent.parent)}")

    counts = {
        "hsm objects": sum(len(s["objects"]) for s in files["hsm_pkcs11.json"]["slots"]),
        "kmip objects": len(files["kmip.json"]["objects"]),
        "cloud keys": (
            len(files["cloud_kms.json"]["aws_kms"]["keys"])
            + len(files["cloud_kms.json"]["azure_key_vault"]["keys"])
            + len(files["cloud_kms.json"]["gcp_kms"]["crypto_key_versions"])
        ),
        "keystore entries": sum(len(s["entries"]) for s in files["keystores.json"]["stores"]),
        "certificates": len(files["certificates.json"]["certificates"]),
    }
    print("\n" + " · ".join(f"{v} {k}" for k, v in counts.items()))
    print(f"total metadata objects: {sum(counts.values())}")


if __name__ == "__main__":
    main()
