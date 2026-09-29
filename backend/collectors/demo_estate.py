"""Synthetic enterprise cryptographic estate.

The blueprint's demo has two halves. The headline finding must come from real,
public TLS endpoints, because a planted finding proves nothing. But the write
path - keystores, PKI, firmware signing, source - needs a target estate, and no
organisation is going to hand one over for a hackathon.

This module is that target estate: a composite Indian financial-services group
that also operates payment infrastructure, which is what makes the DST
highest-risk-persona-governs rule bite. Everything here is clearly synthetic and
labelled as such in the API response.

Design constraints:

  - **Deterministic.** Seeded, so the numbers on stage are the numbers in
    rehearsal. A demo whose headline count changes between runs is unusable.
  - **Structurally realistic.** The shape of a real estate is a long tail of
    TLS endpoints over a small number of very-high-consequence signing anchors.
    Charts built on a flat distribution look synthetic because they are.
  - **Spans the model.** It must contain assets that separate the two axes:
    ephemeral key exchange (high HNDL, near-zero TNFL) and long-lived roots
    (low HNDL, maximum TNFL). Otherwise the dual-axis argument has nothing to
    stand on.
"""

from __future__ import annotations

import datetime
import hashlib
import random

from models.schemas import RawCryptoFinding

ORG_NAME = "Tejomaya Financial Services Group"
ORG_DESCRIPTION = (
    "Synthetic composite: a scheduled commercial bank that also operates a UPI "
    "payment switch and an ATM network, so parts of the estate fall under the "
    "DST critical-infrastructure track while the rest follows the banking track."
)

SEED = 20260820

# Deterministic id generation. uuid4 would make every scan produce different
# ids, which breaks scan-to-scan comparison in the hybrid harness.
_ID_NAMESPACE = "vera-demo-estate"


def _stable_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join((_ID_NAMESPACE, *parts)).encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


# --------------------------------------------------------------------------
# Internal TLS estate
#
# (host, service label, algorithm, key size, cipher suite, protocol, tags,
#  environment)
# --------------------------------------------------------------------------

_TLS_SERVICES: list[tuple[str, str, str, int, str, str, tuple[str, ...], str]] = [
    # --- Payment rails: CII track ---
    ("upi-switch.tejomaya.internal", "UPI payment switch", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("upi", "payments", "cii"), "production"),
    ("upi-psp-gateway.tejomaya.internal", "UPI PSP gateway", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("upi", "payments", "cii"), "production"),
    ("imps-adapter.tejomaya.internal", "IMPS adapter", "RSA", 2048,
     "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("imps", "payments", "cii"), "production"),
    ("neft-gateway.tejomaya.internal", "NEFT batch gateway", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", ("neft", "payments", "cii"), "production"),
    ("rtgs-gateway.tejomaya.internal", "RTGS gateway", "RSA", 3072,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("rtgs", "payments", "cii"), "production"),
    ("atm-switch.tejomaya.internal", "ATM switch", "RSA", 2048,
     "TLS_RSA_WITH_AES_128_CBC_SHA256", "TLSv1.2", ("atm-switch", "cii"), "production"),
    ("card-switch.tejomaya.internal", "Card authorisation switch", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("card-switch", "cii"), "production"),
    ("swift-ca.tejomaya.internal", "SWIFT Alliance connector", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("swift", "cii"), "production"),
    ("settlement-recon.tejomaya.internal", "Settlement reconciliation", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("settlement", "cii"), "production"),
    ("nse-feed.tejomaya.internal", "NSE market data feed", "ECDSA", 256,
     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", ("nse", "cii"), "production"),

    # --- Core banking ---
    ("corebank-api.tejomaya.internal", "Core banking API", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("core-banking",), "production"),
    ("corebank-batch.tejomaya.internal", "Core banking batch", "RSA", 2048,
     "TLS_RSA_WITH_AES_256_CBC_SHA", "TLSv1.2", ("core-banking",), "production"),
    ("deposits-svc.tejomaya.internal", "Deposits service", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", ("deposit",), "production"),
    ("loans-svc.tejomaya.internal", "Loan origination", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("loan",), "production"),
    ("treasury-fx.tejomaya.internal", "Treasury FX desk", "RSA", 3072,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("treasury",), "production"),
    ("branch-teller.tejomaya.internal", "Branch teller application", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLSv1.2", ("branch",), "production"),
    ("gl-posting.tejomaya.internal", "General ledger posting", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("core-banking",), "production"),

    # --- Customer channels ---
    ("netbanking.tejomaya.co.in", "Internet banking", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", ("channel", "bank"), "production"),
    ("m-api.tejomaya.co.in", "Mobile banking API", "ECDSA", 256,
     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", ("channel", "bank"), "production"),
    ("api-gateway.tejomaya.co.in", "Partner API gateway", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", ("channel", "bank"), "production"),
    ("cards.tejomaya.co.in", "Card management portal", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", ("channel", "bank"), "production"),
    ("wealth.tejomaya.co.in", "Wealth management portal", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("channel", "bank"), "production"),
    ("onboarding.tejomaya.co.in", "Digital onboarding", "ECDSA", 256,
     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", ("channel", "bank"), "production"),
    ("support.tejomaya.co.in", "Customer support portal", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", ("channel",), "production"),

    # --- Identity and regulatory integrations ---
    ("ekyc-asa.tejomaya.internal", "Aadhaar eKYC ASA connector", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("aadhaar", "uidai"), "production"),
    ("ckyc-bridge.tejomaya.internal", "CKYC registry bridge", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("gov.in",), "production"),
    ("gstn-filing.tejomaya.internal", "GSTN filing connector", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", ("gstn",), "production"),
    ("cibil-connector.tejomaya.internal", "Credit bureau connector", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("bank",), "production"),
    ("regfiling.tejomaya.internal", "Regulatory reporting", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("rbi",), "production"),

    # --- Infrastructure ---
    ("ldap.tejomaya.internal", "Directory service over TLS", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("identity",), "production"),
    ("kafka-broker-1.tejomaya.internal", "Event bus mTLS", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("infra",), "production"),
    ("kafka-broker-2.tejomaya.internal", "Event bus mTLS", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("infra",), "production"),
    ("mesh-ingress.tejomaya.internal", "Service mesh ingress", "ECDSA", 256,
     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", ("infra",), "production"),
    ("vault.tejomaya.internal", "Secrets manager", "ECDSA", 256,
     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLSv1.3", ("infra",), "production"),
    ("monitoring.tejomaya.internal", "Observability stack", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", ("infra",), "production"),
    ("jenkins.tejomaya.internal", "CI server", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2", ("infra",), "staging"),
    ("artifactory.tejomaya.internal", "Artifact repository", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("infra",), "production"),

    # --- Legacy: the findings that make a real scan interesting ---
    ("legacy-mainframe-gw.tejomaya.internal", "Mainframe gateway", "RSA", 1024,
     "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLSv1.0", ("core-banking", "legacy"), "production"),
    ("legacy-recon.tejomaya.internal", "Legacy reconciliation", "RSA", 1024,
     "TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.1", ("legacy",), "production"),
    ("fileserver-ftps.tejomaya.internal", "FTPS file transfer", "RSA", 2048,
     "TLS_RSA_WITH_AES_256_CBC_SHA", "TLSv1.2", ("legacy",), "production"),

    # --- Disaster recovery mirrors ---
    ("dr-corebank-api.tejomaya.internal", "Core banking API (DR)", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("core-banking",), "dr"),
    ("dr-upi-switch.tejomaya.internal", "UPI switch (DR)", "RSA", 2048,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLSv1.2", ("upi", "cii"), "dr"),
]


# --------------------------------------------------------------------------
# Keystores: PKI, signing anchors, HSM-resident keys
#
# (path, asset_class, algorithm, key size, subject, usage, trust years, tags)
# --------------------------------------------------------------------------

_KEYSTORE_ENTRIES: list[tuple[str, str, str, int, str, str, tuple[str, ...]]] = [
    # --- PKI hierarchy ---
    ("/opt/pki/root-ca/tejomaya-root-ca-g2.pem", "root_ca", "RSA", 4096,
     "CN=Tejomaya Root CA G2,O=Tejomaya Financial Services Group,C=IN", "signing",
     ("pki", "core-banking")),
    ("/opt/pki/issuing/tejomaya-issuing-ca-tls.pem", "issuing_ca", "RSA", 2048,
     "CN=Tejomaya Issuing CA - TLS,O=Tejomaya Financial Services Group,C=IN", "signing",
     ("pki",)),
    ("/opt/pki/issuing/tejomaya-issuing-ca-device.pem", "issuing_ca", "RSA", 2048,
     "CN=Tejomaya Issuing CA - Device,O=Tejomaya Financial Services Group,C=IN", "signing",
     ("pki", "atm-switch")),
    ("/opt/pki/issuing/tejomaya-issuing-ca-user.pem", "issuing_ca", "ECDSA", 256,
     "CN=Tejomaya Issuing CA - User,O=Tejomaya Financial Services Group,C=IN", "signing",
     ("pki", "identity")),

    # --- Signing anchors: the assets the model exists to surface ---
    ("/opt/signing/atm-firmware-signing.p12", "firmware_signing", "RSA", 2048,
     "CN=Tejomaya ATM Firmware Signing,OU=ATM Estate,O=Tejomaya", "signing",
     ("atm-switch", "firmware", "cii")),
    ("/opt/signing/pos-terminal-firmware.p12", "firmware_signing", "RSA", 2048,
     "CN=Tejomaya POS Firmware Signing,OU=Merchant Acquiring,O=Tejomaya", "signing",
     ("card-switch", "firmware", "cii")),
    ("/opt/signing/mobile-app-release.p12", "code_signing", "RSA", 3072,
     "CN=Tejomaya Mobile Release Signing,O=Tejomaya", "signing", ("channel", "code")),
    ("/opt/signing/internal-code-signing.p12", "code_signing", "RSA", 3072,
     "CN=Tejomaya Internal Code Signing,O=Tejomaya", "signing", ("code",)),
    ("/opt/signing/audit-log-signing.p12", "code_signing", "ECDSA", 256,
     "CN=Tejomaya Audit Log Signing,O=Tejomaya", "signing", ("audit", "rbi")),

    # --- Payment HSM ---
    ("hsm://payment-hsm-01/slot0/zmk-rsa-wrap", "payment_hsm", "RSA", 2048,
     "Payment HSM zone master key wrapping pair", "key_wrapping",
     ("payment-hsm", "card-switch", "cii")),
    ("hsm://payment-hsm-01/slot0/card-verify", "payment_hsm", "RSA", 2048,
     "Card verification key pair", "signing", ("payment-hsm", "cii")),
    ("hsm://payment-hsm-02/slot0/zmk-rsa-wrap", "payment_hsm", "RSA", 2048,
     "Payment HSM zone master key wrapping pair (site B)", "key_wrapping",
     ("payment-hsm", "cii")),
    ("hsm://payment-hsm-01/slot1/pin-translation", "payment_hsm", "3DES", 112,
     "PIN block translation key", "encryption", ("payment-hsm", "cii")),

    # --- SWIFT and regulatory PKI ---
    ("/opt/swift/pki/swift-pki-cert.p12", "device_identity", "RSA", 2048,
     "CN=tejomayain-swift,O=SWIFT", "signing", ("swift", "cii")),
    ("/opt/regulatory/dsc-class3-cfo.p12", "code_signing", "RSA", 2048,
     "CN=Class 3 DSC - Regulatory Filing,O=Tejomaya", "signing", ("rbi", "gov.in")),
    ("/opt/aadhaar/asa-signing.p12", "code_signing", "RSA", 2048,
     "CN=Tejomaya ASA Digital Signature,O=UIDAI ASA", "signing", ("aadhaar", "uidai")),

    # --- Token and assertion signing ---
    ("/opt/idp/jwt-signing-rs256.pem", "token_signing", "RSA", 2048,
     "JWT signing key (RS256)", "signing", ("identity", "channel")),
    ("/opt/idp/jwt-signing-es256.pem", "token_signing", "ECDSA", 256,
     "JWT signing key (ES256)", "signing", ("identity",)),
    ("/opt/idp/saml-idp-signing.p12", "token_signing", "RSA", 2048,
     "CN=Tejomaya SAML IdP Signing,O=Tejomaya", "signing", ("identity",)),
    ("/opt/idp/oidc-jwks-active.pem", "token_signing", "ECDSA", 256,
     "OIDC JWKS active signing key", "signing", ("identity", "channel")),

    # --- Device identity ---
    ("/opt/pki/device/atm-fleet-identity.jks", "device_identity", "RSA", 2048,
     "CN=ATM Fleet Device Identity,OU=ATM Estate,O=Tejomaya", "signing",
     ("atm-switch", "cii")),
    ("/opt/pki/device/pos-fleet-identity.jks", "device_identity", "ECDSA", 256,
     "CN=POS Fleet Device Identity,O=Tejomaya", "signing", ("card-switch", "cii")),
    ("/opt/pki/device/branch-kiosk-identity.jks", "device_identity", "RSA", 2048,
     "CN=Branch Kiosk Identity,O=Tejomaya", "signing", ("branch",)),

    # --- mTLS client credentials ---
    ("/opt/mtls/npci-client.p12", "device_identity", "RSA", 2048,
     "CN=tejomaya-npci-client,O=NPCI", "signing", ("npci", "upi", "cii")),
    ("/opt/mtls/cibil-client.p12", "device_identity", "RSA", 2048,
     "CN=tejomaya-cibil-client", "signing", ("bank",)),
    ("/opt/mtls/nsdl-client.p12", "device_identity", "RSA", 2048,
     "CN=tejomaya-nsdl-client,O=NSDL", "signing", ("nsdl", "cii")),

    # --- SSH ---
    ("/etc/ssh/ssh_host_rsa_key", "ssh_key", "RSA", 3072,
     "SSH host key (bastion fleet)", "signing", ("infra",)),
    ("/etc/ssh/ssh_host_ed25519_key", "ssh_key", "Ed25519", 256,
     "SSH host key (bastion fleet)", "signing", ("infra",)),
    ("/home/deploy/.ssh/id_rsa", "ssh_key", "RSA", 2048,
     "Deployment automation key", "signing", ("infra",)),

    # --- Symmetric material: correctly quantum-safe, and the estate must show it ---
    ("/opt/backup/archive-master-key", "backup_encryption", "AES", 256,
     "Backup archive master key", "encryption", ("infra",)),
    ("/opt/backup/tape-archive-legacy", "backup_encryption", "3DES", 112,
     "Legacy tape archive key", "encryption", ("legacy",)),
    ("oracle://corebank/wallet/tde-master", "database_tls", "AES", 256,
     "Oracle TDE master key", "encryption", ("core-banking",)),
    ("/opt/vault/transit-key-primary", "generic_key", "AES", 256,
     "Vault transit encryption key", "encryption", ("infra",)),
]


# --------------------------------------------------------------------------
# Configuration findings
# --------------------------------------------------------------------------

_CONFIG_ENTRIES: list[tuple[str, str, str | None, str | None, str | None, tuple[str, ...]]] = [
    # (path, directive, protocol, cipher_suite, algorithm, tags)
    ("/etc/nginx/conf.d/netbanking.conf", "ssl_protocols", "TLSv1.2 TLSv1.3", None, None, ("channel",)),
    ("/etc/nginx/conf.d/netbanking.conf", "ssl_ciphers", None,
     "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256", None, ("channel",)),
    ("/etc/nginx/conf.d/netbanking.conf", "ssl_ecdh_curve", None, None, "X25519", ("channel",)),
    ("/etc/nginx/conf.d/api-gateway.conf", "ssl_protocols", "TLSv1.2 TLSv1.3", None, None, ("channel",)),
    ("/etc/nginx/conf.d/api-gateway.conf", "ssl_ciphers", None,
     "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384", None, ("channel",)),
    ("/etc/httpd/conf.d/ssl-legacy.conf", "SSLProtocol", "TLSv1.0 TLSv1.1 TLSv1.2", None, None, ("legacy",)),
    ("/etc/httpd/conf.d/ssl-legacy.conf", "SSLCipherSuite", None,
     "ECDHE-RSA-AES256-SHA384:DES-CBC3-SHA", None, ("legacy",)),
    ("/etc/haproxy/haproxy.cfg", "ssl-default-bind-ciphers", None,
     "ECDHE-ECDSA-AES256-GCM-SHA384", None, ("infra",)),
    ("/etc/haproxy/haproxy.cfg", "ssl-default-bind-options", "TLSv1.2", None, None, ("infra",)),
    ("/etc/ssh/sshd_config", "KexAlgorithms", None, None, "ECDH", ("infra",)),
    ("/etc/ssh/sshd_config", "HostKeyAlgorithms", None, None, "RSA", ("infra",)),
    ("/etc/ipsec.conf", "ike", None, None, "DH", ("infra", "vpn")),
    ("/etc/ipsec.conf", "esp", None, "AES256-SHA256", None, ("infra", "vpn")),
    ("/etc/strongswan/branch-tunnels.conf", "ike", None, None, "ECDH", ("branch", "vpn")),
    ("/opt/java/conf/security/java.security", "jdk.tls.disabledAlgorithms", None, None, "3DES", ("infra",)),
    ("/opt/tomcat/conf/server.xml", "sslProtocol", "TLSv1.2", None, None, ("core-banking",)),
    ("/opt/tomcat/conf/server.xml", "ciphers", None,
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", None, ("core-banking",)),
    ("/opt/weblogic/config/config.xml", "ssl-protocol", "TLSv1.2", None, None, ("core-banking", "legacy")),
    ("/etc/postgresql/16/main/postgresql.conf", "ssl_ciphers", None,
     "ECDHE-RSA-AES256-GCM-SHA384", None, ("infra",)),
    ("/etc/openssl/openssl.cnf", "CipherString", None, "DEFAULT:@SECLEVEL=2", None, ("infra",)),
]


# --------------------------------------------------------------------------
# Source-code findings
# --------------------------------------------------------------------------

_SOURCE_ENTRIES: list[tuple[str, str, str, int | None, str, tuple[str, ...]]] = [
    # (location, algorithm, api, key size, usage, tags)
    ("services/payments/upi/signer.py:88", "RSA", "cryptography.hazmat...rsa.generate_private_key",
     2048, "signing", ("upi", "cii")),
    ("services/payments/upi/verify.py:41", "SHA-256", "hashlib.sha256", None, "hashing", ("upi",)),
    ("services/auth/token.py:52", "RSA", "jwt.encode(alg='RS256')", 2048, "signing", ("identity",)),
    ("services/auth/legacy_session.py:19", "SHA-1", "hashlib.sha1", None, "hashing", ("identity", "legacy")),
    ("services/auth/password_legacy.py:33", "MD5", "hashlib.md5", None, "hashing", ("legacy",)),
    ("services/cards/pin_block.java:120", "3DES", "javax.crypto.Cipher.getInstance(\"DESede\")",
     112, "encryption", ("card-switch", "cii", "legacy")),
    ("services/cards/tokenize.java:64", "AES", "javax.crypto.Cipher.getInstance(\"AES/GCM/NoPadding\")",
     256, "encryption", ("card-switch",)),
    ("services/statements/archive.py:77", "AES", "AESGCM", 256, "encryption", ("infra",)),
    ("services/statements/legacy_export.py:26", "DES", "Crypto.Cipher.DES", 56, "encryption", ("legacy",)),
    ("services/kyc/aadhaar_client.py:145", "RSA", "OAEP encrypt to UIDAI public key", 2048,
     "encryption", ("aadhaar", "uidai")),
    ("services/kyc/xml_signer.java:210", "RSA", "javax.xml.crypto.dsig SHA256withRSA", 2048,
     "signing", ("aadhaar",)),
    ("services/treasury/fix_session.py:58", "ECDSA", "cryptography ec.ECDSA(SHA256)", 256,
     "signing", ("treasury",)),
    ("services/infra/mtls_client.py:31", "ECDHE", "ssl.SSLContext.set_ecdh_curve", None,
     "key_exchange", ("infra",)),
    ("libs/crypto/kdf.py:12", "HKDF", "cryptography HKDF", None, "key_derivation", ("infra",)),
    ("libs/crypto/rng.py:8", "SHA-256", "os.urandom + SHA-256 DRBG", None, "hashing", ("infra",)),
    ("services/reporting/rbi_submission.py:190", "RSA", "PKCS#7 detached signature", 2048,
     "signing", ("rbi",)),
]


def _cert_dates(rng: random.Random, trust_years: float) -> tuple[str, str]:
    """Plausible validity window, anchored on *remaining* life rather than issue date.

    The previous version picked an issue date up to 900 days back and added the
    trust horizon, which for a short-lived certificate lands the expiry in the
    past - a third of the estate came out already expired, which reads as stale
    fixture data rather than as a finding.

    Remaining life is drawn instead, from a distribution shaped like a real
    estate: mostly healthy, a renewal cycle's worth in the warning window, a
    couple genuinely overdue. Real inventories do contain expired certificates -
    77% of organisations report an outage caused by one - so a small number of
    them is accurate, and a large number is a bug.
    """
    today = datetime.date.today()
    validity_days = max(30, int(365 * min(trust_years, 10)))

    roll = rng.random()
    if roll < 0.03:
        # Already lapsed. Small, deliberate, and a finding in its own right.
        remaining = -rng.randint(3, 45)
    elif roll < 0.08:
        # Inside the 30-day critical window.
        remaining = rng.randint(2, 29)
    elif roll < 0.14:
        # Inside the 90-day warning window.
        remaining = rng.randint(31, 89)
    else:
        # Healthy: somewhere in the back half of its validity period.
        remaining = rng.randint(120, max(150, validity_days))

    expires = today + datetime.timedelta(days=remaining)
    issued = expires - datetime.timedelta(days=validity_days)
    return (
        datetime.datetime.combine(issued, datetime.time.min).isoformat() + "Z",
        datetime.datetime.combine(expires, datetime.time.min).isoformat() + "Z",
    )


def _sig_alg(algorithm: str) -> str:
    return {
        "RSA": "sha256WithRSAEncryption",
        "ECDSA": "ecdsa-with-SHA256",
        "Ed25519": "Ed25519",
        "3DES": "n/a",
        "AES": "n/a",
    }.get(algorithm, "sha256WithRSAEncryption")


def generate_estate() -> list[RawCryptoFinding]:
    """Build the full synthetic estate. Deterministic for a fixed SEED."""
    rng = random.Random(SEED)
    findings: list[RawCryptoFinding] = []

    # --- TLS: each endpoint yields a certificate, a key exchange and a suite ---
    for host, label, algo, key_size, suite, proto, tags, env in _TLS_SERVICES:
        issued, expires = _cert_dates(rng, 1.1)
        base_tags = list(tags) + [env]

        findings.append(RawCryptoFinding(
            id=_stable_id("tls-cert", host),
            source_type="tls",
            source_location=f"{host}:443",
            asset_class="tls_certificate",
            algorithm=algo,
            key_size=key_size,
            protocol=proto,
            signature_algorithm=_sig_alg(algo),
            cert_subject=f"CN={host},O={ORG_NAME},C=IN",
            cert_issuer="CN=Tejomaya Issuing CA - TLS,O=Tejomaya Financial Services Group,C=IN",
            cert_validity_start=issued,
            cert_validity_end=expires,
            cert_serial=str(rng.getrandbits(96)),
            usage="signing",
            tags=base_tags,
            environment=env,
            raw_details={"type": "certificate", "service": label},
        ))

        # Key exchange: TLS 1.3 negotiates a named group; TLS 1.2 uses whatever
        # the suite specifies.
        kex = "X25519" if proto == "TLSv1.3" else (
            "ECDHE" if "ECDHE" in suite else "RSA"
        )
        findings.append(RawCryptoFinding(
            id=_stable_id("tls-kex", host),
            source_type="tls",
            source_location=f"{host}:443",
            asset_class="tls_key_exchange",
            key_exchange=kex,
            protocol=proto,
            usage="key_exchange",
            tags=base_tags,
            environment=env,
            raw_details={"type": "key_exchange", "service": label},
        ))

        findings.append(RawCryptoFinding(
            id=_stable_id("tls-suite", host),
            source_type="tls",
            source_location=f"{host}:443",
            asset_class="tls_cipher_suite",
            cipher_suite=suite,
            protocol=proto,
            usage="encryption",
            tags=base_tags,
            environment=env,
            raw_details={"type": "cipher_suite", "service": label},
        ))

    # --- Keystores ---
    trust_years_by_class = {
        "root_ca": 20.0, "issuing_ca": 8.0, "firmware_signing": 12.0,
        "code_signing": 10.0, "payment_hsm": 6.0, "device_identity": 8.0,
        "token_signing": 3.0, "ssh_key": 4.0, "backup_encryption": 1.0,
        "database_tls": 2.0, "generic_key": 5.0,
    }
    for path, asset_class, algo, key_size, subject, usage, tags in _KEYSTORE_ENTRIES:
        issued, expires = _cert_dates(rng, trust_years_by_class.get(asset_class, 5.0))
        is_cert = subject.upper().startswith("CN=")
        findings.append(RawCryptoFinding(
            id=_stable_id("keystore", path),
            source_type="keystore",
            source_location=path,
            asset_class=asset_class,
            algorithm=algo,
            key_size=key_size,
            signature_algorithm=_sig_alg(algo) if usage == "signing" else None,
            cert_subject=subject if is_cert else None,
            cert_issuer=(
                "CN=Tejomaya Root CA G2,O=Tejomaya Financial Services Group,C=IN"
                if is_cert and "Root CA" not in subject else
                (subject if is_cert else None)
            ),
            cert_validity_start=issued if is_cert else None,
            cert_validity_end=expires if is_cert else None,
            cert_serial=str(rng.getrandbits(96)) if is_cert else None,
            usage=usage,
            tags=list(tags),
            environment="production",
            raw_details={
                "type": "certificate" if is_cert else "private_key",
                "format": _keystore_format(path),
                "description": subject,
            },
        ))

    # --- Configs ---
    for path, directive, proto, suite, algo, tags in _CONFIG_ENTRIES:
        findings.append(RawCryptoFinding(
            id=_stable_id("config", path, directive, str(proto), str(suite), str(algo)),
            source_type="config",
            source_location=path,
            asset_class="config",
            algorithm=algo,
            protocol=proto,
            cipher_suite=suite,
            usage="encryption",
            tags=list(tags),
            environment="production",
            raw_details={"type": "config_directive", "directive": directive},
        ))

    # --- Source ---
    for location, algo, api, key_size, usage, tags in _SOURCE_ENTRIES:
        findings.append(RawCryptoFinding(
            id=_stable_id("source", location),
            source_type="source",
            source_location=location,
            asset_class="source",
            algorithm=algo,
            key_size=key_size,
            usage=usage,
            tags=list(tags),
            environment="production",
            raw_details={"type": "api_call", "api": api},
        ))

    _assign_owners(findings, rng)
    _seed_expiry_story(findings)
    return findings


# Owning teams, matched to the subsystem tags the estate already carries. A real
# CMDB resolves these; here they are assigned so the "who do we call" gap is a
# realistic minority rather than the whole estate.
_OWNER_BY_TAG: dict[str, str] = {
    "upi": "payments-platform@tejomaya.example",
    "npci": "payments-platform@tejomaya.example",
    "payments": "payments-platform@tejomaya.example",
    "cards": "cards-engineering@tejomaya.example",
    "atm": "atm-engineering@tejomaya.example",
    "pki": "pki-team@tejomaya.example",
    "corebank": "corebank-ops@tejomaya.example",
    "channels": "identity-team@tejomaya.example",
    "infra": "platform-team@tejomaya.example",
    "rbi": "compliance@tejomaya.example",
}


def _assign_owners(findings: list[RawCryptoFinding], rng: random.Random) -> None:
    """Attach an owning team to most assets, leaving a realistic gap.

    An unowned asset cannot be scheduled - there is nobody to do the work - so
    the gap is a real operational finding rather than missing fixture data.
    Roughly one in six is left unowned, which is optimistic against reported
    practice: 53% of organisations cannot precisely quantify their inventory at
    all.
    """
    for finding in findings:
        if rng.random() < 0.17:
            continue  # deliberately orphaned
        for tag in finding.tags:
            owner = _OWNER_BY_TAG.get(tag.lower())
            if owner:
                finding.owner = owner
                break
        else:
            finding.owner = "platform-team@tejomaya.example"


def _seed_expiry_story(findings: list[RawCryptoFinding]) -> None:
    """Put one high-consequence certificate inside the critical window.

    The random draw in _cert_dates produces a realistic *distribution*, but not
    reliably on an asset anyone cares about - and "a staging box expires in nine
    days" is not the point being made. The issuing CA is chosen because
    everything beneath it inherits the outage, which is the same blast-radius
    argument the risk model makes, with a date attached instead of a forecast.
    """
    today = datetime.date.today()
    targets = {
        "Tejomaya Issuing CA - TLS": 9,
        "upi-switch.tejomaya.internal": 21,
    }
    for finding in findings:
        if not finding.cert_validity_end:
            continue
        for needle, days in targets.items():
            if needle in (finding.cert_subject or "") or needle in finding.source_location:
                expires = today + datetime.timedelta(days=days)
                finding.cert_validity_end = (
                    datetime.datetime.combine(expires, datetime.time.min).isoformat() + "Z"
                )
                break


def _keystore_format(path: str) -> str:
    if path.startswith("hsm://"):
        return "PKCS#11"
    if path.startswith("oracle://"):
        return "Oracle Wallet"
    if path.endswith(".jks"):
        return "JKS"
    if path.endswith(".p12"):
        return "PKCS#12"
    if path.endswith(".pem"):
        return "PEM"
    return "raw"


def estate_metadata() -> dict:
    return {
        "organisation": ORG_NAME,
        "description": ORG_DESCRIPTION,
        "synthetic": True,
        "disclaimer": (
            "Synthetic target estate. Every host, path and key in this dataset is "
            "fabricated. It exists so the write path - keystores, PKI, firmware "
            "signing and source scanning - can be demonstrated end to end. Findings "
            "from real endpoints come from the live TLS scan, which is a passive "
            "handshake against public infrastructure."
        ),
        "seed": SEED,
        "tls_services": len(_TLS_SERVICES),
        "keystore_entries": len(_KEYSTORE_ENTRIES),
        "config_entries": len(_CONFIG_ENTRIES),
        "source_entries": len(_SOURCE_ENTRIES),
        "total_findings": (
            len(_TLS_SERVICES) * 3
            + len(_KEYSTORE_ENTRIES)
            + len(_CONFIG_ENTRIES)
            + len(_SOURCE_ENTRIES)
        ),
    }
