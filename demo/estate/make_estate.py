"""Generate the VERA demo estate: every surface the PS names, for one synthetic bank.

WHAT THIS IS
------------
A deterministic, synthetic estate for "Tejomaya Bank" (the same fictional bank
as demo/vault) that exercises every scan surface in SIH26164:

    repos/        source in Java, Go, C, Python, TypeScript, C#, Rust + manifests and lockfiles
    configs/      nginx, HAProxy, openssl.cnf, java.security, sshd_config, strongSwan, Terraform
    images/       two OCI images (base + app layers, a whiteout, a baked-in key, a real JAR)
    captures/     recorded TLS and SSH observations of the bank's endpoints
    keymanager/   a small KMIP export with a retired signing key
    estate.yaml   the bank's own register: systems, hosts, exposure, criticality, data classes

Drift is planted on purpose so the engine has something true to find: a
gateway that negotiates TLS 1.0 and 3DES although its nginx config forbids
both; a ledger built against OpenSSL 3.0.8 that ships a 1.1.1w binary; code
that generates RSA-3072 while RSA-2048 is deployed; a retired KMIP key still
serving; an expired certificate still served; a bastion whose sshd_config
lists ML-KEM but whose daemon does not offer it; an "internal" ledger that
answers on a public address.

NOTHING HERE IS REAL
--------------------
Hosts use example/internal names and the RFC 5737 documentation ranges
(203.0.113.0/24) for "public" addresses. Binaries are synthetic byte blobs
with the markers a scanner reads, not executables. Private-key files contain
only a PEM marker and filler, never a key. Certificates are generated here
from fixed seeds so every run is byte-identical: RSA keys come from seeded
primes, and PKCS#1 v1.5 signatures are deterministic.

Run:  python demo/estate/make_estate.py
"""

from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import random
import shutil
import struct
import tarfile
import textwrap
import zipfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parent
VAULT = OUT.parent / "vault"
EPOCH = dt.datetime(2025, 1, 1, tzinfo=dt.timezone.utc)
RECORDED_AT = "2026-09-22T09:30:00Z"


# --------------------------------------------------------------------------
# Deterministic RSA keys and certificates
# --------------------------------------------------------------------------


def _is_probable_prime(n: int, rng: random.Random) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(24):
        x = pow(rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(candidate, rng):
            return candidate


def rsa_key(seed: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    rng = random.Random(hashlib.sha256(seed.encode()).digest())
    e = 65537
    while True:
        p, q = _prime(bits // 2, rng), _prime(bits // 2, rng)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            break
    d = pow(e, -1, phi)
    public = rsa.RSAPublicNumbers(e, p * q)
    return rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), public).private_key()


def certificate(common_name: str, key: rsa.RSAPrivateKey, *, issuer_name: str | None = None,
                issuer_key: rsa.RSAPrivateKey | None = None, serial: int, days: int = 3650,
                ca: bool = False) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tejomaya Bank"),
                         x509.NameAttribute(NameOID.COUNTRY_NAME, "IN")])
    issuer = subject if issuer_name is None else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Tejomaya Bank"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN")])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(EPOCH).not_valid_after(EPOCH + dt.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return builder.sign(issuer_key or key, hashes.SHA256())


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def public_key_sha256(key) -> str:
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


# --------------------------------------------------------------------------
# Synthetic binaries, class files, archives
# --------------------------------------------------------------------------

AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
DES_S1 = bytes([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11,
                9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11,
                3, 14, 10, 0, 6, 13])


def elf_blob(*markers: bytes, size: int = 65536) -> bytes:
    """A synthetic ELF-shaped blob carrying the byte markers a scanner reads. Not executable."""
    data = bytearray(b"\x7fELF\x02\x01\x01" + b"\x00" * (size - 7))
    offset = 4096
    for marker in markers:
        data[offset:offset + len(marker)] = marker
        offset += len(marker) + 4096
    return bytes(data)


def class_file(class_refs: list[str], strings: list[str]) -> bytes:
    pool: list[bytes] = []

    def utf8(text: str) -> int:
        raw = text.encode()
        pool.append(b"\x01" + struct.pack(">H", len(raw)) + raw)
        return len(pool)

    for name in class_refs:
        pool.append(b"\x07" + struct.pack(">H", utf8(name)))
    for text in strings:
        pool.append(b"\x08" + struct.pack(">H", utf8(text)))
    tail = struct.pack(">HHHHHHH", 0x21, 1, 1, 0, 0, 0, 0)
    return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, len(pool) + 1) + b"".join(pool) + tail


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            z.writestr(info, data)
    return buf.getvalue()


def tar_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def oci_image(path: Path, ref: str, layers: list[dict[str, bytes]], labels: dict) -> str:
    def digest(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()

    blobs, descs, diff_ids = {}, [], []
    for files in layers:
        raw = tar_bytes(files)
        blob = gzip.compress(raw, mtime=0)
        blobs[digest(blob)] = blob
        diff_ids.append(digest(raw))
        descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(blob),
                      "size": len(blob)})
    config = json.dumps({"architecture": "amd64", "os": "linux", "config": {"Labels": labels},
                         "rootfs": {"type": "layers", "diff_ids": diff_ids}}, sort_keys=True).encode()
    blobs[digest(config)] = config
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                      "digest": digest(config), "size": len(config)},
                           "layers": descs}, sort_keys=True).encode()
    blobs[digest(manifest)] = manifest
    index = json.dumps({"schemaVersion": 2, "manifests": [{
        "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest(manifest),
        "size": len(manifest), "annotations": {"org.opencontainers.image.ref.name": ref}}]}, sort_keys=True).encode()
    files = {"oci-layout": b'{"imageLayoutVersion": "1.0.0"}', "index.json": index}
    files.update({f"blobs/sha256/{d.split(':')[1]}": b for d, b in blobs.items()})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(tar_bytes(files))
    return digest(manifest)


KEY_MARKER = b"-----BEGIN EC PRIVATE KEY-----\n(synthetic marker only; no key)\n-----END EC PRIVATE KEY-----\n"


# --------------------------------------------------------------------------
# Repositories
# --------------------------------------------------------------------------

REPOS = {
    "payments-gateway/src/main/java/in/tejomaya/pay/CardVault.java": """
        package in.tejomaya.pay;

        import java.security.*;
        import java.security.spec.RSAKeyGenParameterSpec;
        import javax.crypto.Cipher;
        import javax.net.ssl.SSLContext;

        public class CardVault {
            // Legacy card-data envelope, kept for the 2014 settlement format.
            public byte[] seal(byte[] pan, Key key) throws Exception {
                Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                return cipher.doFinal(pan);
            }

            public KeyPair signingKey() throws Exception {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
                return kpg.generateKeyPair();
            }

            public byte[] signReceipt(PrivateKey key, byte[] receipt) throws Exception {
                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initSign(key);
                signature.update(receipt);
                return signature.sign();
            }

            public SSLContext legacyAcquirerLink() throws Exception {
                return SSLContext.getInstance("TLSv1");
            }

            public Cipher configured(String transformation) throws Exception {
                return Cipher.getInstance(transformation);
            }
        }
        """,
    "payments-gateway/pom.xml": """
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>in.tejomaya</groupId>
          <artifactId>payments-gateway</artifactId>
          <version>4.2.0</version>
          <properties>
            <maven.compiler.release>17</maven.compiler.release>
            <bc.version>1.78</bc.version>
          </properties>
          <dependencies>
            <dependency>
              <groupId>org.bouncycastle</groupId>
              <artifactId>bcprov-jdk18on</artifactId>
              <version>${bc.version}</version>
            </dependency>
            <dependency>
              <groupId>io.jsonwebtoken</groupId>
              <artifactId>jjwt-api</artifactId>
              <version>0.12.5</version>
            </dependency>
          </dependencies>
        </project>
        """,
    "payments-gateway/settlement/main.go": """
        package main

        import (
            "crypto/mlkem"
            "crypto/rand"
            "crypto/rsa"
            "crypto/tls"
        )

        func main() {
            key, _ := rsa.GenerateKey(rand.Reader, 2048)
            _ = key
            acquirer := &tls.Config{MinVersion: tls.VersionTLS10}
            _ = acquirer
            // PQC pilot: ML-KEM for the settlement batch envelope.
            dk, _ := mlkem.GenerateKey768()
            _ = dk
        }
        """,
    "payments-gateway/settlement/go.mod": """
        module tejomaya.example/settlement

        go 1.22

        toolchain go1.22.5

        require golang.org/x/crypto v0.24.0
        """,
    "core-ledger/src/ledger_crypto.c": """
        #include <openssl/rsa.h>
        #include <openssl/evp.h>
        #include <openssl/ssl.h>

        /* Batch signing key for end-of-day ledger files. */
        RSA *ledger_signing_key(void) {
            RSA *rsa = RSA_new();
            BIGNUM *e = BN_new();
            BN_set_word(e, RSA_F4);
            RSA_generate_key_ex(rsa, 1024, e, NULL);
            return rsa;
        }

        const EVP_CIPHER *archive_cipher(void) { return EVP_des_ede3_cbc(); }
        const EVP_MD *legacy_checksum(void) { return EVP_md5(); }

        void ledger_tls(SSL_CTX *ctx) {
            SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
            SSL_CTX_set_cipher_list(ctx, "DES-CBC3-SHA:ECDHE-RSA-AES256-GCM-SHA384");
        }
        """,
    "core-ledger/conanfile.txt": """
        [requires]
        openssl/3.0.8
        zlib/1.3.1

        [generators]
        CMakeDeps
        """,
    "core-ledger/tools/reconcile.py": """
        import hashlib
        from cryptography.hazmat.primitives.asymmetric import rsa

        def file_checksum(data: bytes) -> str:
            return hashlib.md5(data).hexdigest()

        def checksum(data: bytes, algorithm: str) -> str:
            return hashlib.new(algorithm, data).hexdigest()

        REPORT_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        """,
    "core-ledger/tools/requirements.txt": """
        cryptography==41.0.7
        pycryptodome==3.20.0
        rsa==4.9
        """,
    "mobile-api/src/auth.ts": """
        import crypto from "crypto";
        import jwt from "jsonwebtoken";
        import { ml_kem768 } from "@noble/post-quantum/ml-kem";

        export function issueSession(userId: string, key: crypto.KeyObject): string {
          return jwt.sign({ sub: userId }, key, { algorithm: "RS256", expiresIn: "15m" });
        }

        export function deviceFingerprint(input: string): string {
          return crypto.createHash("md5").update(input).digest("hex");
        }

        export function newDeviceKey() {
          return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
        }

        export async function webSigningKey() {
          return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
        }

        // PQC pilot for the device-binding handshake.
        export function pilotKem() {
          return ml_kem768.keygen();
        }
        """,
    "mobile-api/package.json": """
        {
          "name": "mobile-api",
          "version": "3.8.1",
          "dependencies": {
            "jsonwebtoken": "^9.0.2",
            "node-forge": "^1.3.1",
            "elliptic": "^6.5.4",
            "@noble/post-quantum": "^0.2.1"
          }
        }
        """,
    "mobile-api/package-lock.json": json.dumps({
        "name": "mobile-api", "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"jsonwebtoken": "^9.0.2", "node-forge": "^1.3.1", "elliptic": "^6.5.4",
                                  "@noble/post-quantum": "^0.2.1"}},
            "node_modules/jsonwebtoken": {"version": "9.0.2"},
            "node_modules/node-forge": {"version": "1.3.1"},
            "node_modules/elliptic": {"version": "6.5.4"},
            "node_modules/@noble/post-quantum": {"version": "0.2.1"},
            "node_modules/ms": {"version": "2.1.3"},
        }}, indent=2),
    "customer-portal/Services/TokenService.cs": """
        using System.Security.Authentication;
        using System.Security.Cryptography;

        namespace Tejomaya.Portal.Services;

        public class TokenService
        {
            private readonly RSA _signer = RSA.Create(2048);
            public byte[] LegacyHash(byte[] data) => SHA1.HashData(data);
            public SslProtocols PartnerProtocols => SslProtocols.Tls11;
            public MLKem PilotKem() => MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        }
        """,
    "customer-portal/Portal.csproj": """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <PropertyGroup>
            <TargetFramework>net8.0</TargetFramework>
          </PropertyGroup>
          <ItemGroup>
            <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="7.5.1" />
            <PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" />
          </ItemGroup>
        </Project>
        """,
    "customer-portal/infra/main.tf": """
        resource "aws_kms_key" "portal_token_signing" {
          description              = "Portal session token signing"
          customer_master_key_spec = "RSA_2048"
          key_usage                = "SIGN_VERIFY"
        }

        resource "aws_kms_key" "portal_pq_pilot" {
          description = "ML-DSA pilot for document signing"
          key_spec    = "ML_DSA_65"
          key_usage   = "SIGN_VERIFY"
        }

        resource "aws_acm_certificate" "portal" {
          domain_name   = "portal.tejomaya.example"
          key_algorithm = "EC_prime256v1"
        }

        resource "aws_lb_listener" "portal_https" {
          port       = 443
          protocol   = "HTTPS"
          ssl_policy = "ELBSecurityPolicy-2016-08"
        }
        """,
    "customer-portal/pqc-pilot/src/lib.rs": """
        use ml_kem::MlKem768;
        use ring::signature::EcdsaKeyPair;

        pub fn pilot_keys(rng: &mut impl rand_core::CryptoRngCore) {
            let (dk, ek) = MlKem768::generate(rng);
            let _ = (dk, ek);
        }

        pub fn legacy_signer(pkcs8: &[u8]) {
            let _ = EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8);
        }
        """,
    "customer-portal/pqc-pilot/Cargo.lock": """
        version = 3

        [[package]]
        name = "ml-kem"
        version = "0.2.1"

        [[package]]
        name = "ring"
        version = "0.17.8"
        """,
}

CONFIGS = {
    "payments-gateway/nginx.conf": """
        server {
            listen 443 ssl;
            server_name pay.tejomaya.example;
            ssl_protocols TLSv1.2 TLSv1.3;
            ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!3DES:!RC4:!aNULL;
            ssl_ecdh_curve X25519:prime256v1;
        }
        """,
    "payments-gateway/java.security": """
        jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, MD5withRSA, \\
            DH keySize < 1024, EC keySize < 224, anon, NULL
        """,
    "core-ledger/openssl.cnf": """
        openssl_conf = default_conf

        [system_default_sect]
        MinProtocol = TLSv1.2
        Groups = X25519:P-256
        """,
    "mobile-api/haproxy.cfg": """
        global
            ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA
            ssl-default-bind-options ssl-min-ver TLSv1.0 no-tls-tickets

        frontend mobile
            bind :443 ssl crt /etc/haproxy/mobile.pem curves X25519:P-256
        """,
    "ops-bastion/sshd_config": """
        Port 22
        ListenAddress 10.20.0.5
        KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,diffie-hellman-group14-sha256
        HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
        Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
        MACs hmac-sha2-256-etm@openssh.com
        """,
    "branch-vpn/ipsec.conf": """
        conn branch-to-dc
            left=%defaultroute
            right=vpn.tejomaya.internal
            ike=aes128-sha1-modp1024!
            esp=3des-md5!
        """,
    "branch-vpn/swanctl.conf": """
        connections {
          dc-pilot {
            proposals = aes256-sha384-x25519-ke1_mlkem768
            children { core { esp_proposals = aes256gcm16-x25519-ke1_mlkem768 } }
          }
        }
        """,
}


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def _write(rel: str, content: str | bytes) -> None:
    path = OUT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")


def _vault_certificates() -> dict[str, object]:
    """The vault's certificates as the vault collector reports them, by subject CN.

    Captures reuse their exact serial, issuer and validity, which is what makes
    a recorded handshake and a keystore entry resolve to one asset.
    """
    import sys

    sys.path.insert(0, str(OUT.parents[1] / "backend"))
    from collectors.vault_collector import scan_vault

    findings, errors = scan_vault(VAULT)
    if errors:
        raise SystemExit(f"vault could not be read: {errors}")
    return {f.cert_subject.split(",")[0].removeprefix("CN="): f for f in findings if f.cert_serial}


def _tls_cert_finding(host: str, peer_ip: str, *, subject: str, issuer: str, serial: str, algorithm: str,
                      key_size: int, not_before: str, not_after: str, public_key: str | None = None) -> dict:
    details = {"type": "certificate", "peer_ip": peer_ip, "chain_trusted": True, "trust_error": None}
    if public_key:
        details["public_key_sha256"] = public_key
    return {"id": f"cap-cert-{host}", "source_type": "tls", "source_location": host,
            "asset_class": "tls_certificate", "algorithm": algorithm, "key_size": key_size, "protocol": "TLSv1.2",
            "signature_algorithm": "sha256WithRSAEncryption" if algorithm == "RSA" else "ecdsa-with-SHA256",
            "cert_subject": subject, "cert_issuer": issuer, "cert_validity_start": not_before,
            "cert_validity_end": not_after, "cert_serial": serial, "usage": "signing",
            "tags": ["live-scan"], "environment": "production", "raw_details": details}


def _tls_session(host: str, peer_ip: str, protocol: str, suite: str, kex: str | None, hybrid: str) -> list[dict]:
    out = [{"id": f"cap-suite-{host}", "source_type": "tls", "source_location": host,
            "asset_class": "tls_cipher_suite", "protocol": protocol, "cipher_suite": suite,
            "usage": "encryption", "tags": ["live-scan"], "environment": "production",
            "raw_details": {"type": "cipher_suite", "peer_ip": peer_ip}}]
    if kex:
        out.append({"id": f"cap-kex-{host}", "source_type": "tls", "source_location": host,
                    "asset_class": "tls_key_exchange", "protocol": protocol, "key_exchange": kex,
                    "usage": "key_exchange", "tags": ["live-scan"], "environment": "production",
                    "raw_details": {"type": "key_exchange", "peer_ip": peer_ip, "hybrid_status": hybrid}})
    return out


def main() -> None:
    for sub in ("repos", "configs", "images", "captures", "keymanager"):
        shutil.rmtree(OUT / sub, ignore_errors=True)

    for rel, text in REPOS.items():
        _write(f"repos/{rel}", text)
    for rel, text in CONFIGS.items():
        _write(f"configs/{rel}", text)

    # Certificates -----------------------------------------------------------
    root_keys = [rsa_key(f"tejomaya-root-{i}", 2048) for i in range(3)]
    roots = [certificate(f"Tejomaya Demo Root {i + 1}", k, serial=1000 + i, ca=True, days=7300)
             for i, k in enumerate(root_keys)]
    corp_root = certificate("Tejomaya Corporate Root 2026", rsa_key("corp-root"), serial=2026, ca=True, days=7300)
    gw_key = rsa_key("pay-gateway-leaf")
    gw_cert = certificate("pay.tejomaya.example", gw_key, issuer_name="Tejomaya Demo Root 1",
                          issuer_key=root_keys[0], serial=0x5A11, days=500)
    partner_key = rsa_key("partner-signing-2019")

    # Images -----------------------------------------------------------------
    bcprov = zip_bytes({"META-INF/maven/org.bouncycastle/bcprov-jdk18on/pom.properties":
                        b"groupId=org.bouncycastle\nartifactId=bcprov-jdk18on\nversion=1.78\n"})
    gateway_jar = zip_bytes({
        "in/tejomaya/pay/CardVault.class": class_file(
            ["in/tejomaya/pay/CardVault", "javax/crypto/Cipher", "java/security/Signature",
             "java/security/KeyPairGenerator"],
            ["DESede/CBC/PKCS5Padding", "SHA1withRSA", "RSA"]),
        "BOOT-INF/lib/bcprov-jdk18on-1.78.jar": bcprov,
    })
    debian_base = {
        "etc/ssl/certs/ca-certificates.crt": b"".join(pem(r) for r in roots),
        "etc/ssl/openssl.cnf": b"[system_default_sect]\nMinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2\n",
        "var/lib/dpkg/status": (b"Package: libssl3\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\n\n"
                                b"Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\n\n"
                                b"Package: openjdk-17-jre-headless\nStatus: install ok installed\n"
                                b"Version: 17.0.12+7-2~deb12u1\n"),
        "usr/lib/x86_64-linux-gnu/libssl.so.3": elf_blob(b"OpenSSL 3.0.11 19 Sep 2023"),
        "etc/ssl/private/build.key": KEY_MARKER,
    }
    gateway_app = {
        "etc/ssl/private/.wh.build.key": b"",
        "usr/local/share/ca-certificates/corp-root.crt": pem(corp_root),
        "app/payments-gateway.jar": gateway_jar,
        "app/config/signing.key": KEY_MARKER,
        "app/requirements.txt": b"cryptography==41.0.7\n",
    }
    images = {
        "payments-gateway": oci_image(OUT / "images" / "payments-gateway.oci.tar", "tejomaya/payments-gateway:4.2.0",
                                      [debian_base, gateway_app], {"team": "payments"}),
    }
    alpine_base = {
        "lib/apk/db/installed": b"P:libssl3\nV:3.1.4-r5\n\nP:libcrypto3\nV:3.1.4-r5\n\nP:musl\nV:1.2.4-r2\n",
        "etc/ssl/cert.pem": b"".join(pem(r) for r in roots[:2]),
        "usr/lib/libcrypto.so.3": elf_blob(b"OpenSSL 3.1.4 24 Oct 2023"),
    }
    ledger_app = {
        "usr/local/bin/ledgerd": elf_blob(b"OpenSSL 1.1.1w  11 Sep 2023", AES_SBOX, DES_S1),
        "etc/ledger/sshd_config": b"KexAlgorithms diffie-hellman-group14-sha1,curve25519-sha256\n",
    }
    images["core-ledger"] = oci_image(OUT / "images" / "core-ledger.oci.tar", "tejomaya/core-ledger:12.1",
                                      [alpine_base, ledger_app], {"team": "ledger"})

    # Key manager with a retired signing key --------------------------------
    _write("keymanager/manifest.json", json.dumps({
        "vault": "Tejomaya partner key manager (demo)", "synthetic": True, "key_material_present": False,
        "sources": [{"file": "kmip.json", "provenance": "declared", "confidence": 0.85,
                     "proves": "Managed object attributes and lifecycle state.", "cannot_prove": "Use."}]},
        indent=2))
    _write("keymanager/kmip.json", json.dumps({
        "source": "kmip", "collected_at": "2026-09-01T09:00:00Z",
        "endpoint": "kmip://partner-km.tejomaya.internal:5696", "protocol_version": "2.1",
        "note": "Attributes only; no Get operation for key material was issued.",
        "objects": [{
            "Unique Identifier": "PKM-0019", "Name": "partner-signing-2019", "Object Type": "Private Key",
            "Cryptographic Algorithm": "RSA", "Cryptographic Length": 2048,
            "Cryptographic Usage Mask": ["Sign"], "State": "Deactivated",
            "Initial Date": "2019-04-02T09:00:00Z", "Activation Date": "2019-04-10T09:00:00Z",
            "Deactivation Date": "2025-12-31T00:00:00Z", "Object Group": "partner-signing",
            "Protection Storage Mask": ["Software"], "Fresh": False,
            "public_key_sha256": public_key_sha256(partner_key)}]}, indent=2))

    # Captures -----------------------------------------------------------------
    vault = _vault_certificates()

    def from_vault(cn: str, host: str, peer_ip: str) -> dict:
        held = vault[cn]
        return _tls_cert_finding(
            host, peer_ip, subject=held.cert_subject, issuer=held.cert_issuer, serial=held.cert_serial,
            algorithm=held.algorithm, key_size=held.key_size, not_before=str(held.cert_validity_start),
            not_after=str(held.cert_validity_end))

    tls_findings = [
        # payments-gateway: config forbids TLS 1.0 and 3DES; the wire says otherwise (D1, D2).
        _tls_cert_finding("pay.tejomaya.example:443", "203.0.113.20", subject=gw_cert.subject.rfc4514_string(),
                          issuer=gw_cert.issuer.rfc4514_string(), serial=str(gw_cert.serial_number),
                          algorithm="RSA", key_size=2048, not_before=gw_cert.not_valid_before_utc.isoformat(),
                          not_after=gw_cert.not_valid_after_utc.isoformat(), public_key=public_key_sha256(gw_key)),
        *_tls_session("pay.tejomaya.example:443", "203.0.113.20", "TLSv1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                      None, "unknown"),
        # core-ledger: declared internal, answers on a public address (D8).
        from_vault("ledger-core.tejomaya.internal", "ledger-core.tejomaya.internal:443", "203.0.113.30"),
        *_tls_session("ledger-core.tejomaya.internal:443", "203.0.113.30", "TLSv1.2",
                      "ECDHE-RSA-AES256-GCM-SHA384", "X25519", "unknown"),
        # messaging: the held certificate expired on 2026-09-19 and is still served (D6).
        from_vault("mq-broker.tejomaya.internal", "mq-broker.tejomaya.internal:5671", "10.30.1.12"),
        *_tls_session("mq-broker.tejomaya.internal:5671", "10.30.1.12", "TLSv1.2",
                      "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "unknown"),
        # corebank-api: the same certificate the keystore holds (held + observed corroboration).
        from_vault("corebank-api.tejomaya.internal", "corebank-api.tejomaya.internal:8443", "10.30.2.40"),
        *_tls_session("corebank-api.tejomaya.internal:8443", "10.30.2.40", "TLSv1.3",
                      "TLS_AES_256_GCM_SHA384", "X25519", "unknown"),
        from_vault("upi-switch.tejomaya.internal", "upi-switch.tejomaya.internal:443", "10.30.2.51"),
        # partner-gateway: presents a certificate for the key the key manager retired (D5).
        _tls_cert_finding("partner-gateway.tejomaya.internal:443", "10.30.4.8",
                          subject="CN=partner-gateway.tejomaya.internal,O=Tejomaya Bank,C=IN",
                          issuer="CN=Tejomaya Issuing CA - Services,O=Tejomaya Bank,C=IN", serial="1911",
                          algorithm="RSA", key_size=2048, not_before="2019-04-10T00:00:00+00:00",
                          not_after="2027-04-10T00:00:00+00:00", public_key=public_key_sha256(partner_key)),
        # customer-portal: already negotiates the hybrid group.
        *_tls_session("portal.tejomaya.example:443", "203.0.113.41", "TLSv1.3", "TLS_AES_128_GCM_SHA256",
                      "X25519MLKEM768", "supported"),
    ]
    _write("captures/tls.json", json.dumps({
        "source": "tls", "collected_at": RECORDED_AT, "synthetic": True,
        "note": "Recorded handshakes of the demo bank's endpoints (synthetic).", "findings": tls_findings},
        indent=2))
    _write("captures/ssh.json", json.dumps({
        "source": "ssh", "collected_at": RECORDED_AT, "synthetic": True,
        "probes": [
            {"target": "10.20.0.5:22", "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
             "kex_algorithms": ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
                                "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "kex-strict-s-v00@openssh.com"],
             "server_host_key_algorithms": ["rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519"],
             "encryption_server_to_client": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
             "mac_server_to_client": ["hmac-sha2-256-etm@openssh.com", "hmac-sha1"]},
            {"target": "git.tejomaya.internal:22", "banner": "SSH-2.0-OpenSSH_10.0p2",
             "kex_algorithms": ["mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256"],
             "server_host_key_algorithms": ["ssh-ed25519", "ecdsa-sha2-nistp256"],
             "encryption_server_to_client": ["aes256-gcm@openssh.com"],
             "mac_server_to_client": ["hmac-sha2-512-etm@openssh.com"]},
        ]}, indent=2))

    print(f"estate written to {OUT}")
    for name, digest in images.items():
        print(f"  image {name}: {digest}")


if __name__ == "__main__":
    main()
