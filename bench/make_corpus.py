"""Write the detection benchmark corpus: bench/corpus/<surface>/<case>/... plus truth.yaml.

    python bench/make_corpus.py        (deterministic; rewrites bench/corpus/)

Every input is written here, by us, for this benchmark: no third-party code or
binaries, so the corpus is licence-clean and can ship with the repository.

Cases are written as ordinary code an engineer would write, not as mirrors of
the detection rules. Some idioms are deliberately ones the rules may not cover
(a bare `sha256()` after `from hashlib import sha256`, `Cipher(algorithms.AES(...))`),
and every surface has decoys: crypto words in comments, strings and unrelated
identifiers, where the right answer is no finding.

Truth is exhaustive per case: each `expect` entry is one cryptographic use a
correct tool should report, by file and (for source) line. An empty `expect`
means any finding in that case is a false positive.

THE HOLD-OUT
------------
30% of cases are held out, chosen by a hash of the case id (not by hand), and
written to truth.yaml as `split: holdout`. Rules must not be tuned against
them; bench/score.py reports the two splits separately.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CORPUS = HERE / "corpus"
HOLDOUT_PERCENT = 30

sys.path.insert(0, str(ROOT / "demo" / "estate"))
from make_estate import certificate, class_file, elf_blob, oci_image, pem, rsa_key, tar_bytes, zip_bytes  # noqa: E402


def split_of(case_id: str) -> str:
    bucket = int(hashlib.sha256(case_id.encode("utf-8")).hexdigest(), 16) % 100
    return "holdout" if bucket < HOLDOUT_PERCENT else "tune"


def src(text: str) -> str:
    """Source text with a leading newline removed, so line numbers read naturally."""
    return text.lstrip("\n")


# --------------------------------------------------------------------------
# Source code: (case, files, expect). Lines are 1-based.
# --------------------------------------------------------------------------

SOURCE = {
    "python": [
        ("hashlib-md5", {"fingerprint.py": src("""
import hashlib


def fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
""")}, [("fingerprint.py", 5, "MD5")]),
        ("hashlib-new-sha1", {"legacy.py": src("""
import hashlib

digest = hashlib.new("sha1", b"payload").hexdigest()
""")}, [("legacy.py", 3, "SHA-1")]),
        ("rsa-keygen", {"keys.py": src("""
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
""")}, [("keys.py", 3, "RSA")]),
        ("ec-p256", {"sign.py": src("""
from cryptography.hazmat.primitives.asymmetric import ec

signing_key = ec.generate_private_key(ec.SECP256R1())
""")}, [("sign.py", 3, "ECDSA")]),
        ("aesgcm", {"vault.py": src("""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
box = AESGCM(key)
sealed = box.encrypt(os.urandom(12), b"secret", None)
""")}, [("vault.py", 5, "AES")]),
        ("pycryptodome-des3", {"mainframe.py": src("""
from Crypto.Cipher import DES3


def wrap(key, iv, block):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(block)
""")}, [("mainframe.py", 5, "3DES")]),
        ("jwt-rs256", {"tokens.py": src("""
import jwt


def issue(claims, private_pem):
    return jwt.encode(claims, private_pem, algorithm="RS256")
""")}, [("tokens.py", 5, "RS256")]),
        ("cipher-aes-cbc", {"storage.py": src("""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encryptor(key, iv):
    return Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
""")}, [("storage.py", 5, "AES")]),
        ("bare-sha256-import", {"checksum.py": src("""
from hashlib import sha256


def checksum(blob: bytes) -> str:
    return sha256(blob).hexdigest()
""")}, [("checksum.py", 5, "SHA-256")]),
        ("ssl-tlsv1", {"client.py": src("""
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
""")}, [("client.py", 3, "TLSv1")]),
        ("decoy-comment-and-log", {"notes.py": src("""
import logging

log = logging.getLogger(__name__)

# TODO: stop using RSA and MD5 once the partner migrates.
log.info("rotating RSA keys; md5 checks disabled")
""")}, []),
        ("decoy-identifiers", {"report.py": src("""
def describe(md5sum: str, sha1_label: str) -> str:
    return f"{md5sum.upper()} / {sha1_label}"
""")}, []),
    ],
    "java": [
        ("messagedigest-md5", {"Checksum.java": src("""
import java.security.MessageDigest;

public class Checksum {
    public static byte[] of(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
""")}, [("Checksum.java", 5, "MD5")]),
        ("rsa-keypairgenerator", {"Keys.java": src("""
import java.security.KeyPairGenerator;

public class Keys {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kpg.generateKeyPair();
    }
}
""")}, [("Keys.java", 5, "RSA")]),
        ("cipher-aes-gcm", {"Seal.java": src("""
import javax.crypto.Cipher;

public class Seal {
    Cipher cipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
""")}, [("Seal.java", 5, "AES")]),
        ("cipher-desede", {"Legacy.java": src("""
import javax.crypto.Cipher;

public class Legacy {
    Cipher cipher() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
""")}, [("Legacy.java", 5, "3DES")]),
        ("signature-sha1withrsa", {"Signer.java": src("""
import java.security.Signature;

public class Signer {
    Signature signer() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }
}
""")}, [("Signer.java", 5, "RSA")]),
        ("ec-keypair", {"EcKeys.java": src("""
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class EcKeys {
    void make() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
    }
}
""")}, [("EcKeys.java", 6, "EC")]),
        ("sslcontext-tlsv1", {"Client.java": src("""
import javax.net.ssl.SSLContext;

public class Client {
    SSLContext context() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }
}
""")}, [("Client.java", 5, "TLSv1")]),
        ("mac-hmacsha256", {"Hmac.java": src("""
import javax.crypto.Mac;

public class Hmac {
    Mac mac() throws Exception {
        return Mac.getInstance("HmacSHA256");
    }
}
""")}, [("Hmac.java", 5, "HmacSHA256")]),
        ("decoy-strings", {"Notice.java": src("""
public class Notice {
    // KeyPairGenerator.getInstance("RSA") was removed in 2024.
    static final String MESSAGE = "RSA key rotation is scheduled";
}
""")}, []),
    ],
    "go": [
        ("md5-sum", {"sum.go": src("""
package main

import "crypto/md5"

func digest(data []byte) [16]byte {
	return md5.Sum(data)
}
""")}, [("sum.go", 6, "MD5")]),
        ("rsa-generatekey", {"keys.go": src("""
package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func newKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
""")}, [("keys.go", 9, "RSA")]),
        ("ecdsa-p256", {"ec.go": src("""
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
""")}, [("ec.go", 10, "ECDSA")]),
        ("aes-newcipher", {"box.go": src("""
package main

import "crypto/aes"

func block(key []byte) {
	c, _ := aes.NewCipher(key)
	_ = c
}
""")}, [("box.go", 6, "AES")]),
        ("sha1-new", {"hash.go": src("""
package main

import "crypto/sha1"

func hasher() {
	h := sha1.New()
	_ = h
}
""")}, [("hash.go", 6, "SHA-1")]),
        ("tls-minversion-10", {"server.go": src("""
package main

import "crypto/tls"

var cfg = &tls.Config{
	MinVersion: tls.VersionTLS10,
}
""")}, [("server.go", 6, "TLS1.0")]),
        ("tripledes", {"old.go": src("""
package main

import "crypto/des"

func legacy(key []byte) {
	c, _ := des.NewTripleDESCipher(key)
	_ = c
}
""")}, [("old.go", 6, "3DES")]),
        ("ed25519", {"sig.go": src("""
package main

import (
	"crypto/ed25519"
	"crypto/rand"
)

func keys() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, _ = pub, priv
}
""")}, [("sig.go", 9, "Ed25519")]),
        ("decoy-comment", {"doc.go": src("""
package main

import "fmt"

// rsa.GenerateKey is no longer used here; see keys.go.
func main() {
	fmt.Println("md5 and sha1 are disabled")
}
""")}, []),
    ],
    "c": [
        ("rsa-generate", {"keys.c": src("""
#include <openssl/rsa.h>

int make_key(BIGNUM *e) {
    RSA *rsa = RSA_new();
    return RSA_generate_key_ex(rsa, 2048, e, NULL);
}
""")}, [("keys.c", 4, "RSA"), ("keys.c", 5, "RSA")]),
        ("md5-oneshot", {"digest.c": src("""
#include <openssl/md5.h>

void digest(const unsigned char *d, size_t n, unsigned char *out) {
    MD5(d, n, out);
}
""")}, [("digest.c", 4, "MD5")]),
        ("evp-aes-gcm", {"seal.c": src("""
#include <openssl/evp.h>

const EVP_CIPHER *pick(void) {
    return EVP_aes_256_gcm();
}
""")}, [("seal.c", 4, "AES")]),
        ("evp-3des", {"legacy.c": src("""
#include <openssl/evp.h>

const EVP_CIPHER *pick(void) {
    return EVP_des_ede3_cbc();
}
""")}, [("legacy.c", 4, "3DES")]),
        ("cipher-list-rc4", {"tls.c": src("""
#include <openssl/ssl.h>

void harden(SSL_CTX *ctx) {
    SSL_CTX_set_cipher_list(ctx, "RC4-SHA");
}
""")}, [("tls.c", 4, "RC4")]),
        ("ec-p256", {"ec.c": src("""
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

EC_KEY *make(void) {
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}
""")}, [("ec.c", 5, "EC")]),
        ("sha1-oneshot", {"sha.c": src("""
#include <openssl/sha.h>

void h(const unsigned char *d, size_t n, unsigned char *out) {
    SHA1(d, n, out);
}
""")}, [("sha.c", 4, "SHA-1")]),
        ("decoy-comment-printf", {"log.c": src("""
#include <stdio.h>

/* RSA_new() used to be called here. */
void banner(void) {
    printf("MD5 checksum disabled\\n");
}
""")}, []),
    ],
    "javascript": [
        ("createhash-md5", {"etag.js": src("""
const crypto = require('crypto');

function etag(body) {
  return crypto.createHash('md5').update(body).digest('hex');
}
""")}, [("etag.js", 4, "MD5")]),
        ("rsa-keypair", {"keys.js": src("""
const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});
""")}, [("keys.js", 3, "RSA")]),
        ("cipheriv-3des", {"legacy.js": src("""
const crypto = require('crypto');

function enc(key, iv, data) {
  const c = crypto.createCipheriv('des-ede3-cbc', key, iv);
  return Buffer.concat([c.update(data), c.final()]);
}
""")}, [("legacy.js", 4, "3DES")]),
        ("jwt-hs256", {"session.ts": src("""
import jwt from 'jsonwebtoken';

export function token(payload: object, secret: string): string {
  return jwt.sign(payload, secret, { algorithm: 'HS256' });
}
""")}, [("session.ts", 4, "HS256")]),
        ("webcrypto-ecdsa", {"sign.ts": src("""
export async function keys() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
}
""")}, [("sign.ts", 2, "ECDSA")]),
        ("cipheriv-aes-gcm", {"seal.js": src("""
const crypto = require('crypto');

function seal(key, iv) {
  return crypto.createCipheriv('aes-256-gcm', key, iv);
}
""")}, [("seal.js", 4, "AES")]),
        ("named-import-sha1", {"hash.ts": src("""
import { createHash } from 'crypto';

export const sha = (s: string) => createHash('sha1').update(s).digest('hex');
""")}, [("hash.ts", 3, "SHA-1")]),
        ("decoy-strings", {"copy.js": src("""
// crypto.createHash('md5') was replaced by SHA-256.
const label = 'RSA-2048 keys are rotated yearly';
module.exports = { label };
""")}, []),
    ],
    "rust": [
        ("ring-ecdsa", {"sign.rs": src("""
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

fn load(pkcs8: &[u8], rng: &dyn ring::rand::SecureRandom) {
    let _kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, rng);
}
""")}, [("sign.rs", 4, "ECDSA")]),
        ("rsa-crate", {"keys.rs": src("""
use rsa::RsaPrivateKey;

fn make(rng: &mut rand::rngs::OsRng) {
    let _key = RsaPrivateKey::new(rng, 2048).unwrap();
}
""")}, [("keys.rs", 4, "RSA")]),
        ("md5-compute", {"etag.rs": src("""
fn etag(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}
""")}, [("etag.rs", 2, "MD5")]),
        ("sha1-new", {"hash.rs": src("""
use sha1::{Digest, Sha1};

fn h(data: &[u8]) {
    let mut hasher = Sha1::new();
    hasher.update(data);
}
""")}, [("hash.rs", 4, "SHA-1")]),
        ("aes-gcm", {"seal.rs": src("""
use aes_gcm::{Aes256Gcm, KeyInit};

fn cipher(key: &[u8; 32]) {
    let _c = Aes256Gcm::new(key.into());
}
""")}, [("seal.rs", 4, "AES")]),
        ("decoy-comment", {"lib.rs": src("""
// RsaPrivateKey::new was the old API; md5 is not used.
pub fn version() -> &'static str {
    "rsa-free"
}
""")}, []),
    ],
    "csharp": [
        ("md5-create", {"Etag.cs": src("""
using System.Security.Cryptography;

class Etag {
    byte[] Of(byte[] d) => MD5.Create().ComputeHash(d);
}
""")}, [("Etag.cs", 4, "MD5")]),
        ("rsa-create", {"Keys.cs": src("""
using System.Security.Cryptography;

class Keys {
    RSA Make() => RSA.Create(2048);
}
""")}, [("Keys.cs", 4, "RSA")]),
        ("sha1-create", {"Hash.cs": src("""
using System.Security.Cryptography;

class Hash {
    byte[] Of(byte[] d) => SHA1.Create().ComputeHash(d);
}
""")}, [("Hash.cs", 4, "SHA-1")]),
        ("aes-create", {"Seal.cs": src("""
using System.Security.Cryptography;

class Seal {
    Aes Make() => Aes.Create();
}
""")}, [("Seal.cs", 4, "AES")]),
        ("tripledes-create", {"Legacy.cs": src("""
using System.Security.Cryptography;

class Legacy {
    TripleDES Make() => TripleDES.Create();
}
""")}, [("Legacy.cs", 4, "3DES")]),
        ("ecdsa-p256", {"Sign.cs": src("""
using System.Security.Cryptography;

class Sign {
    ECDsa Make() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
}
""")}, [("Sign.cs", 4, "ECDSA")]),
        ("decoy-string", {"Note.cs": src("""
class Note {
    // RSA.Create() was removed from this service.
    const string Text = "MD5 is not used";
}
""")}, []),
    ],
}

EXTENSION_OF = {"python": ".py", "java": ".java", "go": ".go", "c": ".c", "javascript": ".js", "rust": ".rs",
                "csharp": ".cs"}


# --------------------------------------------------------------------------
# Dependencies: (case, files, expected crypto libraries)
# --------------------------------------------------------------------------

DEPENDENCY = [
    ("pypi-requirements", {"requirements.txt": "cryptography==3.4.8\npycryptodome==3.9.0\nrequests==2.31.0\n"},
     ["cryptography", "pycryptodome"]),
    ("npm-package-lock", {"package-lock.json": json.dumps({
        "name": "api", "lockfileVersion": 3, "packages": {
            "": {"name": "api"},
            "node_modules/node-forge": {"version": "1.3.1"},
            "node_modules/jsonwebtoken": {"version": "9.0.2"},
            "node_modules/lodash": {"version": "4.17.21"}}}, indent=2)},
     ["node-forge", "jsonwebtoken"]),
    ("maven-bouncycastle", {"pom.xml": src("""
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>bank</groupId><artifactId>api</artifactId><version>1.0</version>
  <dependencies>
    <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version></dependency>
  </dependencies>
</project>
""")}, ["bcprov"]),
    ("go-mod-xcrypto", {"go.mod": "module bank/api\n\ngo 1.22\n\nrequire golang.org/x/crypto v0.17.0\n"},
     ["golang.org/x/crypto", "Go standard library"]),
    ("cargo-ring-rsa", {"Cargo.lock": src("""
version = 3

[[package]]
name = "ring"
version = "0.16.20"

[[package]]
name = "rsa"
version = "0.9.6"

[[package]]
name = "serde"
version = "1.0.200"
""")}, ["ring", "rsa"]),
    ("composer-phpseclib", {"composer.lock": json.dumps({"packages": [
        {"name": "phpseclib/phpseclib", "version": "3.0.37"},
        {"name": "monolog/monolog", "version": "3.5.0"}]}, indent=2)}, ["phpseclib"]),
    ("gemfile-openssl", {"Gemfile.lock": src("""
GEM
  remote: https://rubygems.org/
  specs:
    openssl (3.2.0)
    rack (3.0.8)

PLATFORMS
  ruby
""")}, ["openssl"]),
    ("decoy-no-crypto", {"requirements.txt": "flask==3.0.0\nnumpy==1.26.4\n"}, []),
]


# --------------------------------------------------------------------------
# Configuration: (case, files, expected algorithms or protocols)
# --------------------------------------------------------------------------

CONFIG = [
    ("nginx-tlsv1", {"nginx.conf": "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n"},
     ["TLSv1", "TLSv1.2"]),
    ("nginx-rc4", {"nginx.conf": "server {\n  listen 443 ssl;\n  ssl_ciphers RC4-SHA;\n}\n"}, ["RC4"]),
    ("sshd-weak-kex", {"sshd_config": "KexAlgorithms diffie-hellman-group1-sha1\n"}, ["DH"]),
    ("sshd-3des", {"sshd_config": "Ciphers 3des-cbc\n"}, ["3DES"]),
    ("openssl-cnf-minprotocol", {"openssl.cnf": src("""
openssl_conf = default_conf

[default_conf]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1
""")}, ["TLSv1"]),
    ("strongswan-modp1024", {"ipsec.conf": src("""
conn branch
    keyexchange=ikev2
    ike=aes128-sha1-modp1024!
""")}, ["AES", "HMAC", "DH"]),
    ("terraform-kms-rsa", {"main.tf": src("""
resource "aws_kms_key" "signing" {
  description              = "token signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
}
""")}, ["RSA"]),
    ("decoy-plain-http", {"nginx.conf": "server {\n  listen 80;\n  location / { proxy_pass http://app; }\n}\n"}, []),
]


# --------------------------------------------------------------------------
# SSH recordings: (case, probe, expected algorithms)
# --------------------------------------------------------------------------

SSH = [
    ("ssh-legacy-kex", {"target": "10.9.0.1:22", "banner": "SSH-2.0-OpenSSH_7.4",
                        "kex_algorithms": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
                        "server_host_key_algorithms": ["ssh-rsa"],
                        "encryption_algorithms_client_to_server": ["aes128-cbc"],
                        "encryption_algorithms_server_to_client": ["aes128-cbc"]},
     ["DH", "DH", "RSA"]),
    ("ssh-modern", {"target": "10.9.0.2:22", "banner": "SSH-2.0-OpenSSH_9.9",
                    "kex_algorithms": ["mlkem768x25519-sha256", "curve25519-sha256"],
                    "server_host_key_algorithms": ["ssh-ed25519"],
                    "encryption_algorithms_client_to_server": ["chacha20-poly1305@openssh.com"],
                    "encryption_algorithms_server_to_client": ["chacha20-poly1305@openssh.com"]},
     ["ML-KEM", "X25519", "Ed25519"]),
]


# --------------------------------------------------------------------------
# Binaries (built with the demo estate's deterministic helpers)
# --------------------------------------------------------------------------

def _aes_sbox() -> bytes:
    """The full 256-byte AES S-box, computed (multiplicative inverse in GF(2^8), then the affine map)."""
    def mul(a: int, b: int) -> int:
        out = 0
        while b:
            if b & 1:
                out ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return out

    box = []
    for x in range(256):
        inv = next((y for y in range(1, 256) if mul(x, y) == 1), 0) if x else 0
        s = inv
        for shift in range(1, 5):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        box.append(s ^ 0x63)
    return bytes(box)


def _binary_cases() -> list[tuple[str, dict[str, bytes], list[str]]]:
    aes_sbox = _aes_sbox()
    sha256_k = bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5")
    cert = pem(certificate("corpus.example", rsa_key("bench-corpus-cert"), serial=0x5EED))
    return [
        ("openssl-banner", {"ledgerd": elf_blob(b"OpenSSL 1.1.1w  11 Sep 2023")}, ["OpenSSL"]),
        ("aes-sbox", {"sealer": elf_blob(aes_sbox)}, ["AES"]),
        ("sha256-constants", {"hasher": elf_blob(sha256_k)}, ["SHA-256"]),
        ("embedded-certificate", {"agent": elf_blob(cert)}, ["RSA"]),
        ("jar-keypairgenerator", {"signer.jar": zip_bytes({
            "com/bank/Signer.class": class_file(["java/security/KeyPairGenerator"], ["RSA"])})}, ["RSA"]),
        ("decoy-plain-elf", {"tool": elf_blob(b"hello from an ordinary program")}, []),
    ]


def _container_cases(case_dir: Path) -> list[tuple[str, str, list[str]]]:
    base = {"var/lib/dpkg/status": b"Package: libssl1.1\nStatus: install ok installed\nVersion: 1.1.1w-0+deb11u1\n\n"}
    app = {"etc/nginx/nginx.conf": b"server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.1;\n}\n"}
    out = []
    for case, layers, expect in (
        ("dpkg-openssl-and-tls-config", [base, app], ["OpenSSL", "TLSv1.1"]),
        ("decoy-no-crypto", [{"srv/index.html": b"<h1>hello</h1>\n"}], []),
    ):
        path = case_dir / case
        path.mkdir(parents=True, exist_ok=True)
        oci_image(path / "image.oci.tar", f"corpus/{case}:1", layers, {})
        out.append((case, "image.oci.tar", expect))
    return out


# --------------------------------------------------------------------------
# Writer
# --------------------------------------------------------------------------

def _write(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8", newline="\n")


def main() -> int:
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    surfaces: dict[str, list[dict]] = {}

    for language, cases in SOURCE.items():
        for case, files, expect in cases:
            case_id = f"source/{language}/{case}"
            for name, text in files.items():
                _write(CORPUS / case_id / name, text)
            surfaces.setdefault("source", []).append({
                "id": case_id, "language": language, "split": split_of(case_id), "path": case_id,
                "expect": [{"file": f, "line": line, "name": name} for f, line, name in expect]})

    for case, files, expect in DEPENDENCY:
        case_id = f"dependency/{case}"
        for name, text in files.items():
            _write(CORPUS / case_id / name, text)
        surfaces.setdefault("dependency", []).append({
            "id": case_id, "split": split_of(case_id), "path": case_id,
            "expect": [{"library": lib} for lib in expect]})

    for case, files, expect in CONFIG:
        case_id = f"config/{case}"
        for name, text in files.items():
            _write(CORPUS / case_id / name, text)
        surfaces.setdefault("config", []).append({
            "id": case_id, "split": split_of(case_id), "path": case_id,
            "expect": [{"name": n} for n in expect]})

    for case, probe, expect in SSH:
        case_id = f"ssh/{case}"
        _write(CORPUS / case_id / "ssh.json", json.dumps({"source": "ssh", "synthetic": True, "probes": [probe]},
                                                        indent=2))
        surfaces.setdefault("ssh", []).append({
            "id": case_id, "split": split_of(case_id), "path": f"{case_id}/ssh.json",
            "expect": [{"name": n} for n in expect]})

    for case, files, expect in _binary_cases():
        case_id = f"binary/{case}"
        for name, data in files.items():
            _write(CORPUS / case_id / name, data)
        surfaces.setdefault("binary", []).append({
            "id": case_id, "split": split_of(case_id), "path": case_id,
            "expect": [{"name": n} for n in expect]})

    for case, image, expect in _container_cases(CORPUS / "container"):
        case_id = f"container/{case}"
        surfaces.setdefault("container", []).append({
            "id": case_id, "split": split_of(case_id), "path": f"{case_id}/{image}",
            "expect": [{"name": n} for n in expect]})

    for surface, cases in surfaces.items():
        _write(CORPUS / surface / "truth.yaml", yaml.safe_dump(
            {"surface": surface, "holdout_percent": HOLDOUT_PERCENT, "cases": cases},
            sort_keys=False, allow_unicode=True))
    total = sum(len(c) for c in surfaces.values())
    held = sum(1 for c in surfaces.values() for case in c if case["split"] == "holdout")
    print(f"wrote {total} cases ({held} held out) under {CORPUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
