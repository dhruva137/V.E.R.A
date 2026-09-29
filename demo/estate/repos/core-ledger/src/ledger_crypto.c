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
