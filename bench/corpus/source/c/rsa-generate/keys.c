#include <openssl/rsa.h>

int make_key(BIGNUM *e) {
    RSA *rsa = RSA_new();
    return RSA_generate_key_ex(rsa, 2048, e, NULL);
}
