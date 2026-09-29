#include <openssl/evp.h>

const EVP_CIPHER *pick(void) {
    return EVP_des_ede3_cbc();
}
