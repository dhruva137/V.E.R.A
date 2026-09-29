#include <openssl/evp.h>

const EVP_CIPHER *pick(void) {
    return EVP_aes_256_gcm();
}
