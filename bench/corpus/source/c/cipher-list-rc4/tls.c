#include <openssl/ssl.h>

void harden(SSL_CTX *ctx) {
    SSL_CTX_set_cipher_list(ctx, "RC4-SHA");
}
