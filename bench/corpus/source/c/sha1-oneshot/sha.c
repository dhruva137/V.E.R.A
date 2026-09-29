#include <openssl/sha.h>

void h(const unsigned char *d, size_t n, unsigned char *out) {
    SHA1(d, n, out);
}
