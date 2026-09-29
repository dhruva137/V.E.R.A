#include <openssl/md5.h>

void digest(const unsigned char *d, size_t n, unsigned char *out) {
    MD5(d, n, out);
}
