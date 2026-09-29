/* Test fixture for the learned_function layer: a made-up ARX block cipher (Speck-like, but with
 * non-standard rotations and a round constant that appears in no signature table), plus ordinary
 * non-cryptographic code. Built static and stripped, so there are no symbols, imports or known constants.
 * Rebuild: python -m ziglang cc -target <x86_64|aarch64>-linux-musl -O2 -static -s proprietary_cipher.c
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROR(x, r) (((x) >> (r)) | ((x) << (32 - (r))))
#define ROL(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

static void key_schedule(const uint32_t k[4], uint32_t rk[27]) {
    uint32_t a = k[0], l[3] = {k[1], k[2], k[3]};
    for (uint32_t i = 0; i < 27; i++) {
        rk[i] = a;
        uint32_t t = (ROR(l[i % 3], 9) + a) ^ (i * 0x5bd1e995u + 0x2c1b3c6du);
        a = ROL(a, 5) ^ t;
        l[i % 3] = t;
    }
}

static void encrypt_block(uint32_t v[2], const uint32_t rk[27]) {
    uint32_t x = v[0], y = v[1];
    for (int i = 0; i < 27; i++) {
        x = (ROR(x, 11) + y) ^ rk[i];
        y = ROL(y, 7) ^ x;
        x ^= ROL(y, 13) & 0x9d2c5680u;
    }
    v[0] = x; v[1] = y;
}

static int parse_line(const char *s, char *key, char *val, size_t n) {
    const char *eq = strchr(s, '=');
    if (!eq || (size_t)(eq - s) >= n) return -1;
    memcpy(key, s, (size_t)(eq - s)); key[eq - s] = 0;
    strncpy(val, eq + 1, n - 1); val[n - 1] = 0;
    return 0;
}

static int count_words(const char *s) {
    int n = 0, in = 0;
    for (; *s; s++) {
        if (*s == ' ' || *s == '\t' || *s == '\n') in = 0;
        else if (!in) { in = 1; n++; }
    }
    return n;
}

int main(int argc, char **argv) {
    uint32_t k[4] = {1, 2, 3, 4}, rk[27], v[2] = {0x01234567, 0x89abcdef};
    char key[64], val[64];
    if (argc > 1 && parse_line(argv[1], key, val, sizeof key) == 0)
        printf("%s -> %s (%d words)\n", key, val, count_words(val));
    key_schedule(k, rk);
    encrypt_block(v, rk);
    printf("%08x %08x\n", v[0], v[1]);
    return 0;
}
