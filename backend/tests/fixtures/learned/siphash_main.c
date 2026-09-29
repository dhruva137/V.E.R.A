/* Test fixture: SipHash-2-4 (github.com/veorq/SipHash, CC0) behind a small CLI, built static and stripped.
 * SipHash is a keyed ARX PRF with no table constants, so only the learned_function layer can see it.
 * Rebuild: python -m ziglang cc -target <x86_64|aarch64>-linux-musl -O2 -static -s siphash_main.c siphash.c
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "siphash.h"

int main(int argc, char **argv) {
    uint8_t key[16] = {0}, out[8];
    const char *msg = argc > 1 ? argv[1] : "hello";
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    siphash(msg, strlen(msg), key, out, sizeof out);
    for (int i = 0; i < 8; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}
