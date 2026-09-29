"""Phase A7: build the end-to-end set of small static programs, stripped and unstripped.

Each program links one library behind a tiny main. It is built static for x86-64 and AArch64, once with symbols
(ground truth) and once stripped with `zig objcopy --strip-all` from the same link, so addresses match. Ground
truth per program:
    contains_crypto   the program performs a cryptographic primitive (SQLite does: ChaCha20 in its PRNG)
    train_overlap     the library is in the detector's TRAIN split (reported separately: not independent)

    python build_cli.py      -> research/e2e/bin/<name>_<arch>{,.stripped}
"""
from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "indicrypt_bench" / "src"
FIX = HERE.parents[1] / "backend" / "tests" / "fixtures" / "learned"
BIN = HERE / "bin"
ZIG = [sys.executable, "-m", "ziglang"]
RNG_STUB = "void randombytes(unsigned char *x, unsigned long long n){ while(n--) *x++ = (unsigned char)n; }\n"

PROGRAMS = {
    # name: (contains_crypto, train_overlap, sources, include dirs, defines, main)
    "aes_tiny": (True, True, ["tiny-aes/aes.c"], ["tiny-aes"], ["AES256=1"],
                 '#include "aes.h"\n#include <stdio.h>\nint main(){uint8_t k[32]={1},b[16]={2};struct AES_ctx c;'
                 'AES_init_ctx(&c,k);AES_ECB_encrypt(&c,b);printf("%02x\\n",b[0]);return 0;}'),
    "sha256_bcon": (True, True, ["bcon/sha256.c"], ["bcon"], [],
                    '#include "sha256.h"\n#include <stdio.h>\n#include <string.h>\nint main(int c,char**v){SHA256_CTX x;BYTE h[32];'
                    'const char*m=c>1?v[1]:"abc";sha256_init(&x);sha256_update(&x,(const BYTE*)m,strlen(m));sha256_final(&x,h);printf("%02x\\n",h[0]);return 0;}'),
    "md5_bcon": (True, True, ["bcon/md5.c"], ["bcon"], [],
                 '#include "md5.h"\n#include <stdio.h>\n#include <string.h>\nint main(int c,char**v){MD5_CTX x;BYTE h[16];'
                 'const char*m=c>1?v[1]:"abc";md5_init(&x);md5_update(&x,(const BYTE*)m,strlen(m));md5_final(&x,h);printf("%02x\\n",h[0]);return 0;}'),
    "des_bcon": (True, True, ["bcon/des.c"], ["bcon"], [],
                 '#include "des.h"\n#include <stdio.h>\nint main(){BYTE k[8]={1},in[8]={2},out[8];BYTE s[16][6];'
                 'des_key_setup(k,s,DES_ENCRYPT);des_crypt(in,out,s);printf("%02x\\n",out[0]);return 0;}'),
    "rc4_bcon": (True, True, ["bcon/arcfour.c"], ["bcon"], [],
                 '#include "arcfour.h"\n#include <stdio.h>\nint main(){BYTE st[256],k[5]={1,2,3,4,5},o[16];'
                 'arcfour_key_setup(st,k,5);arcfour_generate_stream(st,o,16);printf("%02x\\n",o[0]);return 0;}'),
    "blowfish_bcon": (True, True, ["bcon/blowfish.c"], ["bcon"], [],
                      '#include "blowfish.h"\n#include <stdio.h>\nint main(){BYTE k[8]={1},in[8]={2},out[8];BLOWFISH_KEY ks;'
                      'blowfish_key_setup(k,&ks,8);blowfish_encrypt(in,out,&ks);printf("%02x\\n",out[0]);return 0;}'),
    "monocypher": (True, False, ["monocypher/src/monocypher.c"], ["monocypher/src"], [],
                   '#include "monocypher.h"\n#include <stdio.h>\nint main(){uint8_t k[32]={1},n[24]={0},m[64]={0},c[64],h[64];'
                   'crypto_chacha20_x(c,m,64,k,n,0);crypto_blake2b(h,64,c,64);printf("%02x\\n",h[0]);return 0;}'),
    "tweetnacl": (True, False, ["tweetnacl/tweetnacl.c"], ["tweetnacl"], [],
                  '#include "tweetnacl.h"\n#include <stdio.h>\n' + RNG_STUB + 'int main(){unsigned char pk[32],sk[32];'
                  'crypto_box_keypair(pk,sk);printf("%02x\\n",pk[0]);return 0;}'),
    "microecc": (True, False, ["micro-ecc/uECC.c"], ["micro-ecc"], [],
                 '#include "uECC.h"\n#include <stdio.h>\nstatic int rng(uint8_t*d,unsigned s){while(s--)*d++=(uint8_t)(s*7+1);return 1;}'
                 'int main(){uint8_t pub[64],priv[32];uECC_set_rng(rng);uECC_make_key(pub,priv,uECC_secp256r1());printf("%02x\\n",pub[0]);return 0;}'),
    "siphash": (True, False, ["siphash/siphash.c"], ["siphash"], [],
                '#include "siphash.h"\n#include <stdio.h>\n#include <string.h>\nint main(int c,char**v){unsigned char k[16]={0},o[8];'
                'const char*m=c>1?v[1]:"abc";siphash(m,strlen(m),k,o,8);printf("%02x\\n",o[0]);return 0;}'),
    "mlkem768": (True, False, [f"pqclean/crypto_kem/ml-kem-768/clean/{f}.c" for f in
                               ("cbd", "indcpa", "kem", "ntt", "poly", "polyvec", "reduce", "symmetric-shake", "verify")]
                 + ["pqclean/common/fips202.c"], ["pqclean/crypto_kem/ml-kem-768/clean", "pqclean/common"], [],
                 '#include "api.h"\n#include <stdio.h>\n#include <stddef.h>\n#include <stdint.h>\n'
                 'int PQCLEAN_randombytes(uint8_t*o,size_t n){while(n--)*o++=(uint8_t)n;return 0;}'
                 'int main(){static uint8_t pk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES],sk[PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES];'
                 'PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk,sk);printf("%02x\\n",pk[0]);return 0;}'),
    "mldsa44": (True, False, [f"pqclean/crypto_sign/ml-dsa-44/clean/{f}.c" for f in
                              ("ntt", "packing", "poly", "polyvec", "reduce", "rounding", "sign", "symmetric-shake")]
                + ["pqclean/common/fips202.c"], ["pqclean/crypto_sign/ml-dsa-44/clean", "pqclean/common"], [],
                '#include "api.h"\n#include <stdio.h>\n#include <stddef.h>\n#include <stdint.h>\n'
                'int PQCLEAN_randombytes(uint8_t*o,size_t n){while(n--)*o++=(uint8_t)n;return 0;}'
                'int main(){static uint8_t pk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES],sk[PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES];'
                'PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk,sk);printf("%02x\\n",pk[0]);return 0;}'),
    "proprietary_arx": (True, False, [str(FIX / "proprietary_cipher.c")], [], [], None),
    "sqlite_chacha": (True, False, ["sqlite/sqlite3.c"], ["sqlite"], ["SQLITE_THREADSAFE=0", "SQLITE_OMIT_LOAD_EXTENSION"],
                      '#include "sqlite3.h"\n#include <stdio.h>\nint main(){sqlite3*d;sqlite3_open(":memory:",&d);'
                      'sqlite3_exec(d,"create table t(x); insert into t values(random());",0,0,0);sqlite3_close(d);puts("ok");return 0;}'),
    # ---- non-crypto
    "zlib": (False, True, [f"zlib/{f}.c" for f in ("adler32", "crc32", "deflate", "inflate", "inffast", "inftrees", "trees", "zutil", "compress", "uncompr")],
             ["zlib"], [], '#include "zlib.h"\n#include <stdio.h>\nint main(){unsigned char s[64]="hello hello hello",d[128];uLongf n=128;'
             'compress(d,&n,s,64);printf("%lu\\n",n);return 0;}'),
    "lz4": (False, False, ["lz4/lib/lz4.c"], ["lz4/lib"], [],
            '#include "lz4.h"\n#include <stdio.h>\nint main(){char s[64]="aaaaaaaaaaaaaaaabbbbbbbb",d[128];int n=LZ4_compress_default(s,d,64,128);printf("%d\\n",n);return 0;}'),
    "cjson": (False, True, ["cjson/cJSON.c"], ["cjson"], [],
              '#include "cJSON.h"\n#include <stdio.h>\nint main(){cJSON*j=cJSON_Parse("{\\"a\\":[1,2,3]}");char*s=cJSON_Print(j);puts(s);return 0;}'),
    "xxhash": (False, False, ["xxhash/xxhash.c"], ["xxhash"], [],
               '#include "xxhash.h"\n#include <stdio.h>\n#include <string.h>\nint main(int c,char**v){const char*m=c>1?v[1]:"abc";'
               'printf("%llx\\n",(unsigned long long)XXH3_64bits(m,strlen(m)));return 0;}'),
    "kissfft": (False, False, ["kissfft/kiss_fft.c"], ["kissfft"], ["FIXED_POINT=32"],
                '#include "kiss_fft.h"\n#include <stdio.h>\nint main(){kiss_fft_cpx in[64]={{1,0}},out[64];kiss_fft_cfg c=kiss_fft_alloc(64,0,0,0);'
                'kiss_fft(c,in,out);printf("%d\\n",(int)out[1].r);return 0;}'),
    "miniz": (False, False, ["miniz/miniz.c", "miniz/miniz_tdef.c", "miniz/miniz_tinfl.c"], ["miniz", "../extra/miniz"], ["MINIZ_NO_ARCHIVE_APIS", "MINIZ_NO_STDIO"],
              '#include "miniz.h"\n#include <stdio.h>\nint main(){unsigned char s[64]="hello hello",d[128];mz_ulong n=128;mz_compress(d,&n,s,64);printf("%lu\\n",n);return 0;}'),
    "yyjson": (False, False, ["yyjson/src/yyjson.c"], ["yyjson/src"], [],
               '#include "yyjson.h"\n#include <stdio.h>\nint main(){yyjson_doc*d=yyjson_read("[1,2,3]",7,0);printf("%d\\n",(int)yyjson_arr_size(yyjson_doc_get_root(d)));return 0;}'),
    "lodepng": (False, False, [str(HERE.parent / "indicrypt_bench" / "extra" / "lodepng_impl.c")], ["lodepng"], [],
                '#include "lodepng.h"\n#include <stdio.h>\nint main(){unsigned char px[16]={255};unsigned char*o;size_t n;'
                'lodepng_encode32(&o,&n,px,2,2);printf("%zu\\n",n);return 0;}'),
    "stb_image": (False, False, [str(HERE.parent / "indicrypt_bench" / "extra" / "stb_image_impl.c")], ["stb"], [],
                  '#include "stb_image.h"\n#include <stdio.h>\nint main(int c,char**v){int w,h,n;unsigned char*p=stbi_load(c>1?v[1]:"x.png",&w,&h,&n,0);'
                  'printf("%d\\n",p?w:-1);return 0;}'),
    "lua": (False, True, [f"lua/{f}.c" for f in ("lapi", "lauxlib", "lbaselib", "lcode", "lcorolib", "lctype", "ldblib", "ldebug", "ldo",
                                                  "ldump", "lfunc", "lgc", "linit", "liolib", "llex", "lmathlib", "lmem", "loadlib",
                                                  "lobject", "lopcodes", "loslib", "lparser", "lstate", "lstring", "lstrlib", "ltable",
                                                  "ltablib", "ltm", "lundump", "lutf8lib", "lvm", "lzio")],
            ["lua"], [], '#include "lua.h"\n#include "lauxlib.h"\n#include "lualib.h"\nint main(){lua_State*L=luaL_newstate();luaL_openlibs(L);'
            'luaL_dostring(L,"print(1+1)");lua_close(L);return 0;}'),
}


def build(job):
    name, arch = job
    crypto, overlap, srcs, incs, defs, main = PROGRAMS[name]
    BIN.mkdir(exist_ok=True)
    files = [s if Path(s).is_absolute() else str(SRC / s) for s in srcs]
    if main is not None:
        mf = BIN / f"{name}_main.c"
        mf.write_text(main + "\n")
        files.append(str(mf))
    out = BIN / f"{name}_{arch}"
    cmd = ZIG + ["cc", "-target", f"{arch}-linux-musl", "-O2", "-static", "-w", "-fno-sanitize=all", "-g0"]
    cmd += [f"-I{SRC / i}" for i in incs] + [f"-D{d}" for d in defs] + files + ["-o", str(out)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        return name, arch, False, p.stderr[-300:]
    # Stripped twin: the same deterministic link with -s (zig objcopy cannot strip every image), so addresses match.
    s = subprocess.run(cmd[:-1] + [str(out) + ".stripped", "-s"], capture_output=True, text=True)
    return name, arch, s.returncode == 0, s.stderr[-200:]


def main():
    only = set(sys.argv[1:])
    jobs = [(n, a) for n in PROGRAMS for a in ("x86_64", "aarch64") if not only or n in only]
    with ThreadPoolExecutor(4) as pool:
        res = list(pool.map(build, jobs))
    old = json.loads((HERE / "manifest.json").read_text()) if (HERE / "manifest.json").exists() else {}
    manifest = old | {f"{n}_{a}": {"contains_crypto": PROGRAMS[n][0], "train_overlap": PROGRAMS[n][1], "ok": ok, "error": err if not ok else ""}
                for n, a, ok, err in res}
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(sum(v["ok"] for v in manifest.values()), "of", len(manifest), "built")
    for k, v in manifest.items():
        if not v["ok"]:
            print("FAILED", k, v["error"])


if __name__ == "__main__":
    main()
