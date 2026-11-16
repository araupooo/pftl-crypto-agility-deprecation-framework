/* Driver for the sphincs/sphincsplus reference implementation (FIPS 205
 * SLH-DSA-SHA2-192s; build with -DPARAMS=sphincs-sha2-192s). CLI:
 *   ref_slhdsa_driver keypair <pk_out> <sk_out>
 *   ref_slhdsa_driver sign    <sk_in> <msg_in> <sig_out>
 *   ref_slhdsa_driver verify  <pk_in> <msg_in> <sig_in>
 * verify exits 0 = VALID, 1 = INVALID, 2 = error. Pure SLH-DSA signing
 * (randomized, per FIPS 205 default: opt_rand is random).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n ? (size_t)n : 1);
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(buf); return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "cannot write %s\n", path); return -1; }
    if (len > 0 && fwrite(buf, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s keypair|sign|verify ...\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "keypair") && argc == 4) {
        uint8_t pk[CRYPTO_PUBLICKEYBYTES];
        uint8_t sk[CRYPTO_SECRETKEYBYTES];
        if (crypto_sign_keypair(pk, sk)) {
            fprintf(stderr, "keypair failed\n"); return 2;
        }
        if (write_file(argv[2], pk, sizeof pk) ||
            write_file(argv[3], sk, sizeof sk)) return 2;
        printf("keypair: pk %zu B, sk %zu B\n",
               sizeof pk, sizeof sk);
        return 0;
    }
    if (!strcmp(argv[1], "sign") && argc == 5) {
        size_t sklen, mlen;
        uint8_t *sk = read_file(argv[2], &sklen);
        uint8_t *m = read_file(argv[3], &mlen);
        if (!sk || !m) return 2;
        if (sklen != CRYPTO_SECRETKEYBYTES) {
            fprintf(stderr, "bad sk length %zu\n", sklen); return 2;
        }
        uint8_t sig[CRYPTO_BYTES];
        size_t siglen = 0;
        if (crypto_sign_signature(sig, &siglen, m, mlen, sk)) {
            fprintf(stderr, "sign failed\n"); return 2;
        }
        if (write_file(argv[4], sig, siglen)) return 2;
        printf("sign: sig %zu B over msg %zu B\n", siglen, mlen);
        return 0;
    }
    if (!strcmp(argv[1], "verify") && argc == 5) {
        size_t pklen, mlen, siglen;
        uint8_t *pk = read_file(argv[2], &pklen);
        uint8_t *m = read_file(argv[3], &mlen);
        uint8_t *sig = read_file(argv[4], &siglen);
        if (!pk || !m || !sig) return 2;
        if (pklen != CRYPTO_PUBLICKEYBYTES) {
            fprintf(stderr, "bad pk length %zu\n", pklen); return 2;
        }
        int r = crypto_sign_verify(sig, siglen, m, mlen, pk);
        printf("%s\n", r == 0 ? "VALID" : "INVALID");
        return r == 0 ? 0 : 1;
    }
    fprintf(stderr, "bad usage\n");
    return 2;
}
