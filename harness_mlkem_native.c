/* Harness Valgrind (técnica ctgrind) para mlkem-native.
   sk = [ dk_PKE (384*K bytes) | ek | H(ek) | z (32 bytes) ] -> solo dk_PKE y z son secretos */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/random.h>
#include <valgrind/memcheck.h>
#include "mlkem_native.h"

#define LVL      MLK_CONFIG_PARAMETER_SET
#define PK_BYTES MLKEM_PUBLICKEYBYTES(LVL)
#define SK_BYTES MLKEM_SECRETKEYBYTES(LVL)
#define CT_BYTES MLKEM_CIPHERTEXTBYTES(LVL)
#define DK_PKE_BYTES (384 * (LVL / 256))
#define Z_BYTES 32

/* mlkem-native requiere que la aplicación provea randombytes() */
int randombytes(uint8_t *out, size_t outlen) {
    size_t done = 0;
    while (done < outlen) {
        ssize_t r = getrandom(out + done, outlen - done, 0);
        if (r < 0) return -1;
        done += (size_t)r;
    }
    return 0;
}

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 10;
    uint8_t pk[PK_BYTES], sk[SK_BYTES], ct[CT_BYTES], ss_enc[MLKEM_BYTES], ss_dec[MLKEM_BYTES];
    int fallos = 0;

    for (int it = 0; it < iters; it++) {
        if (mlkem_keypair(pk, sk) != 0 || mlkem_enc(ct, ss_enc, pk) != 0) { fallos++; continue; }

        VALGRIND_MAKE_MEM_UNDEFINED(sk, DK_PKE_BYTES);
        VALGRIND_MAKE_MEM_UNDEFINED(sk + SK_BYTES - Z_BYTES, Z_BYTES);

        int r = mlkem_dec(ss_dec, ct, sk);

        VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
        VALGRIND_MAKE_MEM_DEFINED(ss_dec, MLKEM_BYTES);
        VALGRIND_MAKE_MEM_DEFINED(sk, SK_BYTES);

        if (r != 0) { fallos++; continue; }
        for (int i = 0; i < MLKEM_BYTES; i++)
            if (ss_enc[i] != ss_dec[i]) { fallos++; break; }
    }
    printf("ML-KEM-%d: %d/%d decaps correctos\n", LVL, iters - fallos, iters);
    return fallos != 0;
}
