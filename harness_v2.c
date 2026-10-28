#include <stdio.h>
#include <stdlib.h>
#include <valgrind/memcheck.h>
#include "kem.h"
#include "params.h"

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 10;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES], ss_enc[CRYPTO_BYTES], ss_dec[CRYPTO_BYTES];
    int fallos = 0;

    for (int it = 0; it < iters; it++) {
        crypto_kem_keypair(pk, sk);
        crypto_kem_enc(ct, ss_enc, pk);

        /* sk = [ dk_PKE | ek | H(ek) | z ] -> solo dk_PKE y z son secretos */
        VALGRIND_MAKE_MEM_UNDEFINED(sk, KYBER_INDCPA_SECRETKEYBYTES);
        VALGRIND_MAKE_MEM_UNDEFINED(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);

        crypto_kem_dec(ss_dec, ct, sk);

        VALGRIND_MAKE_MEM_DEFINED(ss_dec, CRYPTO_BYTES);
        VALGRIND_MAKE_MEM_DEFINED(sk, CRYPTO_SECRETKEYBYTES);

        for (int i = 0; i < CRYPTO_BYTES; i++)
            if (ss_enc[i] != ss_dec[i]) { fallos++; break; }
    }
    printf("%s: %d/%d decaps correctos\n", CRYPTO_ALGNAME, iters - fallos, iters);
    return fallos != 0;
}
