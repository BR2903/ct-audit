/* Harness Valgrind (técnica ctgrind) para ML-KEM de PQClean (implementación "clean").
   Compilar con -DLVL=512, 768 o 1024 e -I a la carpeta crypto_kem/ml-kem-LVL/clean.
   sk = [ dk_PKE | ek | H(ek) | z ] -> solo dk_PKE y z son secretos */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <valgrind/memcheck.h>
#include "api.h"
#include "params.h"

#define CAT3(a, b, c) a##b##c
#define XCAT3(a, b, c) CAT3(a, b, c)
#define NS(x) XCAT3(PQCLEAN_MLKEM, LVL, _CLEAN_##x)

#define PK_BYTES NS(CRYPTO_PUBLICKEYBYTES)
#define SK_BYTES NS(CRYPTO_SECRETKEYBYTES)
#define CT_BYTES NS(CRYPTO_CIPHERTEXTBYTES)
#define SS_BYTES NS(CRYPTO_BYTES)

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 10;
    uint8_t pk[PK_BYTES], sk[SK_BYTES], ct[CT_BYTES], ss_enc[SS_BYTES], ss_dec[SS_BYTES];
    int fallos = 0;

    for (int it = 0; it < iters; it++) {
        if (NS(crypto_kem_keypair)(pk, sk) != 0 || NS(crypto_kem_enc)(ct, ss_enc, pk) != 0) { fallos++; continue; }

        VALGRIND_MAKE_MEM_UNDEFINED(sk, KYBER_INDCPA_SECRETKEYBYTES);
        VALGRIND_MAKE_MEM_UNDEFINED(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);

        int r = NS(crypto_kem_dec)(ss_dec, ct, sk);

        VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
        VALGRIND_MAKE_MEM_DEFINED(ss_dec, SS_BYTES);
        VALGRIND_MAKE_MEM_DEFINED(sk, SK_BYTES);

        if (r != 0) { fallos++; continue; }
        for (int i = 0; i < SS_BYTES; i++)
            if (ss_enc[i] != ss_dec[i]) { fallos++; break; }
    }
    printf("ML-KEM-%d: %d/%d decaps correctos\n", LVL, iters - fallos, iters);
    return fallos != 0;
}
