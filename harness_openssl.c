/* Harness Valgrind (técnica ctgrind) para el ML-KEM nativo de OpenSSL (crypto/ml_kem/ml_kem.c).
   Usa la API interna ossl_ml_kem_*; compilar con -DLVL=512, 768 o 1024 y enlazar contra
   ml_kem.c (compilado con el compilador/flags bajo prueba) + libcrypto.a (compilada una vez).
   Secretos de la clave: el vector s (rank escalares de 256 x uint16) y z (32 bytes). */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "crypto/ml_kem.h"

#define CAT(a, b) a##b
#define XCAT(a, b) CAT(a, b)
#define EVP_TYPE XCAT(EVP_PKEY_ML_KEM_, LVL)
#define SCALAR_BYTES (ML_KEM_DEGREE * sizeof(uint16_t))

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 10;
    int fallos = 0;
    uint8_t pk[2048], ct[2048], ss_enc[32], ss_dec[32];

    for (int it = 0; it < iters; it++) {
        ML_KEM_KEY *key = ossl_ml_kem_key_new(NULL, NULL, EVP_TYPE);
        if (key == NULL) { fallos++; continue; }
        const ML_KEM_VINFO *v = key->vinfo;
        if (!ossl_ml_kem_genkey(pk, v->pubkey_bytes, key)
            || !ossl_ml_kem_encap_rand(ct, v->ctext_bytes, ss_enc, sizeof(ss_enc), key)) {
            fallos++; ossl_ml_kem_key_free(key); continue;
        }
        size_t s_bytes = (size_t)v->rank * SCALAR_BYTES;

        VALGRIND_MAKE_MEM_UNDEFINED(key->s, s_bytes);
        VALGRIND_MAKE_MEM_UNDEFINED(key->z, ML_KEM_RANDOM_BYTES);

        int r = ossl_ml_kem_decap(ss_dec, sizeof(ss_dec), ct, v->ctext_bytes, key);

        VALGRIND_MAKE_MEM_DEFINED(&r, sizeof r);
        VALGRIND_MAKE_MEM_DEFINED(ss_dec, sizeof(ss_dec));
        VALGRIND_MAKE_MEM_DEFINED(key->s, s_bytes);
        VALGRIND_MAKE_MEM_DEFINED(key->z, ML_KEM_RANDOM_BYTES);

        if (r != 1 || memcmp(ss_enc, ss_dec, sizeof(ss_dec)) != 0) fallos++;
        ossl_ml_kem_key_free(key);
    }
    printf("ML-KEM-%d: %d/%d decaps correctos\n", LVL, iters - fallos, iters);
    return fallos != 0;
}
