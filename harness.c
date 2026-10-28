#include <stdio.h>
#include <valgrind/memcheck.h>
#include "kem.h"
#include "params.h"

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES], ss_enc[CRYPTO_BYTES], ss_dec[CRYPTO_BYTES];

    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss_enc, pk);

    /* sk = [ indcpa_sk | pk | H(pk) | z ]  -> solo indcpa_sk y z son secretos */
    VALGRIND_MAKE_MEM_UNDEFINED(sk, KYBER_INDCPA_SECRETKEYBYTES);
    VALGRIND_MAKE_MEM_UNDEFINED(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES);

    crypto_kem_dec(ss_dec, ct, sk);

    /* declasificar la salida antes de usarla */
    VALGRIND_MAKE_MEM_DEFINED(ss_dec, CRYPTO_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(sk, CRYPTO_SECRETKEYBYTES);

    int ok = 1;
    for (int i = 0; i < CRYPTO_BYTES; i++) ok &= (ss_enc[i] == ss_dec[i]);
    printf("Shared secrets %s\n", ok ? "coinciden" : "NO coinciden");
    return !ok;
}
