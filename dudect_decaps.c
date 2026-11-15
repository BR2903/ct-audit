/* Test dudect para crypto_kem_dec (decapsulation) de ML-KEM (pq-crystals ref).
   Clave fija. Clase 0: ciphertext VÁLIDO (fail = 0).
               Clase 1: el mismo tipo de ciphertext con un byte alterado (fail = 1).
   Si decaps es constant-time, ambas clases tardan lo mismo. Si el cmov del
   implicit rejection filtra el bit 'fail', las clases se distinguen por tiempo. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define DUDECT_VISIBLITY_STATIC          /* evita choque con randombytes() de Kyber */
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "kem.h"

static uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ss[CRYPTO_BYTES];
    crypto_kem_dec(ss, data, sk);
    return ss[0];                        /* usar el resultado */
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    uint8_t ss[CRYPTO_BYTES], pos[2];
    for (size_t i = 0; i < c->number_measurements; i++) {
        uint8_t *ct = input_data + i * c->chunk_size;
        crypto_kem_enc(ct, ss, pk);      /* ciphertext válido */
        classes[i] = randombit();
        if (classes[i] == 1) {           /* invalidarlo: alterar un byte al azar */
            randombytes(pos, 2);
            ct[((pos[0] << 8) | pos[1]) % CRYPTO_CIPHERTEXTBYTES] ^= 0x01;
        }
    }
}

int main(void) {
    crypto_kem_keypair(pk, sk);
    dudect_config_t config = { .chunk_size = CRYPTO_CIPHERTEXTBYTES, .number_measurements = 2000 };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET)
        state = dudect_main(&ctx);
    dudect_free(&ctx);
    return (int)state;
}
