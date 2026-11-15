/* Test dudect para crypto_kem_dec (decapsulation) de ML-KEM de PQClean ("clean").
   Mismo diseño que dudect_decaps.c (pq-crystals):
   Clave fija. Clase 0: ciphertext VÁLIDO (fail = 0).
               Clase 1: el mismo tipo de ciphertext con un bit alterado (fail = 1).
   Versión de duración fija: mide hasta que la detenga timeout (no se detiene al primer cruce).
   Compilar con -DLVL=512, 768 o 1024 e -I a crypto_kem/ml-kem-LVL/clean y a common. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define DUDECT_VISIBLITY_STATIC
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "api.h"

#define CAT3(a, b, c) a##b##c
#define XCAT3(a, b, c) CAT3(a, b, c)
#define NS(x) XCAT3(PQCLEAN_MLKEM, LVL, _CLEAN_##x)
#define PK_BYTES NS(CRYPTO_PUBLICKEYBYTES)
#define SK_BYTES NS(CRYPTO_SECRETKEYBYTES)
#define CT_BYTES NS(CRYPTO_CIPHERTEXTBYTES)
#define SS_BYTES NS(CRYPTO_BYTES)

static uint8_t pk[PK_BYTES], sk[SK_BYTES];

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ss[SS_BYTES];
    NS(crypto_kem_dec)(ss, data, sk);
    return ss[0];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    uint8_t ss[SS_BYTES], pos[2];
    for (size_t i = 0; i < c->number_measurements; i++) {
        uint8_t *ct = input_data + i * c->chunk_size;
        NS(crypto_kem_enc)(ct, ss, pk);          /* ciphertext válido */
        classes[i] = randombit();
        if (classes[i] == 1) {                   /* invalidarlo: alterar un bit */
            randombytes(pos, 2);
            ct[((pos[0] << 8) | pos[1]) % CT_BYTES] ^= 0x01;
        }
    }
}

int main(void) {
    NS(crypto_kem_keypair)(pk, sk);
    dudect_config_t config = { .chunk_size = CT_BYTES, .number_measurements = 2000 };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    for (;;)
        dudect_main(&ctx);
    return 0;
}
