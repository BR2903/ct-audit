/* Test dudect para la decapsulation del ML-KEM nativo de OpenSSL (crypto/ml_kem/ml_kem.c).
   Mismo diseño que dudect_decaps.c (pq-crystals):
   Clave fija. Clase 0: ciphertext VÁLIDO (fail = 0).
               Clase 1: el mismo tipo de ciphertext con un bit alterado (fail = 1).
   Versión de duración fija: mide hasta que la detenga timeout.
   Compilar con -DLVL=512, 768 o 1024 y enlazar ml_kem.c + libcrypto.a. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define DUDECT_VISIBLITY_STATIC
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "crypto/ml_kem.h"

#define CAT(a, b) a##b
#define XCAT(a, b) CAT(a, b)
#define EVP_TYPE XCAT(EVP_PKEY_ML_KEM_, LVL)

static ML_KEM_KEY *key;
static size_t ct_bytes;

uint8_t do_one_computation(uint8_t *data) {
    uint8_t ss[32];
    ossl_ml_kem_decap(ss, sizeof(ss), data, ct_bytes, key);
    return ss[0];
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    uint8_t ss[32], pos[2];
    for (size_t i = 0; i < c->number_measurements; i++) {
        uint8_t *ct = input_data + i * c->chunk_size;
        ossl_ml_kem_encap_rand(ct, ct_bytes, ss, sizeof(ss), key);   /* ciphertext válido */
        classes[i] = randombit();
        if (classes[i] == 1) {                                        /* invalidarlo: alterar un bit */
            randombytes(pos, 2);
            ct[((pos[0] << 8) | pos[1]) % ct_bytes] ^= 0x01;
        }
    }
}

int main(void) {
    uint8_t pk[2048];
    key = ossl_ml_kem_key_new(NULL, NULL, EVP_TYPE);
    if (key == NULL || !ossl_ml_kem_genkey(pk, key->vinfo->pubkey_bytes, key)) {
        fprintf(stderr, "No se pudo generar la clave\n");
        return 1;
    }
    ct_bytes = key->vinfo->ctext_bytes;
    dudect_config_t config = { .chunk_size = ct_bytes, .number_measurements = 2000 };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    for (;;)
        dudect_main(&ctx);
    return 0;
}
