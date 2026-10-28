/* Test dudect para poly_frommsg de Kyber (ref).
   Clase 0: mensaje fijo (todo ceros)   Clase 1: mensaje aleatorio
   Si la función es constant-time, ambas clases tardan lo mismo. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#include "params.h"
#include "poly.h"

#define MSG_BYTES KYBER_INDCPA_MSGBYTES   /* 32 bytes = 256 bits */

uint8_t do_one_computation(uint8_t *data) {
    poly p;
    poly_frommsg(&p, data);
    return (uint8_t)p.coeffs[0];          /* usar el resultado para que no se elimine */
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(input_data, c->number_measurements * c->chunk_size);
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0)
            memset(input_data + i * c->chunk_size, 0x00, c->chunk_size);
    }
}

int main(void) {
    dudect_config_t config = { .chunk_size = MSG_BYTES, .number_measurements = 10000 };
    dudect_ctx_t ctx;
    dudect_init(&ctx, &config);
    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET)
        state = dudect_main(&ctx);
    dudect_free(&ctx);
    return (int)state;
}
