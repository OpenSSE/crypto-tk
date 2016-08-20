
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
#if __AES__                /* Defined by gcc/clang when compiling for AES-NI */
/* ------------------------------------------------------------------------- */

#include <stdint.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#define block __m128i

/* ------------------------------------------------------------------------- */
#elif __ARM_FEATURE_CRYPTO
/* ------------------------------------------------------------------------- */

#include <arm_neon.h>
#define block uint8x16_t

/* ------------------------------------------------------------------------- */
#else
#error - This implementation requires __AES__ or __ARM_FEATURE_CRYPTO
#endif
/* ------------------------------------------------------------------------- */

typedef struct {
    block I[3];    /* 1I,2I,4I */
    block J[3];    /* 1J,2J,4J */
    block L;
    block delta3_cache;
} aez_ctx_t;



void aez_setup(const unsigned char *key, unsigned keylen, aez_ctx_t *ctx);
void aez_encrypt(aez_ctx_t *ctx, const char *n, unsigned nbytes,
                 const char *ad, unsigned adbytes, unsigned abytes,
                 const char *src, unsigned bytes, char *dst);
int aez_decrypt(aez_ctx_t *ctx, const char *n, unsigned nbytes,
                 const char *ad, unsigned adbytes, unsigned abytes,
                 const char *src, unsigned bytes, char *dst);

#ifdef __cplusplus
}
#endif