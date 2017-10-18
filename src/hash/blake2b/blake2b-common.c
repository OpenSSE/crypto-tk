// This is derived from supercop/crypto_hash/blake2b/xmm

/*
 BLAKE2 reference source code package - optimized C implementations
 
 Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 
 To the extent possible under law, the author(s) have dedicated all copyright
 and related and neighboring rights to this software to the public domain
 worldwide. This software is distributed without any warranty.
 
 You should have received a copy of the CC0 Public Domain Dedication along with
 this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "./blake2-config.h"

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__ ((__aligned__(x)))
#endif


#include <emmintrin.h>
#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP)
#include <x86intrin.h>
#endif

#include "./blake2b-round.h"

#include "./blake2b-common.h"

void blake2b_hash(const unsigned char *in, size_t inlen, unsigned char *out) {
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
    const __m128i r16 = _mm_setr_epi8( 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 );
    const __m128i r24 = _mm_setr_epi8( 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 );
#endif
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __m128i xmm4;
    __m128i xmm5;
    __m128i xmm6;
    __m128i xmm7;
    
    __m128i b0, b1, t0, t1;
    uint64_t ctr = 0;
    
    xmm0 = _mm_set_epi64x(0xBB67AE8584CAA73BULL, 0x6a09e667f3bcc908ULL ^ 0x0000000001010040ULL);
    xmm1 = _mm_set_epi64x(0xA54FF53A5F1D36F1ULL, 0x3C6EF372FE94F82BULL);
    xmm2 = _mm_set_epi64x(0x9B05688C2B3E6C1FULL, 0x510E527FADE682D1ULL);
    xmm3 = _mm_set_epi64x(0x5BE0CD19137E2179ULL, 0x1F83D9ABFB41BD6BULL);
    
    while(inlen > 128)
    {
#if defined(HAVE_SSE41)
        const __m128i m0 = LOADU_C( in + 00 );
        const __m128i m1 = LOADU_C( in + 16 );
        const __m128i m2 = LOADU_C( in + 32 );
        const __m128i m3 = LOADU_C( in + 48 );
        const __m128i m4 = LOADU_C( in + 64 );
        const __m128i m5 = LOADU_C( in + 80 );
        const __m128i m6 = LOADU_C( in + 96 );
        const __m128i m7 = LOADU_C( in + 112 );
#else
        const uint64_t  m0 = ( ( const uint64_t * )in )[ 0];
        const uint64_t  m1 = ( ( const uint64_t * )in )[ 1];
        const uint64_t  m2 = ( ( const uint64_t * )in )[ 2];
        const uint64_t  m3 = ( ( const uint64_t * )in )[ 3];
        const uint64_t  m4 = ( ( const uint64_t * )in )[ 4];
        const uint64_t  m5 = ( ( const uint64_t * )in )[ 5];
        const uint64_t  m6 = ( ( const uint64_t * )in )[ 6];
        const uint64_t  m7 = ( ( const uint64_t * )in )[ 7];
        const uint64_t  m8 = ( ( const uint64_t * )in )[ 8];
        const uint64_t  m9 = ( ( const uint64_t * )in )[ 9];
        const uint64_t m10 = ( ( const uint64_t * )in )[10];
        const uint64_t m11 = ( ( const uint64_t * )in )[11];
        const uint64_t m12 = ( ( const uint64_t * )in )[12];
        const uint64_t m13 = ( ( const uint64_t * )in )[13];
        const uint64_t m14 = ( ( const uint64_t * )in )[14];
        const uint64_t m15 = ( ( const uint64_t * )in )[15];
#endif
        
        const __m128i iv0 = xmm0;
        const __m128i iv1 = xmm1;
        const __m128i iv2 = xmm2;
        const __m128i iv3 = xmm3;
        
        ctr += 128;
        
        xmm4 = _mm_set_epi64x(0xBB67AE8584CAA73BULL, 0x6a09e667f3bcc908ULL);
        xmm5 = _mm_set_epi64x(0xA54FF53A5F1D36F1ULL, 0x3C6EF372FE94F82BULL);
#if defined(__x86_64__)
        xmm6 = _mm_xor_si128(_mm_cvtsi64_si128(ctr), _mm_set_epi64x(0x9B05688C2B3E6C1FULL, 0x510E527FADE682D1ULL));
#else
        xmm6 = _mm_xor_si128(_mm_set_epi64x(0, ctr), _mm_set_epi64x(0x9B05688C2B3E6C1FULL, 0x510E527FADE682D1ULL));
#endif
        xmm7 = _mm_set_epi64x(0x5BE0CD19137E2179ULL, 0x1F83D9ABFB41BD6BULL);
        
        ROUND(0);
        ROUND(1);
        ROUND(2);
        ROUND(3);
        ROUND(4);
        ROUND(5);
        ROUND(6);
        ROUND(7);
        ROUND(8);
        ROUND(9);
        ROUND(10);
        ROUND(11);
        
        xmm0 = _mm_xor_si128(xmm0, xmm4);
        xmm1 = _mm_xor_si128(xmm1, xmm5);
        xmm2 = _mm_xor_si128(xmm2, xmm6);
        xmm3 = _mm_xor_si128(xmm3, xmm7);
        
        xmm0 = _mm_xor_si128(xmm0, iv0);
        xmm1 = _mm_xor_si128(xmm1, iv1);
        xmm2 = _mm_xor_si128(xmm2, iv2);
        xmm3 = _mm_xor_si128(xmm3, iv3);
        
        in += 128;
        inlen -= 128;
    }
    
    ctr += inlen;
    
    do
    {
#if defined(HAVE_SSE41)
        __m128i m0, m1, m2, m3, m4, m5, m6, m7;
#else
        uint64_t m0, m1, m2, m3, m4, m5, m6, m7;
        uint64_t m8, m9, m10, m11, m12, m13, m14, m15;
#endif
        
        const __m128i iv0 = xmm0;
        const __m128i iv1 = xmm1;
        const __m128i iv2 = xmm2;
        const __m128i iv3 = xmm3;
        
        if(inlen & 128)
        {
#if defined(HAVE_SSE41)
            m0 = LOADU_C( in + 00 );
            m1 = LOADU_C( in + 16 );
            m2 = LOADU_C( in + 32 );
            m3 = LOADU_C( in + 48 );
            m4 = LOADU_C( in + 64 );
            m5 = LOADU_C( in + 80 );
            m6 = LOADU_C( in + 96 );
            m7 = LOADU_C( in + 112 );
#else
            m0 = ( ( const uint64_t * )in )[ 0];
            m1 = ( ( const uint64_t * )in )[ 1];
            m2 = ( ( const uint64_t * )in )[ 2];
            m3 = ( ( const uint64_t * )in )[ 3];
            m4 = ( ( const uint64_t * )in )[ 4];
            m5 = ( ( const uint64_t * )in )[ 5];
            m6 = ( ( const uint64_t * )in )[ 6];
            m7 = ( ( const uint64_t * )in )[ 7];
            m8 = ( ( const uint64_t * )in )[ 8];
            m9 = ( ( const uint64_t * )in )[ 9];
            m10 = ( ( const uint64_t * )in )[10];
            m11 = ( ( const uint64_t * )in )[11];
            m12 = ( ( const uint64_t * )in )[12];
            m13 = ( ( const uint64_t * )in )[13];
            m14 = ( ( const uint64_t * )in )[14];
            m15 = ( ( const uint64_t * )in )[15];
#endif
        }
        else
        {
            ALIGN(16) uint8_t buffer[128]  = {0};
            uint8_t *p = buffer;
            if(inlen & 64)
            {
                STORE(p + 00, LOADU_C(in + 00));
                STORE(p + 16, LOADU_C(in + 16));
                STORE(p + 32, LOADU_C(in + 32));
                STORE(p + 48, LOADU_C(in + 48));
                in += 64; p += 64;
            }
            if(inlen & 32) { STORE(p + 00, LOADU_C(in + 00)); STORE(p + 16, LOADU_C(in + 16)); in += 32; p += 32; }
            if(inlen & 16) { STORE(p + 00, LOADU_C(in + 00)); in += 16; p += 16; }
            if(inlen &  8) { *(uint64_t*)p = *(const uint64_t*)in; p += 8; in += 8; }
            if(inlen &  4) { *(uint32_t*)p = *(const uint32_t*)in; p += 4; in += 4; }
            if(inlen &  2) { *(uint16_t*)p = *(const uint16_t*)in; p += 2; in += 2; }
            if(inlen &  1) { *p = *in; }
#if defined(HAVE_SSE41)
            m0 = LOADU_C( buffer + 00 );
            m1 = LOADU_C( buffer + 16 );
            m2 = LOADU_C( buffer + 32 );
            m3 = LOADU_C( buffer + 48 );
            m4 = LOADU_C( buffer + 64 );
            m5 = LOADU_C( buffer + 80 );
            m6 = LOADU_C( buffer + 96 );
            m7 = LOADU_C( buffer + 112 );
#else
            m0 = ( ( const uint64_t * )buffer )[ 0];
            m1 = ( ( const uint64_t * )buffer )[ 1];
            m2 = ( ( const uint64_t * )buffer )[ 2];
            m3 = ( ( const uint64_t * )buffer )[ 3];
            m4 = ( ( const uint64_t * )buffer )[ 4];
            m5 = ( ( const uint64_t * )buffer )[ 5];
            m6 = ( ( const uint64_t * )buffer )[ 6];
            m7 = ( ( const uint64_t * )buffer )[ 7];
            m8 = ( ( const uint64_t * )buffer )[ 8];
            m9 = ( ( const uint64_t * )buffer )[ 9];
            m10 = ( ( const uint64_t * )buffer )[10];
            m11 = ( ( const uint64_t * )buffer )[11];
            m12 = ( ( const uint64_t * )buffer )[12];
            m13 = ( ( const uint64_t * )buffer )[13];
            m14 = ( ( const uint64_t * )buffer )[14];
            m15 = ( ( const uint64_t * )buffer )[15];
#endif
        }
        
        xmm4 = _mm_set_epi64x(0xBB67AE8584CAA73BULL, 0x6a09e667f3bcc908ULL);
        xmm5 = _mm_set_epi64x(0xA54FF53A5F1D36F1ULL, 0x3C6EF372FE94F82BULL);
#if defined(__x86_64__)
        xmm6 = _mm_xor_si128(_mm_cvtsi64_si128(ctr), _mm_set_epi64x(0x9B05688C2B3E6C1FULL, 0x510E527FADE682D1ULL));
        xmm7 = _mm_xor_si128(_mm_cvtsi64_si128(-1ULL), _mm_set_epi64x(0x5BE0CD19137E2179ULL, 0x1F83D9ABFB41BD6BULL));
#else
        xmm6 = _mm_xor_si128(_mm_set_epi64x(0, ctr), _mm_set_epi64x(0x9B05688C2B3E6C1FULL, 0x510E527FADE682D1ULL));
        xmm7 = _mm_xor_si128(_mm_set_epi64x(0, -1ULL), _mm_set_epi64x(0x5BE0CD19137E2179ULL, 0x1F83D9ABFB41BD6BULL));
#endif
        
        ROUND(0);
        ROUND(1);
        ROUND(2);
        ROUND(3);
        ROUND(4);
        ROUND(5);
        ROUND(6);
        ROUND(7);
        ROUND(8);
        ROUND(9);
        ROUND(10);
        ROUND(11);
        
        xmm0 = _mm_xor_si128(xmm0, xmm4);
        xmm1 = _mm_xor_si128(xmm1, xmm5);
        xmm2 = _mm_xor_si128(xmm2, xmm6);
        xmm3 = _mm_xor_si128(xmm3, xmm7);
        
        xmm0 = _mm_xor_si128(xmm0, iv0);
        xmm1 = _mm_xor_si128(xmm1, iv1);
        xmm2 = _mm_xor_si128(xmm2, iv2);
        xmm3 = _mm_xor_si128(xmm3, iv3);
        
    } while(0);
    
    STOREU(out + 00, xmm0);
    STOREU(out + 16, xmm1);
    STOREU(out + 32, xmm2);
    STOREU(out + 48, xmm3);
}
