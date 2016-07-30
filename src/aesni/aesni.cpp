//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2016 Raphael Bost
//
// This file is part of libsse_crypto.
//
// libsse_crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// libsse_crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with libsse_crypto.  If not, see <http://www.gnu.org/licenses/>.
//


#include "aesni.hpp"

namespace sse
{
    
    namespace crypto
    {
        
        extern __inline__ uint64_t rdtsc(void) {
            uint64_t a, d;
            __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
            return (d<<32) | a;
        }
        
        uint64_t tick_counter = 0;
    }
}

#if USE_AESNI

#pragma message "Use AES NI"

#include <iostream>
#include <iomanip>
#include <cstring>

namespace sse
{
    
    namespace crypto
    {
        
        
//#define KEYEXP_128(K, I, Rcon) \
//I = _mm_aeskeygenassist_si128(K, Rcon); \
//K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
//K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
//K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
//I = _mm_shuffle_epi32(I, 0xFF); \
//K = _mm_xor_si128(K,I);
        

#define KEYEXP_128(K, I, Rcon) \
I = _mm_shuffle_epi8(K, mask) ; \
R = _mm_set_epi32(Rcon,Rcon,Rcon,Rcon) ; \
I = _mm_aesenclast_si128(I, R); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
I = _mm_shuffle_epi32(I, 0xFF); \
K = _mm_xor_si128(K,I);
        
// same as the above macro, but without the first call to aeskeygenassist
// this should improve pipelining
        
#define FINISH_EXP128(K, I) \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
I = _mm_shuffle_epi32(I, 0xFF); \
K = _mm_xor_si128(K,I);

//#define DOUBLE_KEYEXP_128(K1, K2, I2 Rcon) \
//I2 = _mm_aeskeygenassist_si128(K1, Rcon); \
//K2 = _mm_xor_si128(K, _mm_slli_si128(K2, 4)); \
//K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
//K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
//I = _mm_shuffle_epi32(I, 0xFF); \
//K = _mm_xor_si128(K,I);
        
        
        
        aes_subkeys_type aesni_derive_subkeys(const uint8_t* key)
        {
            aes_subkeys_type subkeys;
                        
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+0, K);

            // for each round, derive a new subkey (un rolled)
            
            KEYEXP_128(K, I, 0x01);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+1, K);
            
            KEYEXP_128(K, I, 0x02);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+2, K);

            KEYEXP_128(K, I, 0x04);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+3, K);
            
            KEYEXP_128(K, I, 0x08);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+4, K);
            
            KEYEXP_128(K, I, 0x10);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+5, K);
            
            KEYEXP_128(K, I, 0x20);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+6, K);
            
            KEYEXP_128(K, I, 0x40);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+7, K);
            
            KEYEXP_128(K, I, 0x80);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+8, K);

            KEYEXP_128(K, I, 0x1B);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+9, K);


            KEYEXP_128(K, I, 0x36);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+10, K);
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);

            return subkeys;
        }
        
        void aesni_encrypt(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            uint64_t now =  rdtsc();

            // XOR it to the state
            state = _mm_xor_si128(state, SK);

            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            state = _mm_aesenc_si128(state, SK);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            state = _mm_aesenclast_si128(state, SK);

            tick_counter += rdtsc() - now;

            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state);

        }

        void aesni_encrypt2(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            uint64_t now =  rdtsc();

            // XOR it to the state
            state1 = _mm_xor_si128(state1, SK);
            state2 = _mm_xor_si128(state2, SK);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            state1 = _mm_aesenc_si128(state1, SK);
            state2 = _mm_aesenc_si128(state2, SK);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            state1 = _mm_aesenclast_si128(state1, SK);
            state2 = _mm_aesenclast_si128(state2, SK);
            
            tick_counter += rdtsc() - now;

            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            
        }


#define ENCRYPT_ROUND_1(K, I, S1, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K);

#define ENCRYPT_ROUND_1_LAST(K, I, S1) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K);

        void pipeline_encrypt1(const uint8_t* in, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            
            // ROUND 0
            
            uint64_t now =  rdtsc();
            
            // XOR it to the state
            state1 = _mm_xor_si128(state1, K);
            state2 = _mm_xor_si128(state2, K);
            
            ENCRYPT_ROUND_1(K, I, state1, 0x01);
            ENCRYPT_ROUND_1(K, I, state1, 0x02);
            ENCRYPT_ROUND_1(K, I, state1, 0x04);
            ENCRYPT_ROUND_1(K, I, state1, 0x08);
            ENCRYPT_ROUND_1(K, I, state1, 0x10);
            ENCRYPT_ROUND_1(K, I, state1, 0x20);
            ENCRYPT_ROUND_1(K, I, state1, 0x40);
            ENCRYPT_ROUND_1(K, I, state1, 0x80);
            ENCRYPT_ROUND_1(K, I, state1, 0x1b);
            ENCRYPT_ROUND_1_LAST(K, I, state1);
            
            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            
        }
        
        
#define ENCRYPT_ROUND_2(K, I, S1, S2, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K);
        
#define ENCRYPT_ROUND_2_LAST(K, I, S1, S2) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K);
        
        void pipeline_encrypt2(const uint8_t* in, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            
            // ROUND 0
            
            uint64_t now =  rdtsc();
            
            // XOR it to the state
            state1 = _mm_xor_si128(state1, K);
            state2 = _mm_xor_si128(state2, K);
            
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x01);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x02);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x04);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x08);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x10);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x20);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x40);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x80);
            ENCRYPT_ROUND_2(K, I, state1, state2, 0x1b);
            ENCRYPT_ROUND_2_LAST(K, I, state1, state2);
            
            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            
        }

        
        
//#define ENCRYPT_ROUND_1_FIRST(K1, I1, K2, I2 , S1) \
//I2 = K1; \
//I2 = _mm_shuffle_epi8(I2, mask) ; \
//R = _mm_set_epi32(0x01,0x01,0x01,0x01) ; \
//I2 = _mm_aesenclast_si128(I2, R); \
//S1 = _mm_xor_si128(S1, K1); \
//K2 = K1; \
//FINISH_EXP128(K2,I2);
//        
//#define ENCRYPT_ROUND_1(K1, I1, K2, I2 , S1, Rcon) \
//I2 = K1; \
//I2 = _mm_shuffle_epi8(I2, mask) ; \
//R = _mm_set_epi32(Rcon,Rcon,Rcon,Rcon) ; \
//I2 = _mm_aesenclast_si128(I2, R); \
//S1 = _mm_aesenc_si128(S1, K1); \
//K2 = K1; \
//FINISH_EXP128(K2,I2);
//        
//        
//#define ENCRYPT_ROUND_1_LAST(K, S1) \
//S1 = _mm_aesenclast_si128(S1, K);
//        
//        void pipeline_encrypt1(const uint8_t* in, const uint8_t* key, uint8_t *out)
//        {
//            __m128i K1, K2, I1, I2, mask, R;
//            
//            // load the key in the first SSE register
//            K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
//            
//            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
//            
//            // load the input
//            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
//            
//            ENCRYPT_ROUND_1_FIRST(K1, I1, K2, I2, state1);
//            ENCRYPT_ROUND_1(K2, I2, K1, I1, state1, 0x02);
//            ENCRYPT_ROUND_1(K1, I1, K2, I2, state1, 0x04);
//            ENCRYPT_ROUND_1(K2, I2, K1, I1, state1, 0x08);
//            ENCRYPT_ROUND_1(K1, I1, K2, I2, state1, 0x10);
//            ENCRYPT_ROUND_1(K2, I2, K1, I1, state1, 0x20);
//            ENCRYPT_ROUND_1(K1, I1, K2, I2, state1, 0x40);
//            ENCRYPT_ROUND_1(K2, I2, K1, I1, state1, 0x80);
//            ENCRYPT_ROUND_1(K1, I1, K2, I2, state1, 0x1b);
//            ENCRYPT_ROUND_1(K2, I2, K1, I1, state1, 0x36);
//            ENCRYPT_ROUND_1_LAST(K1, state1);
//            
//            // cleanup
//            K1 = _mm_set_epi64x(0x00, 0x00);
//            I1 = _mm_set_epi64x(0x00, 0x00);
//            K2 = _mm_set_epi64x(0x00, 0x00);
//            I2 = _mm_set_epi64x(0x00, 0x00);
//            
//            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
//            
//        }
        
        //#define ENCRYPT_ROUND_2_FIRST(K1, I1, K2, I2 , S1, S2) \
        //I2 = K1; \
        //R = _mm_set_epi32(0x01,0x01,0x01,0x01) ; \
        //I2 = _mm_shuffle_epi8(I2, mask) ; \
        //I2 = _mm_aesenclast_si128(I2, R); \
        //S1 = _mm_xor_si128(S1, K1); \
        //S2 = _mm_xor_si128(S2, K1); \
        //K2 = K1; \
        //FINISH_EXP128(K2,I2);
        //
        //#define ENCRYPT_ROUND_2(K1, I1, K2, I2 , S1, S2, Rcon) \
        //I2 = K1; \
        //R = _mm_set_epi32(Rcon,Rcon,Rcon,Rcon) ; \
        //I2 = _mm_shuffle_epi8(I2, mask) ; \
        //I2 = _mm_aesenclast_si128(I2, R); \
        //S1 = _mm_aesenc_si128(S1, K1); \
        //S2 = _mm_aesenc_si128(S2, K1); \
        //K2 = K1; \
        //FINISH_EXP128(K2,I2);
        //
        //
        //#define ENCRYPT_ROUND_2_LAST(K, S1, S2) \
        //S1 = _mm_aesenclast_si128(S1, K); \
        //S2 = _mm_aesenclast_si128(S2, K);
        //
        //        void pipeline_encrypt2(const uint8_t* in, const uint8_t* key, uint8_t *out)
        //        {
        //            __m128i K1, K2, I1, I2, mask, R;
        //
        //            // load the key in the first SSE register
        //            K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
        //
        //            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
        //
        //            uint64_t now =  rdtsc();
        //
        //            // load the input
        //            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
        //            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
        //
        //            ENCRYPT_ROUND_2_FIRST(K1, I1, K2, I2, state1, state2);
        //            ENCRYPT_ROUND_2(K2, I2, K1, I1, state1, state2, 0x02);
        //            ENCRYPT_ROUND_2(K1, I1, K2, I2, state1, state2, 0x04);
        //            ENCRYPT_ROUND_2(K2, I2, K1, I1, state1, state2, 0x08);
        //            ENCRYPT_ROUND_2(K1, I1, K2, I2, state1, state2, 0x10);
        //            ENCRYPT_ROUND_2(K2, I2, K1, I1, state1, state2, 0x20);
        //            ENCRYPT_ROUND_2(K1, I1, K2, I2, state1, state2, 0x40);
        //            ENCRYPT_ROUND_2(K2, I2, K1, I1, state1, state2, 0x80);
        //            ENCRYPT_ROUND_2(K1, I1, K2, I2, state1, state2, 0x1b);
        //            ENCRYPT_ROUND_2(K2, I2, K1, I1, state1, state2, 0x36);
        //            ENCRYPT_ROUND_2_LAST(K1, state1, state2);
        //
        //            tick_counter += rdtsc() - now;
        //
        //            
        //            // cleanup
        //            K1 = _mm_set_epi64x(0x00, 0x00);
        //            I1 = _mm_set_epi64x(0x00, 0x00);
        //            K2 = _mm_set_epi64x(0x00, 0x00);
        //            I2 = _mm_set_epi64x(0x00, 0x00);
        //            
        //            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
        //            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
        //   
        //        }
        

}
}

#endif
