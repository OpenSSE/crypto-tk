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

//namespace sse
//{
//    
//    namespace crypto
//    {
//        
//        extern __inline__ uint64_t rdtsc(void) {
//            uint64_t a, d;
//            __asm__ volatile ("rdtsc" : "=a" (a), "=d" (d));
//            return (d<<32) | a;
//        }
//        
//        uint64_t tick_counter = 0;
//    }
//}

#if USE_AESNI

#pragma message "Use AES NI"

#include <iostream>
#include <iomanip>
#include <exception>
#include <cstring>

namespace sse
{
    
    namespace crypto
    {
        
        
        // use aesenclast instead of aeskeygenassist:
        // it improves the throughput for the PRG
        
#define KEYEXP_128(K, I, Rcon) \
I = _mm_shuffle_epi8(K, mask) ; \
R = _mm_set_epi32(Rcon,Rcon,Rcon,Rcon) ; \
I = _mm_aesenclast_si128(I, R); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
K = _mm_xor_si128(K, _mm_slli_si128(K, 4)); \
I = _mm_shuffle_epi32(I, 0xFF); \
K = _mm_xor_si128(K,I);
        
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

        void aesni_encrypt1(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            
            
//            uint64_t now =  rdtsc();
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));

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
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state);
            
        }
        
        
#define XOR_KEY_2(K, S1, S2) \
S1 = _mm_xor_si128(S1, K); \
S2 = _mm_xor_si128(S2, K);
        
#define ENCRYPT_ROUND_2(K, S1, S2) \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K);

#define ENCRYPT_ROUND_LAST_2(K, S1, S2) \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K);
        
        void aesni_encrypt2(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_2(SK, state1, state2);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_2(SK, state1, state2);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            
        }

        
#define XOR_KEY_3(K, S1, S2, S3) \
S1 = _mm_xor_si128(S1, K); \
S2 = _mm_xor_si128(S2, K); \
S3 = _mm_xor_si128(S3, K);
        
        
#define ENCRYPT_ROUND_3(K, S1, S2, S3) \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K);
        
#define ENCRYPT_ROUND_LAST_3(K, S1, S2, S3) \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K);
        
        void aesni_encrypt3(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_3(SK, state1, state2, state3);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_3(SK, state1, state2, state3);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            
        }

        
#define XOR_KEY_4(K, S1, S2, S3, S4) \
S1 = _mm_xor_si128(S1, K); \
S2 = _mm_xor_si128(S2, K); \
S3 = _mm_xor_si128(S3, K); \
S4 = _mm_xor_si128(S4, K);
        
#define ENCRYPT_ROUND_4(K, S1, S2, S3, S4) \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); 
        
#define ENCRYPT_ROUND_LAST_4(K, S1, S2, S3, S4) \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); 
        
        void aesni_encrypt4(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_4(SK, state1, state2, state3, state4);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_4(SK, state1, state2, state3, state4);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            
        }

        
#define XOR_KEY_5(K, S1, S2, S3, S4, S5) \
S1 = _mm_xor_si128(S1, K); \
S2 = _mm_xor_si128(S2, K); \
S3 = _mm_xor_si128(S3, K); \
S4 = _mm_xor_si128(S4, K); \
S5 = _mm_xor_si128(S5, K);
        
#define ENCRYPT_ROUND_5(K, S1, S2, S3, S4, S5) \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); 
        
#define ENCRYPT_ROUND_LAST_5(K, S1, S2, S3, S4, S5) \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K);
        
        void aesni_encrypt5(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_5(SK, state1, state2, state3, state4, state5);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_5(SK, state1, state2, state3, state4, state5);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
          
        }

        
#define XOR_KEY_6(K, S1, S2, S3, S4, S5, S6) \
S1 = _mm_xor_si128(S1, K); \
S2 = _mm_xor_si128(S2, K); \
S3 = _mm_xor_si128(S3, K); \
S4 = _mm_xor_si128(S4, K); \
S5 = _mm_xor_si128(S5, K); \
S6 = _mm_xor_si128(S6, K);
        
#define ENCRYPT_ROUND_6(K, S1, S2, S3, S4, S5, S6) \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); \
S6 = _mm_aesenc_si128(S6, K); 
        
#define ENCRYPT_ROUND_LAST_6(K, S1, S2, S3, S4, S5, S6) \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K); \
S6 = _mm_aesenclast_si128(S6, K);
        
        void aesni_encrypt6(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            __m128i state6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+5);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_6(SK, state1, state2, state3, state4, state5, state6);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_6(SK, state1, state2, state3, state4, state5, state6);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            
        }

        
#define XOR_KEY_7(K, S1, S2, S3, S4, S5, S6, S7) \
S1 = _mm_xor_si128(S1, K); \
S2 = _mm_xor_si128(S2, K); \
S3 = _mm_xor_si128(S3, K); \
S4 = _mm_xor_si128(S4, K); \
S5 = _mm_xor_si128(S5, K); \
S6 = _mm_xor_si128(S6, K); \
S7 = _mm_xor_si128(S7, K);
        
#define ENCRYPT_ROUND_7(K, S1, S2, S3, S4, S5, S6, S7) \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); \
S6 = _mm_aesenc_si128(S6, K); \
S7 = _mm_aesenc_si128(S7, K);
        
#define ENCRYPT_ROUND_LAST_7(K, S1, S2, S3, S4, S5, S6, S7) \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K); \
S6 = _mm_aesenclast_si128(S6, K); \
S7 = _mm_aesenclast_si128(S7, K);

        
        void aesni_encrypt7(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            __m128i state6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+5);
            __m128i state7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+6);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            
        }


#define XOR_KEY_8(K, S1, S2, S3, S4, S5, S6, S7, S8) \
S1 = _mm_xor_si128(S1, K); \
S2 = _mm_xor_si128(S2, K); \
S3 = _mm_xor_si128(S3, K); \
S4 = _mm_xor_si128(S4, K); \
S5 = _mm_xor_si128(S5, K); \
S6 = _mm_xor_si128(S6, K); \
S7 = _mm_xor_si128(S7, K); \
S8 = _mm_xor_si128(S8, K);
        

#define ENCRYPT_ROUND_8(K, S1, S2, S3, S4, S5, S6, S7, S8) \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); \
S6 = _mm_aesenc_si128(S6, K); \
S7 = _mm_aesenc_si128(S7, K); \
S8 = _mm_aesenc_si128(S8, K);
        
#define ENCRYPT_ROUND_LAST_8(K, S1, S2, S3, S4, S5, S6, S7, S8) \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K); \
S6 = _mm_aesenclast_si128(S6, K); \
S7 = _mm_aesenclast_si128(S7, K); \
S8 = _mm_aesenclast_si128(S8, K);

        
        void aesni_encrypt8(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            __m128i state6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+5);
            __m128i state7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+6);
            __m128i state8 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+7);

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
     
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
        
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
        
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
        
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
           
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);

//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+7, state8);

        }
        
 
        void aesni_encrypt(const uint8_t* in, const uint64_t len, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            uint64_t i = 0;
            
            while (i+8 <= len) { // at least 8 blocks to generate
                aesni_encrypt8(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                i+=8;
            }
            
            switch (len-i) {
                case 0:
                    break;
                case 1:
                    aesni_encrypt1(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 2:
                    aesni_encrypt2(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 3:
                    aesni_encrypt3(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 4:
                    aesni_encrypt4(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 5:
                    aesni_encrypt5(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 6:
                    aesni_encrypt6(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 7:
                    aesni_encrypt7(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                    
                default:
                    throw std::out_of_range("len-i > 7");
                    break;
            }
            
        }
        
        void aesni_encrypt_xor1(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            
            __m128i old_state = state;

            //            uint64_t now =  rdtsc();
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
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
            
            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            state = _mm_xor_si128(state, old_state);

            // clean up the old_state registers: they could contain sensitive information
            
            old_state = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state);
            
        }
        
        void aesni_encrypt_xor2(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            
            __m128i old_state1 = state1;
            __m128i old_state2 = state2;

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            //            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_2(SK, state1, state2);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_2(SK, state1, state2);
            
            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            state1 = _mm_xor_si128(state1, old_state1);
            state2 = _mm_xor_si128(state2, old_state2);

            // clean up the old_state registers: they could contain sensitive information
            
            old_state1 = _mm_set_epi64x(0x00, 0x00);
            old_state2 = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            
        }
        
        void aesni_encrypt_xor3(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            
            __m128i old_state1 = state1;
            __m128i old_state2 = state2;
            __m128i old_state3 = state3;

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            //            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_3(SK, state1, state2, state3);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);

            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_3(SK, state1, state2, state3);

            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            state1 = _mm_xor_si128(state1, old_state1);
            state2 = _mm_xor_si128(state2, old_state2);
            state3 = _mm_xor_si128(state3, old_state3);

            // clean up the old_state registers: they could contain sensitive information
            
            old_state1 = _mm_set_epi64x(0x00, 0x00);
            old_state2 = _mm_set_epi64x(0x00, 0x00);
            old_state3 = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            
        }
        
        
        void aesni_encrypt_xor4(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            
            __m128i old_state1 = state1;
            __m128i old_state2 = state2;
            __m128i old_state3 = state3;
            __m128i old_state4 = state4;

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            //            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_4(SK, state1, state2, state3, state4);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_4(SK, state1, state2, state3, state4);
            
            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            
            state1 = _mm_xor_si128(state1, old_state1);
            state2 = _mm_xor_si128(state2, old_state2);
            state3 = _mm_xor_si128(state3, old_state3);
            state4 = _mm_xor_si128(state4, old_state4);

            // clean up the old_state registers: they could contain sensitive information
            
            old_state1 = _mm_set_epi64x(0x00, 0x00);
            old_state2 = _mm_set_epi64x(0x00, 0x00);
            old_state3 = _mm_set_epi64x(0x00, 0x00);
            old_state4 = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            
        }
        
        
        void aesni_encrypt_xor5(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            
            __m128i old_state1 = state1;
            __m128i old_state2 = state2;
            __m128i old_state3 = state3;
            __m128i old_state4 = state4;
            __m128i old_state5 = state5;

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            //            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_5(SK, state1, state2, state3, state4, state5);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_5(SK, state1, state2, state3, state4, state5);
            
            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            state1 = _mm_xor_si128(state1, old_state1);
            state2 = _mm_xor_si128(state2, old_state2);
            state3 = _mm_xor_si128(state3, old_state3);
            state4 = _mm_xor_si128(state4, old_state4);
            state5 = _mm_xor_si128(state5, old_state5);

            // clean up the old_state registers: they could contain sensitive information
            
            old_state1 = _mm_set_epi64x(0x00, 0x00);
            old_state2 = _mm_set_epi64x(0x00, 0x00);
            old_state3 = _mm_set_epi64x(0x00, 0x00);
            old_state4 = _mm_set_epi64x(0x00, 0x00);
            old_state5 = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            
        }
        
        
        void aesni_encrypt_xor6(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            __m128i state6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+5);
            
            __m128i old_state1 = state1;
            __m128i old_state2 = state2;
            __m128i old_state3 = state3;
            __m128i old_state4 = state4;
            __m128i old_state5 = state5;
            __m128i old_state6 = state6;
            

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            //            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_6(SK, state1, state2, state3, state4, state5, state6);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_6(SK, state1, state2, state3, state4, state5, state6);
            
            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            state1 = _mm_xor_si128(state1, old_state1);
            state2 = _mm_xor_si128(state2, old_state2);
            state3 = _mm_xor_si128(state3, old_state3);
            state4 = _mm_xor_si128(state4, old_state4);
            state5 = _mm_xor_si128(state5, old_state5);
            state6 = _mm_xor_si128(state6, old_state6);

            // clean up the old_state registers: they could contain sensitive information
            
            old_state1 = _mm_set_epi64x(0x00, 0x00);
            old_state2 = _mm_set_epi64x(0x00, 0x00);
            old_state3 = _mm_set_epi64x(0x00, 0x00);
            old_state4 = _mm_set_epi64x(0x00, 0x00);
            old_state5 = _mm_set_epi64x(0x00, 0x00);
            old_state6 = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            
        }
        
        
        void aesni_encrypt_xor7(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            __m128i state6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+5);
            __m128i state7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+6);
            
            __m128i old_state1 = state1;
            __m128i old_state2 = state2;
            __m128i old_state3 = state3;
            __m128i old_state4 = state4;
            __m128i old_state5 = state5;
            __m128i old_state6 = state6;
            __m128i old_state7 = state7;
            

            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            //            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            
            state1 = _mm_xor_si128(state1, old_state1);
            state2 = _mm_xor_si128(state2, old_state2);
            state3 = _mm_xor_si128(state3, old_state3);
            state4 = _mm_xor_si128(state4, old_state4);
            state5 = _mm_xor_si128(state5, old_state5);
            state6 = _mm_xor_si128(state6, old_state6);
            state7 = _mm_xor_si128(state7, old_state7);

            // clean up the old_state registers: they could contain sensitive information
            
            old_state1 = _mm_set_epi64x(0x00, 0x00);
            old_state2 = _mm_set_epi64x(0x00, 0x00);
            old_state3 = _mm_set_epi64x(0x00, 0x00);
            old_state4 = _mm_set_epi64x(0x00, 0x00);
            old_state5 = _mm_set_epi64x(0x00, 0x00);
            old_state6 = _mm_set_epi64x(0x00, 0x00);
            old_state7 = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            
        }
        

        void aesni_encrypt_xor8(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in));
            __m128i state2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+1);
            __m128i state3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+2);
            __m128i state4 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+3);
            __m128i state5 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+4);
            __m128i state6 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+5);
            __m128i state7 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+6);
            __m128i state8 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in)+7);
            
            __m128i old_state1 = state1;
            __m128i old_state2 = state2;
            __m128i old_state3 = state3;
            __m128i old_state4 = state4;
            __m128i old_state5 = state5;
            __m128i old_state6 = state6;
            __m128i old_state7 = state7;
            __m128i old_state8 = state8;
            
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
            //            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            //            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            state1 = _mm_xor_si128(state1, old_state1);
            state2 = _mm_xor_si128(state2, old_state2);
            state3 = _mm_xor_si128(state3, old_state3);
            state4 = _mm_xor_si128(state4, old_state4);
            state5 = _mm_xor_si128(state5, old_state5);
            state6 = _mm_xor_si128(state6, old_state6);
            state7 = _mm_xor_si128(state7, old_state7);
            state8 = _mm_xor_si128(state8, old_state8);
            
            // clean up the old_state registers: they could contain sensitive information
            
            old_state1 = _mm_set_epi64x(0x00, 0x00);
            old_state2 = _mm_set_epi64x(0x00, 0x00);
            old_state3 = _mm_set_epi64x(0x00, 0x00);
            old_state4 = _mm_set_epi64x(0x00, 0x00);
            old_state5 = _mm_set_epi64x(0x00, 0x00);
            old_state6 = _mm_set_epi64x(0x00, 0x00);
            old_state7 = _mm_set_epi64x(0x00, 0x00);
            old_state8 = _mm_set_epi64x(0x00, 0x00);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+7, state8);
            
        }
        


        void aesni_encrypt_xor(const uint8_t* in, const uint64_t len, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            uint64_t i = 0;
            
            while (i+8 <= len) { // at least 8 blocks to generate
                aesni_encrypt_xor8(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                i+=8;
            }
			
            
            switch (len-i) {
                case 0:
                    break;
                case 1:
                    aesni_encrypt_xor1(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 2:
                    aesni_encrypt_xor2(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 3:
                    aesni_encrypt_xor3(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 4:
                    aesni_encrypt_xor4(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 5:
                    aesni_encrypt_xor5(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 6:
                    aesni_encrypt_xor6(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                case 7:
                    aesni_encrypt_xor7(in+(i*kAESBlockSize), subkeys, out + (i*kAESBlockSize));
                    break;
                    
                default:
                    throw std::out_of_range("len-i > 7");
                    break;
            }
            
        }

        void aesni_ctr1(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state = _mm_set_epi64x(0x00, iv);
            
            
//            uint64_t now =  rdtsc();
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
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
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state);
            
        }


#define EXP_ENCRYPT_ROUND_1(K, I, S1, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K);

#define EXP_ENCRYPT_ROUND_1_LAST(K, I, S1) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K);

        void aesni_ctr1(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            state1 = _mm_xor_si128(state1, K);

            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x01);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x02);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x04);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x08);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x10);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x20);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x40);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x80);
            EXP_ENCRYPT_ROUND_1(K, I, state1, 0x1b);
            EXP_ENCRYPT_ROUND_1_LAST(K, I, state1);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
        }

#define EXP_ENCRYPT_ROUND_2(K, I, S1, S2, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K);
        
#define EXP_ENCRYPT_ROUND_2_LAST(K, I, S1, S2) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K);
        
        void aesni_ctr2(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_2(SK, state1, state2);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_2(SK, state1, state2);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_2(SK, state1, state2);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            
        }

        void aesni_ctr2(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_2(K, state1, state2);
            
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x01);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x02);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x04);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x08);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x10);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x20);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x40);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x80);
            EXP_ENCRYPT_ROUND_2(K, I, state1, state2, 0x1b);
            EXP_ENCRYPT_ROUND_2_LAST(K, I, state1, state2);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            
        }


#define EXP_ENCRYPT_ROUND_3(K, I, S1, S2, S3, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K);

        
#define EXP_ENCRYPT_ROUND_3_LAST(K, I, S1, S2, S3) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K);

        void aesni_ctr3(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_3(SK, state1, state2, state3);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_3(SK, state1, state2, state3);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_3(SK, state1, state2, state3);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            
        }

        void aesni_ctr3(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_3(K, state1, state2, state3);
            
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x01);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x02);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x04);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x08);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x10);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x20);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x40);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x80);
            EXP_ENCRYPT_ROUND_3(K, I, state1, state2, state3, 0x1b);
            EXP_ENCRYPT_ROUND_3_LAST(K, I, state1, state2, state3);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            
        }
        
#define EXP_ENCRYPT_ROUND_4(K, I, S1, S2, S3, S4, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K);
        
#define EXP_ENCRYPT_ROUND_4_LAST(K, I, S1, S2, S3, S4) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K);

        void aesni_ctr4(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_4(SK, state1, state2, state3, state4);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_4(SK, state1, state2, state3, state4);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_4(SK, state1, state2, state3, state4);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            
        }

        void aesni_ctr4(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_4(K, state1, state2, state3, state4);
            
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x01);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x02);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x04);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x08);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x10);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x20);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x40);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x80);
            EXP_ENCRYPT_ROUND_4(K, I, state1, state2, state3, state4, 0x1b);
            EXP_ENCRYPT_ROUND_4_LAST(K, I, state1, state2, state3, state4);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
        }
		
#define EXP_ENCRYPT_ROUND_5(K, I, S1, S2, S3, S4, S5, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); 
        
#define EXP_ENCRYPT_ROUND_5_LAST(K, I, S1, S2, S3, S4, S5) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K); 
        
        void aesni_ctr5(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_5(SK, state1, state2, state3, state4, state5);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_5(SK, state1, state2, state3, state4, state5);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_5(SK, state1, state2, state3, state4, state5);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            
        }

        void aesni_ctr5(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_5(K, state1, state2, state3, state4, state5);
            
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x01);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x02);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x04);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x08);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x10);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x20);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x40);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x80);
            EXP_ENCRYPT_ROUND_5(K, I, state1, state2, state3, state4, state5, 0x1b);
            EXP_ENCRYPT_ROUND_5_LAST(K, I, state1, state2, state3, state4, state5);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);

            
        }
		
#define EXP_ENCRYPT_ROUND_6(K, I, S1, S2, S3, S4, S5, S6, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); \
S6 = _mm_aesenc_si128(S6, K); 
        
#define EXP_ENCRYPT_ROUND_6_LAST(K, I, S1, S2, S3, S4, S5, S6) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K); \
S6 = _mm_aesenclast_si128(S6, K); 
        
        void aesni_ctr6(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            __m128i state6 = _mm_set_epi64x(0x00, iv+5);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_6(SK, state1, state2, state3, state4, state5, state6);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_6(SK, state1, state2, state3, state4, state5, state6);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_6(SK, state1, state2, state3, state4, state5, state6);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            
        }

        void aesni_ctr6(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            __m128i state6 = _mm_set_epi64x(0x00, iv+5);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_6(K, state1, state2, state3, state4, state5, state6);
            
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x01);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x02);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x04);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x08);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x10);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x20);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x40);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x80);
            EXP_ENCRYPT_ROUND_6(K, I, state1, state2, state3, state4, state5, state6, 0x1b);
            EXP_ENCRYPT_ROUND_6_LAST(K, I, state1, state2, state3, state4, state5, state6);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            
        }
		
#define EXP_ENCRYPT_ROUND_7(K, I, S1, S2, S3, S4, S5, S6, S7, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); \
S6 = _mm_aesenc_si128(S6, K); \
S7 = _mm_aesenc_si128(S7, K); 
        
#define EXP_ENCRYPT_ROUND_7_LAST(K, I, S1, S2, S3, S4, S5, S6, S7) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K); \
S6 = _mm_aesenclast_si128(S6, K); \
S7 = _mm_aesenclast_si128(S7, K); 
        
        void aesni_ctr7(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            __m128i state6 = _mm_set_epi64x(0x00, iv+5);
            __m128i state7 = _mm_set_epi64x(0x00, iv+6);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_7(SK, state1, state2, state3, state4, state5, state6, state7);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            
        }

        void aesni_ctr7(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            __m128i state6 = _mm_set_epi64x(0x00, iv+5);
            __m128i state7 = _mm_set_epi64x(0x00, iv+6);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_7(K, state1, state2, state3, state4, state5, state6, state7);
            
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x01);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x02);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x04);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x08);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x10);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x20);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x40);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x80);
            EXP_ENCRYPT_ROUND_7(K, I, state1, state2, state3, state4, state5, state6, state7, 0x1b);
            EXP_ENCRYPT_ROUND_7_LAST(K, I, state1, state2, state3, state4, state5, state6, state7);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            
        }
#define EXP_ENCRYPT_ROUND_8(K, I, S1, S2, S3, S4, S5, S6, S7, S8, Rcon) \
KEYEXP_128(K, I, Rcon); \
S1 = _mm_aesenc_si128(S1, K); \
S2 = _mm_aesenc_si128(S2, K); \
S3 = _mm_aesenc_si128(S3, K); \
S4 = _mm_aesenc_si128(S4, K); \
S5 = _mm_aesenc_si128(S5, K); \
S6 = _mm_aesenc_si128(S6, K); \
S7 = _mm_aesenc_si128(S7, K); \
S8 = _mm_aesenc_si128(S8, K);
        
#define EXP_ENCRYPT_ROUND_8_LAST(K, I, S1, S2, S3, S4, S5, S6, S7, S8) \
KEYEXP_128(K, I, 0x36); \
S1 = _mm_aesenclast_si128(S1, K); \
S2 = _mm_aesenclast_si128(S2, K); \
S3 = _mm_aesenclast_si128(S3, K); \
S4 = _mm_aesenclast_si128(S4, K); \
S5 = _mm_aesenclast_si128(S5, K); \
S6 = _mm_aesenclast_si128(S6, K); \
S7 = _mm_aesenclast_si128(S7, K); \
S8 = _mm_aesenclast_si128(S8, K);
        
        void aesni_ctr8(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            __m128i state6 = _mm_set_epi64x(0x00, iv+5);
            __m128i state7 = _mm_set_epi64x(0x00, iv+6);
            __m128i state8 = _mm_set_epi64x(0x00, iv+7);
            
            // load the first subkey
            __m128i SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data()));
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            // load the next subkeys and call the magical aesenc instruction
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+1);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+2);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+3);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+4);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+5);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+6);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+7);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+8);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+9);
            ENCRYPT_ROUND_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
            SK = _mm_loadu_si128(reinterpret_cast<const __m128i*>(subkeys.data())+10);
            ENCRYPT_ROUND_LAST_8(SK, state1, state2, state3, state4, state5, state6, state7, state8);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            SK = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+7, state8);
            
        }

        void aesni_ctr8(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            __m128i state6 = _mm_set_epi64x(0x00, iv+5);
            __m128i state7 = _mm_set_epi64x(0x00, iv+6);
            __m128i state8 = _mm_set_epi64x(0x00, iv+7);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_8(K, state1, state2, state3, state4, state5, state6, state7, state8);
            
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x01);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x02);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x04);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x08);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x10);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x20);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x40);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x80);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x1b);
            EXP_ENCRYPT_ROUND_8_LAST(K, I, state1, state2, state3, state4, state5, state6, state7, state8);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+7, state8);
            
        }

        aes_subkeys_type aesni_ctr_exp8(const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            aes_subkeys_type subkeys;

            __m128i K, I, mask, R;
            
            mask = _mm_set_epi32(0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d);
            
            // load the key in the first SSE register
            K = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
            
            // load the input
            __m128i state1 = _mm_set_epi64x(0x00, iv);
            __m128i state2 = _mm_set_epi64x(0x00, iv+1);
            __m128i state3 = _mm_set_epi64x(0x00, iv+2);
            __m128i state4 = _mm_set_epi64x(0x00, iv+3);
            __m128i state5 = _mm_set_epi64x(0x00, iv+4);
            __m128i state6 = _mm_set_epi64x(0x00, iv+5);
            __m128i state7 = _mm_set_epi64x(0x00, iv+6);
            __m128i state8 = _mm_set_epi64x(0x00, iv+7);
            
            // ROUND 0
            
//            uint64_t now =  rdtsc();
            
            // XOR it to the state
            XOR_KEY_8(K, state1, state2, state3, state4, state5, state6, state7, state8);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+0, K);

            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x01);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+1, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x02);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+2, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x04);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+3, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x08);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+4, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x10);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+5, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x20);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+6, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x40);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+7, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x80);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+8, K);
            EXP_ENCRYPT_ROUND_8(K, I, state1, state2, state3, state4, state5, state6, state7, state8, 0x1b);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+9, K);
            EXP_ENCRYPT_ROUND_8_LAST(K, I, state1, state2, state3, state4, state5, state6, state7, state8);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(subkeys.data())+10, K);
            
//            tick_counter += rdtsc() - now;
            
            // cleanup
            K = _mm_set_epi64x(0x00, 0x00);
            I = _mm_set_epi64x(0x00, 0x00);
            
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), state1);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+1, state2);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+2, state3);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+3, state4);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+4, state5);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+5, state6);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+6, state7);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(out)+7, state8);
            
            return subkeys;
        }
        
        
        
        void aesni_ctr(const uint64_t N, const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out)
        {
            uint64_t i = 0;
            
            while (i+8 <= N) { // at least 8 blocks to generate
                aesni_ctr8(i+iv, subkeys, out + (i*kAESBlockSize));
                i+=8;
            }
            
            switch (N-i) {
                case 0:
                    break;
                case 1:
                    aesni_ctr1(i+iv, subkeys, out + (i*kAESBlockSize));
                    break;
                case 2:
                    aesni_ctr2(i+iv, subkeys, out + (i*kAESBlockSize));
                    break;
                case 3:
                    aesni_ctr3(i+iv, subkeys, out + (i*kAESBlockSize));
                    break;
                case 4:
                    aesni_ctr4(i+iv, subkeys, out + (i*kAESBlockSize));
                    break;
                case 5:
                    aesni_ctr5(i+iv, subkeys, out + (i*kAESBlockSize));
                    break;
                case 6:
                    aesni_ctr6(i+iv, subkeys, out + (i*kAESBlockSize));
                    break;
                case 7:
                    aesni_ctr7(i+iv, subkeys, out + (i*kAESBlockSize));
                    break;
                    
                default:
                    throw std::out_of_range("N-i > 7");
                    break;
            }
            
        }

        void aesni_ctr(const uint64_t N, const uint64_t iv, const uint8_t* key, uint8_t *out)
        {
            if(N >= 8)
            {
                aes_subkeys_type subkeys = aesni_ctr_exp8(iv, key, out);
                
                if (N > 8) {
                    aesni_ctr(N-8, iv+8, subkeys, out+8*kAESBlockSize);
                }
                
                std::fill(subkeys.begin(), subkeys.end(), 0x00);
            }else{
                switch (N) {
                    case 0:
                        break;
                    case 1:
                        aesni_ctr1(iv, key, out);
                        break;
                    case 2:
                        aesni_ctr2(iv, key, out);
                        break;
                    case 3:
                        aesni_ctr3(iv, key, out);
                        break;
                    case 4:
                        aesni_ctr4(iv, key, out);
                        break;
                    case 5:
                        aesni_ctr5(iv, key, out);
                        break;
                    case 6:
                        aesni_ctr6(iv, key, out);
                        break;
                    case 7:
                        aesni_ctr7(iv, key, out);
                        break;
                        
                    default:
                        throw std::out_of_range("N > 7");
                        break;
                }
            }
        }

}

}

#endif
