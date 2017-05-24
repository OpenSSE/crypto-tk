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


#pragma once

#define USE_AESNI (!defined( NO_AESNI ) && defined (__AES__))

#include <cstdint>

//namespace sse
//{
//    
//    namespace crypto
//    {
//        
//        extern uint64_t tick_counter;
//    }
//}

#if USE_AESNI

#include <array>

#include <emmintrin.h>
#include <wmmintrin.h>
#include <tmmintrin.h>


namespace sse
{
    
    namespace crypto
    {
        constexpr uint8_t kNAESRound = 10;
        constexpr uint8_t kAESBlockSize = 16;


        typedef std::array<uint8_t, kAESBlockSize> aes_key_type;
        typedef std::array<uint8_t, (kNAESRound+1)*kAESBlockSize> aes_subkeys_type;

        aes_subkeys_type aesni_derive_subkeys(const uint8_t* key);
        inline aes_subkeys_type aesni_derive_subkeys(const aes_key_type& key)
        {
            return aesni_derive_subkeys(key.data());
        }
        

        void aesni_encrypt1(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt2(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt3(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt4(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt5(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt6(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt7(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt8(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt(const uint8_t* in, const uint64_t len, const aes_subkeys_type &subkeys, uint8_t *out);

        void aesni_encrypt_xor1(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor2(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor3(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor4(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor5(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor6(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor7(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor8(const uint8_t* in, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_encrypt_xor(const uint8_t* in, const uint64_t len, const aes_subkeys_type &subkeys, uint8_t *out);


        void aesni_ctr1(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr2(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr3(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr4(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr5(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr6(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr7(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr8(const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);

        void aesni_ctr1(const uint64_t iv, const uint8_t* key, uint8_t *out);
        void aesni_ctr2(const uint64_t iv, const uint8_t* key, uint8_t *out);
        void aesni_ctr3(const uint64_t iv, const uint8_t* key, uint8_t *out);
        void aesni_ctr4(const uint64_t iv, const uint8_t* key, uint8_t *out);
        void aesni_ctr5(const uint64_t iv, const uint8_t* key, uint8_t *out);
        void aesni_ctr6(const uint64_t iv, const uint8_t* key, uint8_t *out);
        void aesni_ctr7(const uint64_t iv, const uint8_t* key, uint8_t *out);
        void aesni_ctr8(const uint64_t iv, const uint8_t* key, uint8_t *out);
        
        
        aes_subkeys_type aesni_ctr_exp8(const uint64_t iv, const uint8_t* key, uint8_t *out);

        void aesni_ctr(const uint64_t N, const uint64_t iv, const aes_subkeys_type &subkeys, uint8_t *out);
        void aesni_ctr(const uint64_t N, const uint64_t iv, const uint8_t* key, uint8_t *out);

    }
}

#endif
