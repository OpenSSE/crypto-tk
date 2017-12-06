//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Raphael Bost
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

#include "random.hpp"
#include "key.hpp"

#include <cstdint>
#include <cstring>

#include <sodium/utils.h>
#include <string>
#include <array>
#include <iostream>
#include <iomanip>

#include <cassert>

namespace sse
{
    
    namespace crypto
    {
        
        
        /*****
         * HMac class
         *
         * Implementation of HMAC.
         * It is templatized according to the hash function.
         ******/
        
        template <class H, uint16_t N> class HMac
        {
        public:
            static constexpr uint16_t kHMACKeySize = H::kBlockSize;
            static constexpr uint16_t kKeySize = N;
            static constexpr uint16_t kMinKeySize = 16; // minimum key size to ensure security
            
            static_assert(kHMACKeySize >= kMinKeySize, "The hash block size is less than 16 bytes. \
                                              This is insecure. Chose an other hash function" );

            static_assert(N >= kMinKeySize, "The HMAC key is less than 16 bytes. \
                          This is insecure. Chose an other hash function" );

            static constexpr uint8_t kDigestSize = H::kDigestSize;
            
            HMac() : key_()
            {
            };

            HMac(HMac<H,N>& hmac) = delete;
            HMac(const HMac<H,N>& hmac) = delete;

            explicit HMac(Key<kKeySize>&& key) : key_(std::move(key))
            {
                if(key_.is_empty())
                {
                    throw std::invalid_argument("Invalid key: key is empty");
                }

            };
            
            
            void hmac(const unsigned char* in, const size_t &length, unsigned char* out,  const size_t &out_len = kDigestSize) const;
            std::array<uint8_t, H::kDigestSize> hmac(const unsigned char* in, const size_t &length) const;
            std::array<uint8_t, H::kDigestSize> hmac(const std::string &s) const;
            
        private:
            
            Key<kKeySize> key_;
        };
        
        
        // HMac instantiation
        template <class H, uint16_t N> void HMac<H,N>::hmac(const unsigned char* in, const size_t &length, unsigned char* out, const size_t &out_len) const
        {
            assert(out_len <= kDigestSize);
            
            uint8_t* buffer, *tmp;
            size_t i_len = kHMACKeySize + length;
            size_t o_len = kHMACKeySize + kDigestSize;
            size_t buffer_len = (i_len > kDigestSize) ? i_len : (kDigestSize);
            
            buffer = static_cast<uint8_t*>(sodium_malloc(buffer_len));
            tmp = static_cast<uint8_t*>(sodium_malloc(o_len));
            
            key_.unlock();
            
            // set the buffer to 0x00
            memset(buffer, 0, kHMACKeySize);
            
            // copy the key to the buffer
            memcpy(buffer, key_.data(), kKeySize);
            
            // set the other bytes to 0x00
            if (kKeySize < kHMACKeySize) {
                memset(buffer+kKeySize, 0x00, kHMACKeySize-kKeySize);
            }

            // xor the magic number for input
            for(uint16_t i = 0; i < kHMACKeySize; ++i){
                buffer[i] ^= 0x36;
            }
            
            memcpy(buffer + kHMACKeySize, in, length);

            H::hash(buffer, i_len, buffer);
            
            // prepend the key
            memcpy(tmp, key_.data(), kKeySize);
            // set the other bytes to 0x00
            if (kKeySize < kHMACKeySize) {
                memset(tmp+kKeySize, 0x00, kHMACKeySize-kKeySize);
            }

            // xor the magic number for output
            for(uint16_t i = 0; i < kHMACKeySize; ++i){
                tmp[i] ^= 0x5c;
            }

            memcpy(tmp + kHMACKeySize, buffer, kDigestSize);
            
            H::hash(tmp, kHMACKeySize + kDigestSize, buffer);
            

            memcpy(out, buffer, out_len);
            
            sodium_memzero(buffer,buffer_len);
            sodium_free(buffer);
            
            sodium_memzero(tmp,o_len);
            sodium_free(tmp);

            key_.lock();
        }
        
        template <class H, uint16_t N> std::array<uint8_t, H::kDigestSize> HMac<H,N>::hmac(const unsigned char* in, const size_t &length) const
        {
            std::array<uint8_t, kDigestSize> result;
            
            hmac(in, length, result.data(), kDigestSize);
            return result;
        }
        
        // Convienience function to run HMac over a C++ string
        template <class H, uint16_t N> std::array<uint8_t, H::kDigestSize> HMac<H,N>::hmac(const std::string &s) const
        {
            return hmac((const unsigned char*)s.data() , s.length());
        }
        
    } // namespace crypto
} // namespace sse
