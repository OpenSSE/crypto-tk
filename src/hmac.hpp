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

#include "random.hpp"
#include "key.hpp"
#include "sodium/utils.h"

#include <cstdint>
#include <cstring>

#include <string>
#include <array>
#include <iostream>

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

            HMac(Key<kKeySize>&& key) : key_(std::move(key))
            {
            };

            HMac(uint8_t* const k) : key_(k)
            {
                if(k == NULL)
                {
                    throw std::invalid_argument("Invalid key: key == NULL");
                }
            };
            
//            HMac(const void* k, const uint8_t &len) :
//            key_{}
//            {
//                if(len > kHMACKeySize)
//                {
//                    throw std::invalid_argument("Invalid key length: len > kKeySize");
//                }
//
//                if(len < kMinKeySize)
//                {
//                    throw std::invalid_argument("Invalid key length: len < 16. Insecure key size");
//                }
//
//                if(k == NULL)
//                {
//                    throw std::invalid_argument("Invalid key: key == NULL");
//                }
//
//                uint8_t l = (kKeySize < len) ? kKeySize : len;
//
//                std::memset(key_.data(), 0x00, kKeySize);
//                std::memcpy(key_.data(),k,l);
//
//                gen_padded_keys(key_);
//            };
            
//            HMac(const std::string& k)
//            {
//                uint8_t l = (kKeySize < k.size()) ? kKeySize : k.size();
//
//                std::memset(key_.data(), 0x00, kKeySize);
//                std::memcpy(key_.data(),k.data(),l);
//
//                gen_padded_keys(key_);
//            }
//
//            HMac(const std::string& k, const uint8_t &len)
//            {
//                if(len > kKeySize)
//                {
//                    throw std::invalid_argument("Invalid key length: len > kKeySize");
//                }
//
//                if(len == 0)
//                {
//                    throw std::invalid_argument("Invalid key length: len == 0");
//                }
//
//                uint8_t l = (kKeySize < len) ? kKeySize : len;
//
//                std::memset(key_.data(), 0x00, kKeySize);
//                std::memcpy(key_.data(),k.data(),l);
//
//                gen_padded_keys(key_);
//            }
//
//            HMac(const std::array<uint8_t,kKeySize>& k) : key_(k)
//            {
//                gen_padded_keys(k);
//            };
//
//            HMac(const HMac<H>& k) : key_(k.key_), o_key_(k.o_key_), i_key_(k.i_key_)
//            {
//
//            };
            
            // Destructor.
            // Set the content of the key to zero before destruction: remove all traces of the key in memory.
            ~HMac()
            {
//                std::fill(key_.begin(), key_.end(), 0);
//                std::fill(o_key_.begin(), o_key_.end(), 0);
//                std::fill(i_key_.begin(), i_key_.end(), 0);
            };
            
//            const std::array<uint8_t,kKeySize>& key() const
//            {
//                return key_;
//            };
//
//            const uint8_t* key_data() const
//            {
//                return key_.data();
//            };
            
            void hmac(const unsigned char* in, const size_t &length, unsigned char* out,  const size_t &out_len = kDigestSize) const;
            std::array<uint8_t, H::kDigestSize> hmac(const unsigned char* in, const size_t &length) const;
            std::array<uint8_t, H::kDigestSize> hmac(const std::string &s) const;
            
        private:
//            void gen_padded_keys(const std::array<uint8_t,kKeySize> &in_key);
            
            Key<kKeySize> key_;
//            std::array<uint8_t,kKeySize> key_;
//            std::array<uint8_t,kKeySize> o_key_;
//            std::array<uint8_t,kKeySize> i_key_;
            
        };
        
//        template <class H> void HMac<H>::gen_padded_keys(const std::array<uint8_t,kKeySize> &in_key)
//        {
//            memcpy(o_key_.data(), in_key.data(), kKeySize);
//            memcpy(i_key_.data(), in_key.data(), kKeySize);
//
//            for(uint8_t i = 0; i < kKeySize; ++i)
//            {
//                o_key_[i] ^= 0x5c;
//                i_key_[i] ^= 0x36;
//            }
//        }
        
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
            
            memcpy(buffer, key_.data(), kKeySize);
            
            // xor the magic number for input
            for(uint8_t i = 0; i < kHMACKeySize; ++i){
                buffer[i] ^= 0x36;
            }
            
            memcpy(buffer + kHMACKeySize, in, length);
            
            H::hash(buffer, i_len, buffer);
            
            memcpy(tmp, key_.data(), kKeySize);
            // xor the magic number for output
            for(uint8_t i = 0; i < kHMACKeySize; ++i){
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
