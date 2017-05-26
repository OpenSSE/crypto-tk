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

#include <cstdint>
#include <cstring>

#include <string>
#include <array>

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
        
        template <class H> class HMac
        {
        public:
            static constexpr uint8_t kKeySize = H::kBlockSize;
            static constexpr uint8_t kDigestSize = H::kDigestSize;
            
            HMac()
            {
                random_bytes(kKeySize, key_.data());
                gen_padded_keys(key_);
            };
            
            HMac(const void* k)
            {
                if(k == NULL)
                {
                    throw std::invalid_argument("Invalid key: key == NULL");
                }
                
                std::memcpy(key_.data(),k,kKeySize);
                gen_padded_keys(key_);
            };
            
            HMac(const void* k, const uint8_t &len) :
            key_{}, o_key_{}, i_key_{}
            {
                if(len > kKeySize)
                {
                    throw std::invalid_argument("Invalid key length: len > kKeySize");
                }
                
                if(len == 0)
                {
                    throw std::invalid_argument("Invalid key length: len == 0");
                }
                
                if(k == NULL)
                {
                    throw std::invalid_argument("Invalid key: key == NULL");
                }
                
                uint8_t l = (kKeySize < len) ? kKeySize : len;
                
                std::memset(key_.data(), 0x00, kKeySize);
                std::memcpy(key_.data(),k,l);
                
                gen_padded_keys(key_);
            };
            
            HMac(const std::string& k)
            {
                uint8_t l = (kKeySize < k.size()) ? kKeySize : k.size();
                
                std::memset(key_.data(), 0x00, kKeySize);
                std::memcpy(key_.data(),k.data(),l);
                
                gen_padded_keys(key_);
            }
            
            HMac(const std::string& k, const uint8_t &len)
            {
                if(len > kKeySize)
                {
                    throw std::invalid_argument("Invalid key length: len > kKeySize");
                }
                
                if(len == 0)
                {
                    throw std::invalid_argument("Invalid key length: len == 0");
                }

                uint8_t l = (kKeySize < len) ? kKeySize : len;
                
                std::memset(key_.data(), 0x00, kKeySize);
                std::memcpy(key_.data(),k.data(),l);
                
                gen_padded_keys(key_);
            }
            
            HMac(const std::array<uint8_t,kKeySize>& k) : key_(k)
            {
                gen_padded_keys(k);
            };
            
            HMac(const HMac<H>& k) : key_(k.key_), o_key_(k.o_key_), i_key_(k.i_key_)
            {
                
            };
            
            // Destructor.
            // Set the content of the key to zero before destruction: remove all traces of the key in memory.
            ~HMac()
            {
                std::fill(key_.begin(), key_.end(), 0);
                std::fill(o_key_.begin(), o_key_.end(), 0);
                std::fill(i_key_.begin(), i_key_.end(), 0);
            };
            
            const std::array<uint8_t,kKeySize>& key() const
            {
                return key_;
            };
            
            const uint8_t* key_data() const
            {
                return key_.data();
            };
            
            void hmac(const unsigned char* in, const size_t &length, unsigned char* out,  const size_t &out_len = kDigestSize) const;
            std::array<uint8_t, H::kDigestSize> hmac(const unsigned char* in, const size_t &length) const;
            std::array<uint8_t, H::kDigestSize> hmac(const std::string &s) const;
            
        private:
            void gen_padded_keys(const std::array<uint8_t,kKeySize> &in_key);
            
            std::array<uint8_t,kKeySize> key_;
            std::array<uint8_t,kKeySize> o_key_;
            std::array<uint8_t,kKeySize> i_key_;
            
        };
        
        template <class H> void HMac<H>::gen_padded_keys(const std::array<uint8_t,kKeySize> &in_key)
        {
            memcpy(o_key_.data(), in_key.data(), kKeySize);
            memcpy(i_key_.data(), in_key.data(), kKeySize);
            
            for(uint8_t i = 0; i < kKeySize; ++i)
            {
                o_key_[i] ^= 0x5c;
                i_key_[i] ^= 0x36;
            }
        }
        
        // HMac instantiation
        // For now, use OpenSSL's HMAC-512 implementation
        template <class H> void HMac<H>::hmac(const unsigned char* in, const size_t &length, unsigned char* out, const size_t &out_len) const
        {
            assert(out_len <= kDigestSize);
            
            unsigned char* buffer, *tmp;
            size_t i_len = kKeySize + length;
            size_t o_len = kKeySize + kDigestSize;
            size_t buffer_len = (i_len > kDigestSize) ? i_len : (kDigestSize);
            
            buffer = new unsigned char [buffer_len];
            tmp = new unsigned char [o_len];
            
            memcpy(buffer, i_key_.data(), kKeySize);
            memcpy(buffer + kKeySize, in, length);
            
            H::hash(buffer, i_len, buffer);
            
            memcpy(tmp, o_key_.data(), kKeySize);
            memcpy(tmp + kKeySize, buffer, kDigestSize);
            
            H::hash(tmp, kKeySize + kDigestSize, buffer);
            
            std::memcpy(out, buffer, out_len);
            
            delete [] buffer;
            delete [] tmp;
        }
        
        template <class H> std::array<uint8_t, H::kDigestSize> HMac<H>::hmac(const unsigned char* in, const size_t &length) const
        {
            std::array<uint8_t, kDigestSize> result;
            
            hmac(in, length, result.data(), kDigestSize);
            
            return result;
        }
        
        // Convienience function to run HMac over a C++ string
        template <class H> std::array<uint8_t, H::kDigestSize> HMac<H>::hmac(const std::string &s) const
        {
            return hmac((const unsigned char*)s.data() , s.length());
        }
        
    } // namespace crypto
} // namespace sse
