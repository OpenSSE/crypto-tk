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


#include "prg.hpp"
#include "aesni/aesni.hpp"

#include <openssl/aes.h>
#include <openssl/modes.h>


#include <cstring>

#include <iostream>
#include <iomanip>

#define PUTU32(ct, st) { \
    (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); \
    (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }

#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ \
                        ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))

namespace sse
{
    
    namespace crypto
    {
        class Prg::PrgImpl
        {
        public:
#if USE_AESNI
            typedef aes_subkeys_type key_type;
#else
            typedef AES_KEY key_type;
#endif
            

            PrgImpl() = delete;
            
            inline PrgImpl(const std::array<uint8_t,kKeySize>& k);
            inline PrgImpl(const uint8_t* k);
            
            inline ~PrgImpl();
            
            inline void derive(const size_t len, std::string &out) const;
            inline void derive(const size_t len, unsigned char* out) const;
            
            inline void derive(const uint32_t offset, const size_t len, unsigned char* out) const;
            inline void derive(const uint32_t offset, const size_t len, std::string &out) const;
            
            inline void gen_subkeys(const unsigned char *userKey);

            
            inline static void derive(const uint8_t* k, const uint32_t offset, const size_t len, unsigned char* out);
            
            static constexpr uint8_t kBlockSize = AES_BLOCK_SIZE;

        private:
            
            key_type aes_enc_key_;


        };
        
        
        Prg::Prg(const std::array<uint8_t,kKeySize>& k) : prg_imp_(new PrgImpl(k))
        {
        }
        
        Prg::Prg(const uint8_t* k) : prg_imp_(new PrgImpl(k))
        {
            
        }
        
        Prg::~Prg()
        {
            delete prg_imp_;
        }
        
        void Prg::derive(const size_t len, std::string &out) const
        {
            prg_imp_->derive(len, out);
        }

        std::string Prg::derive(const size_t len) const
        {
            std::string out;
            
            prg_imp_->derive(len, out);
            
            return out;
        }

        void Prg::derive(const uint32_t offset, const size_t len, std::string &out) const
        {
            prg_imp_->derive(offset, len, out);
        }
        
        std::string Prg::derive(const uint32_t offset, const size_t len) const
        {
            std::string out;
            
            prg_imp_->derive(offset,len, out);
            
            return out;
        }
        
        void Prg::derive(const uint32_t offset, const size_t len, unsigned char* out) const
        {
            prg_imp_->derive(offset,len, out);
        }

        void Prg::derive(const uint8_t* k, const size_t len, std::string &out)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(k, 0, len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            memset(data, 0, len);
            
            delete [] data;
        }
        
        void Prg::derive(const std::array<uint8_t,Prg::kKeySize>& k, const size_t len, std::string &out)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(k.data(), 0, len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            memset(data, 0, len);
            
            delete [] data;
        }
        
        void Prg::derive(const uint8_t* k, const uint32_t offset, const size_t len, unsigned char* out)
        {
            Prg::PrgImpl::derive(k, offset, len, out);
        }

        std::string Prg::derive(const std::array<uint8_t,Prg::kKeySize>& k, const size_t len)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(k.data(), 0, len, data);
            std::string out = std::string((char *)data, len);
            
            // erase the buffer
            memset(data, 0, len);
            
            delete [] data;
            return out;
        }
        
        void Prg::derive(const std::array<uint8_t,Prg::kKeySize>& k, const uint32_t offset, const size_t len, std::string &out)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(k.data(), offset, len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            memset(data, 0, len);
            
            delete [] data;
        }

        std::string Prg::derive(const std::array<uint8_t,Prg::kKeySize>& k, const uint32_t offset, const size_t len)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(k.data(), offset, len, data);
            std::string out = std::string((char *)data, len);
            
            // erase the buffer
            memset(data, 0, len);
            
            delete [] data;
            return out;
        }

        

        // Prg implementation
        
        Prg::PrgImpl::PrgImpl(const std::array<uint8_t,kKeySize>& k)
        : aes_enc_key_{}
        {
            gen_subkeys(k.data());
        }
        
        Prg::PrgImpl::PrgImpl(const uint8_t* k)
        : aes_enc_key_{}
        {
            gen_subkeys(k);
        }
        
        Prg::PrgImpl::~PrgImpl()
        {
            // erase subkeys
#if USE_AESNI
            std::fill(aes_enc_key_.begin(), aes_enc_key_.end(), 0x00);
#else
            memset(&aes_enc_key_, 0x00, sizeof(AES_KEY));
#endif
        }

#define MIN(a,b) (((a) > (b)) ? (b) : (a))
        void Prg::PrgImpl::gen_subkeys(const unsigned char *userKey)
        {
            if (userKey == NULL) {
                throw std::invalid_argument("PRG input key is NULL");
            }

#if USE_AESNI
            aes_enc_key_ = aesni_derive_subkeys(userKey);
#else
            if (AES_set_encrypt_key(userKey, 128, &aes_enc_key_) != 0)
            {
                // throw an exception
                throw std::runtime_error("Unable to init AES subkeys");
            }
#endif
        }

        void Prg::PrgImpl::derive(const size_t len, unsigned char* out) const
        {
            
            derive(0, len, out);
        }
        

        void Prg::PrgImpl::derive(const uint32_t offset, const size_t len, unsigned char* out) const
        {
            if (len == 0) {
                throw std::invalid_argument("The minimum number of bytes to encrypt is 1.");
            }
            
            uint32_t extra_len = (offset % AES_BLOCK_SIZE);
            uint32_t block_offset = offset/AES_BLOCK_SIZE;
            size_t max_block_index = (len+offset)/AES_BLOCK_SIZE;
            
            if ((len+offset)%AES_BLOCK_SIZE != 0) {
                max_block_index++;
            }
            
            size_t block_len = max_block_index - block_offset;

            
#if USE_AESNI
            if (offset%AES_BLOCK_SIZE == 0 && len%AES_BLOCK_SIZE == 0) {
                // things are aligned, good !
                
                aesni_ctr(block_len, block_offset, aes_enc_key_, out);
                
            }else{
                // we need to create a buffer
                unsigned char *tmp = new unsigned char[block_len*AES_BLOCK_SIZE];
                aesni_ctr(block_len, block_offset, aes_enc_key_, tmp);

                memcpy(out, tmp+extra_len, len);
                memset(tmp, 0x00, block_len*AES_BLOCK_SIZE);

                delete [] tmp;
            }
#else
            unsigned char *in = new unsigned char[block_len*AES_BLOCK_SIZE];
            memset(in, 0x00, block_len*AES_BLOCK_SIZE);
            
            unsigned char *tmp = new unsigned char[block_len*AES_BLOCK_SIZE];

            for (size_t i = block_offset; i < max_block_index; i++) {
                ((size_t*)in)[2*(i-block_offset)] = i;
            }
            
            memset(out, 0, len);
            
            for (size_t i = 0; i < block_len; i++) {
                AES_encrypt(in+i*AES_BLOCK_SIZE, tmp+i*AES_BLOCK_SIZE, &aes_enc_key_);
            }
            
            memcpy(out, tmp+extra_len, len);
            memset(tmp, 0x00, block_len*AES_BLOCK_SIZE);
            
            delete [] tmp;
            delete [] in;
#endif
        }

        void Prg::PrgImpl::derive(const size_t len, std::string &out) const
        {
            unsigned char *data = new unsigned char[len];
            
            derive(len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            memset(data, 0, len);

            delete [] data;
        }
        
        void Prg::PrgImpl::derive(const uint32_t offset, const size_t len, std::string &out) const
        {
            unsigned char *data = new unsigned char[len];
            
            derive(offset, len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            memset(data, 0, len);
            
            delete [] data;
        }
        
        
        void Prg::PrgImpl::derive(const uint8_t* k, const uint32_t offset, const size_t len, unsigned char* out)
        {
            if (k == NULL) {
                throw std::invalid_argument("PRG input key is NULL");
            }
            if (len == 0) {
                throw std::invalid_argument("The minimum number of bytes to encrypt is 1.");
            }
            
            uint32_t extra_len = (offset % AES_BLOCK_SIZE);
            uint32_t block_offset = offset/AES_BLOCK_SIZE;
            size_t max_block_index = (len+offset)/AES_BLOCK_SIZE;
            
            if ((len+offset)%AES_BLOCK_SIZE != 0) {
                max_block_index++;
            }
            
            size_t block_len = max_block_index - block_offset;
            
            
#if USE_AESNI
            if (offset%AES_BLOCK_SIZE == 0 && len%AES_BLOCK_SIZE == 0) {
                // things are aligned, good !
                
                aesni_ctr(block_len, block_offset, k, out);
                
            }else{
                // we need to create a buffer
                unsigned char *tmp = new unsigned char[block_len*AES_BLOCK_SIZE];
                aesni_ctr(block_len, block_offset, k, tmp);
                
                memcpy(out, tmp+extra_len, len);
                memset(tmp, 0x00, block_len*AES_BLOCK_SIZE);
                
                delete [] tmp;
            }
#else
            key_type aes_enc_key;

            if (AES_set_encrypt_key(k, 128, &aes_enc_key) != 0)
            {
                // throw an exception
                throw std::runtime_error("Unable to init AES subkeys");
            }

            unsigned char *in = new unsigned char[block_len*AES_BLOCK_SIZE];
            memset(in, 0x00, block_len*AES_BLOCK_SIZE);
            
            unsigned char *tmp = new unsigned char[block_len*AES_BLOCK_SIZE];
            
            for (size_t i = block_offset; i < max_block_index; i++) {
                ((size_t*)in)[2*(i-block_offset)] = i;
            }
            
            memset(out, 0, len);
            
            for (size_t i = 0; i < block_len; i++) {
                AES_encrypt(in+i*AES_BLOCK_SIZE, tmp+i*AES_BLOCK_SIZE, &aes_enc_key);
            }
            
            memcpy(out, tmp+extra_len, len);
            memset(tmp, 0x00, block_len*AES_BLOCK_SIZE);
            memset(&aes_enc_key, 0x00, sizeof(key_type));
            
            
            delete [] tmp;
            delete [] in;
#endif
        }

    }

}
