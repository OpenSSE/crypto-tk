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

#include <openssl/aes.h>

#include <iostream>

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
            
            PrgImpl() = delete;
            
            PrgImpl(const std::array<uint8_t,kKeySize>& k);
            PrgImpl(const uint8_t* k);
            
            ~PrgImpl();
            
            void derive(const size_t len, std::string &out) const;
            void derive(const size_t len, unsigned char* out) const;
            
            void derive(const uint32_t offset, const size_t len, unsigned char* out) const;
            void derive(const uint32_t offset, const size_t len, std::string &out) const;
            
            void gen_subkeys(const unsigned char *userKey);

            
            static constexpr uint8_t kBlockSize = AES_BLOCK_SIZE;

        private:
            AES_KEY aes_enc_key_;
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

        void Prg::derive(const size_t offset, const size_t len, std::string &out) const
        {
            prg_imp_->derive(offset, len, out);
        }
        
        std::string Prg::derive(const size_t offset, const size_t len) const
        {
            std::string out;
            
            prg_imp_->derive(offset,len, out);
            
            return out;
        }
        
        
        // Prg implementation
        
        Prg::PrgImpl::PrgImpl(const std::array<uint8_t,kKeySize>& k)
        {
            gen_subkeys(k.data());
        }
        
        Prg::PrgImpl::PrgImpl(const uint8_t* k)
        {
            gen_subkeys(k);
        }
        
        Prg::PrgImpl::~PrgImpl()
        {
            // erase subkeys
            memset(&aes_enc_key_, 0x00, sizeof(AES_KEY));
        }

#define MIN(a,b) (((a) > (b)) ? (b) : (a))
        void Prg::PrgImpl::gen_subkeys(const unsigned char *userKey)
        {
            if (AES_set_encrypt_key(userKey, 128, &aes_enc_key_) != 0)
            {
                // throw an exception
                throw std::runtime_error("Unable to init AES subkeys");
            }
        }

        void Prg::PrgImpl::derive(const size_t len, unsigned char* out) const
        {
            if (len == 0) {
                throw std::runtime_error("The minimum number of bytes to encrypt is 1.");
            }
            
            unsigned char enc_iv[AES_BLOCK_SIZE];
            unsigned char ecount[AES_BLOCK_SIZE];
            memset(ecount, 0x00, AES_BLOCK_SIZE);
            
            unsigned int num = 0;
            
            memset(enc_iv, 0, AES_BLOCK_SIZE);
            memset(out, 0, len);
            
            AES_ctr128_encrypt(out, out, len, &aes_enc_key_, enc_iv, ecount, &num);
            
            // erase ecount to avoid (partial) recovery of the last block
            memset(ecount, 0x00, AES_BLOCK_SIZE);
    
        
        }

        
        void Prg::PrgImpl::derive(const uint32_t offset, const size_t len, unsigned char* out) const
        {
            if (len == 0) {
                throw std::runtime_error("The minimum number of bytes to encrypt is 1.");
            }
            
            uint32_t block_offset = offset/AES_BLOCK_SIZE;
            
            unsigned char enc_iv[AES_BLOCK_SIZE];
            unsigned char ecount[AES_BLOCK_SIZE];
            memset(ecount, 0x00, AES_BLOCK_SIZE);
            
            uint32_t extra_len = (offset % AES_BLOCK_SIZE);
            
            unsigned char *tmp = new unsigned char[len+extra_len];

            unsigned int num = 0;
            
            memset(enc_iv, 0, AES_BLOCK_SIZE);
            memset(tmp, 0, len+extra_len);
            
            PUTU32(enc_iv + 12, block_offset);


            AES_ctr128_encrypt(tmp, tmp, len+extra_len, &aes_enc_key_, enc_iv, ecount, &num);
            
            // erase ecount to avoid (partial) recovery of the last block
            memset(ecount, 0x00, AES_BLOCK_SIZE);
            
            memcpy(out, tmp+extra_len, len);
            memset(tmp, 0x00, len+extra_len);
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

    }
}