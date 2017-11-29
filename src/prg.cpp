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

#include <sodium/crypto_stream_chacha20.h>


#include <cstring>


// ChaCha is not really a all-in-one stream cipher (like RC4/Trivium/Grain)
// It is just a block cipher in counter mode
// To improve the performance and be able to jump to the right offset,
// we have to use the block size (64 bytes)
#define CHACHA20_BLOCK_SIZE 64

// static nonce
static const uint8_t chacha_nonce [8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

namespace sse
{
    
    namespace crypto
    {
        class Prg::PrgImpl
        {
        public:
            PrgImpl() = delete;
            
            inline PrgImpl(Key<kKeySize>&& key);
                        
            inline void derive(const size_t len, std::string &out) const;
            inline void derive(const size_t len, unsigned char* out) const;
            
            inline void derive(const uint32_t offset, const size_t len, unsigned char* out) const;
            inline void derive(const uint32_t offset, const size_t len, std::string &out) const;
            

            
            inline static void derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len, unsigned char* out);
            
        private:
     
            Key<kKeySize> key_;
        };
        
        
        Prg::Prg(Key<kKeySize>&& k) : prg_imp_(new PrgImpl(std::move(k)))
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

        void Prg::derive(Key<kKeySize>&& k, const size_t len, std::string &out)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(std::move(k), 0, len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            sodium_memzero(data, len);

            delete [] data;
        }
        
        void Prg::derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len, unsigned char* out)
        {
            Prg::PrgImpl::derive(std::move(k), offset, len, out);
        }

        std::string Prg::derive(Key<kKeySize>&& k, const size_t len)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(std::move(k), 0, len, data);
            std::string out = std::string((char *)data, len);
            
            // erase the buffer
            sodium_memzero(data, len);

            delete [] data;
            return out;
        }
        
        void Prg::derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len, std::string &out)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(std::move(k), offset, len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            sodium_memzero(data, len);

            delete [] data;
        }

        std::string Prg::derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len)
        {
            unsigned char *data = new unsigned char[len];
            
            Prg::PrgImpl::derive(std::move(k), offset, len, data);
            std::string out = std::string((char *)data, len);
            
            // erase the buffer
            sodium_memzero(data, len);

            delete [] data;
            return out;
        }

        

        // Prg implementation
        
        Prg::PrgImpl::PrgImpl(Key<kKeySize>&& key)
        : key_(std::move(key))
        {
        }
        
        void Prg::PrgImpl::derive(const size_t len, unsigned char* out) const
        {
            
            derive(0, len, out);
        }
        

        void Prg::PrgImpl::derive(const uint32_t offset, const size_t len, unsigned char* out) const
        {
            if (len == 0) {
                throw std::invalid_argument("The minimum number of bytes to derive is 1.");
            }
            
            uint32_t extra_len = (offset % CHACHA20_BLOCK_SIZE);
            uint32_t block_offset = offset/CHACHA20_BLOCK_SIZE;
            size_t max_block_index = (len+offset)/CHACHA20_BLOCK_SIZE;
            
            if ((len+offset)%CHACHA20_BLOCK_SIZE != 0) {
                max_block_index++;
            }
            
            size_t block_len = max_block_index - block_offset;

            memset(out, 0, len);

            key_.unlock();

            if (offset%CHACHA20_BLOCK_SIZE == 0) {
                // things are aligned, good !
                crypto_stream_chacha20_xor_ic(out, out, len, chacha_nonce, block_offset, key_.data());
            }else{
                // we need to create a buffer
                unsigned char *tmp = new unsigned char[block_len*CHACHA20_BLOCK_SIZE];
                memset(tmp, 0, block_len*CHACHA20_BLOCK_SIZE);

                crypto_stream_chacha20_xor_ic(tmp, tmp, block_len*CHACHA20_BLOCK_SIZE, chacha_nonce, block_offset, key_.data());

                memcpy(out, tmp+extra_len, len);
                sodium_memzero(tmp, block_len*CHACHA20_BLOCK_SIZE);

                delete [] tmp;
            }

            key_.lock();
        }

        void Prg::PrgImpl::derive(const size_t len, std::string &out) const
        {
            unsigned char *data = new unsigned char[len];
            
            derive(len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            sodium_memzero(data, len);

            delete [] data;
        }
        
        void Prg::PrgImpl::derive(const uint32_t offset, const size_t len, std::string &out) const
        {
            unsigned char *data = new unsigned char[len];
            
            derive(offset, len, data);
            out = std::string((char *)data, len);
            
            // erase the buffer
            sodium_memzero(data, len);

            delete [] data;
        }
        
        
        void Prg::PrgImpl::derive(Key<kKeySize>&& k, const uint32_t offset, const size_t len, unsigned char* out)
        {
            if (k.is_empty()) {
                throw std::invalid_argument("PRG input key is empty");
            }
            if (len == 0) {
                throw std::invalid_argument("The minimum number of bytes to derive is 1.");
            }
            
            Key<kKeySize> local_key(std::move(k)); // make sure the input key cannot be reused
            
            uint32_t extra_len = (offset % CHACHA20_BLOCK_SIZE);
            uint32_t block_offset = offset/CHACHA20_BLOCK_SIZE;
            size_t max_block_index = (len+offset)/CHACHA20_BLOCK_SIZE;
            
            if ((len+offset)%CHACHA20_BLOCK_SIZE != 0) {
                max_block_index++;
            }
            
            size_t block_len = max_block_index - block_offset;
            
            memset(out, 0, len);
            
            local_key.unlock();
            
            if (offset%CHACHA20_BLOCK_SIZE == 0) {
                // things are aligned, good !
                crypto_stream_chacha20_xor_ic(out, out, len, chacha_nonce, block_offset, local_key.data());
            }else{
                // we need to create a buffer
                unsigned char *tmp = new unsigned char[block_len*CHACHA20_BLOCK_SIZE];
                memset(tmp, 0, block_len*CHACHA20_BLOCK_SIZE);
                
                crypto_stream_chacha20_xor_ic(tmp, tmp, block_len*CHACHA20_BLOCK_SIZE, chacha_nonce, block_offset, local_key.data());
                
                memcpy(out, tmp+extra_len, len);
                sodium_memzero(tmp, block_len*CHACHA20_BLOCK_SIZE);
                
                delete [] tmp;
            }
            
            local_key.lock();
        }


    }

}

/* Instantiate some of the useful template sizes */

INSTANTIATE_PRG_TEMPLATE(16)
INSTANTIATE_PRG_TEMPLATE(32)

#ifdef CHECK_TEMPLATE_INSTANTIATION
#pragma message "Instantiate templates for unit tests and code coverage"
/* To avoid file duplication in code coverage report */

INSTANTIATE_PRG_TEMPLATE(10)
INSTANTIATE_PRG_TEMPLATE(18)
#endif
