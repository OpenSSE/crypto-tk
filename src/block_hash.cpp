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

#include "block_hash.hpp"

#include <cstring>

#include <array>
#include <openssl/aes.h>

#include <iostream>
#include <iomanip>

namespace sse
{
    
    namespace crypto
    {
        
#if AESNI_OPENSSL_UNDO
#warning Using OpenSSL undocumented code. You might have to use your own recompile libcrypto
        extern "C" {
            int aesni_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key);
            int aesni_set_decrypt_key(const unsigned char *userKey, int bits, AES_KEY *key);
            
            void aesni_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
        }
#endif
        class BlockHash::BlockHashImpl
        {
        public:
            
            static inline void hash(const unsigned char *in, unsigned char *out);
            static inline void hash(const std::string &in, std::string &out);
            static inline void hash(const std::string &in, const size_t out_len, std::string &out);
            static inline std::string hash(const std::string &in);
            static inline std::string hash(const std::string &in, const size_t out_len);
            
        private:
            static AES_KEY *enc_key__;
            static std::array<uint8_t, AES_BLOCK_SIZE> iv__;
            
            inline const static AES_KEY* get_key();
        };
        
        AES_KEY *BlockHash::BlockHashImpl::enc_key__ = NULL;
        
//        std::array<uint8_t, AES_BLOCK_SIZE> BlockHash::BlockHashImpl::iv__ = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
        
        // chosing this IV allows us to rely on the NIST's test vectors in the unit tests
        std::array<uint8_t, AES_BLOCK_SIZE> BlockHash::BlockHashImpl::iv__ = {{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}};
        
        
        const AES_KEY* BlockHash::BlockHashImpl::get_key()
        {
            
            if (enc_key__ == NULL) {
                enc_key__ = new AES_KEY;
                
#if AESNI_OPENSSL_UNDO
                if (aesni_set_encrypt_key(iv__.data(), 128, enc_key__) != 0)
#else
                if (AES_set_encrypt_key(iv__.data(), 128, enc_key__) != 0)
#endif
                {
                    // throw an exception
                    throw std::runtime_error("Unable to init AES subkeys");
                }
            }
            return enc_key__;
        }

    
    
        void BlockHash::BlockHashImpl::hash(const unsigned char *in,  unsigned char *out)
        {
#if AESNI_OPENSSL_UNDO
            aesni_encrypt(in, out, get_key());
            
//            std::cout << "NI: \t\t";
//            for(size_t j = 0; j <  AES_BLOCK_SIZE; j++)
//            {
//                std::cout << std::hex << std::setw(2) << std::setfill('0') << (uint) *(out+j);
//            }
//            std::cout << std::endl;

#else
            AES_encrypt(in, out, get_key());
#endif
            for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                out[i] ^= in[i];
            }
        }
    
        
        
        void BlockHash::hash(const unsigned char *in,  unsigned char *out)
        {
            BlockHash::BlockHashImpl::hash(in, out);
        }
    
        void BlockHash::hash(const unsigned char *in, const size_t out_len, unsigned char *out)
        {
            if (out_len > AES_BLOCK_SIZE) {
                throw std::runtime_error("out_len is too large. out_len must be less than " + AES_BLOCK_SIZE);
            }

            if (out_len <= 0) {
                throw std::runtime_error("out_len must be larger than 0");
            }

            unsigned char tmp [AES_BLOCK_SIZE];
            
            hash(in, tmp);
            
            memcpy(out, tmp, out_len);
            memset(tmp, 0x00, AES_BLOCK_SIZE);
        }
        
        void BlockHash::hash(const std::string &in, std::string &out)
        {
            unsigned char tmp [AES_BLOCK_SIZE];
            hash(reinterpret_cast<const unsigned char*>(in.data()), tmp);
            
            out = std::string((char *)tmp, AES_BLOCK_SIZE);
            memset(tmp, 0x00, AES_BLOCK_SIZE);
        }
        
        void BlockHash::hash(const std::string &in, const size_t out_len, std::string &out)
        {
            if (out_len > AES_BLOCK_SIZE) {
                throw std::runtime_error("out_len is too large. out_len must be less than " + AES_BLOCK_SIZE);
            }
            
            if (out_len <= 0) {
                throw std::runtime_error("out_len must be larger than 0");
            }
            
            unsigned char tmp [AES_BLOCK_SIZE];
            hash(reinterpret_cast<const unsigned char*>(in.data()), tmp);
            
            out = std::string((char *)tmp, out_len);
            memset(tmp, 0x00, AES_BLOCK_SIZE);

        }
        
        std::string BlockHash::hash(const std::string &in)
        {
            std::string out;
            hash(in, out);
            return out;
        }
        
        std::string BlockHash::hash(const std::string &in, const size_t out_len)
        {
            std::string out;
            hash(in, out_len, out);
            return out;
        }
        

    }
}