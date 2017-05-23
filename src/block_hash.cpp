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

#include "aesni/aesni.hpp"

#include <cstring>

#include <array>
#include <openssl/aes.h>

#include <iostream>
#include <iomanip>

namespace sse
{
    
    namespace crypto
    {
        class BlockHash::BlockHashImpl
        {
        public:
            
            static inline void hash(const unsigned char *in, unsigned char *out);
            static inline void hash(const std::string &in, std::string &out);
            static inline void hash(const std::string &in, const size_t out_len, std::string &out);
            static inline std::string hash(const std::string &in);
            static inline std::string hash(const std::string &in, const size_t out_len);
            
            static inline void mult_hash(const unsigned char *in, uint64_t in_len, unsigned char *out);

#if USE_AESNI
            typedef aes_subkeys_type key_type;
#else
            typedef AES_KEY key_type;
#endif
            
        private:
            static key_type *enc_key__;
          
            static std::array<uint8_t, AES_BLOCK_SIZE> iv__;
            
            inline const static key_type* get_key();
        };
        
        BlockHash::BlockHashImpl::key_type *BlockHash::BlockHashImpl::enc_key__ = NULL;

        // chosing this IV allows us to rely on the NIST's test vectors in the unit tests
        std::array<uint8_t, AES_BLOCK_SIZE> BlockHash::BlockHashImpl::iv__ = {{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}};
        
        
        const BlockHash::BlockHashImpl::key_type* BlockHash::BlockHashImpl::get_key()
        {
            
            if (enc_key__ == NULL) {
#if USE_AESNI
                enc_key__ = new aes_subkeys_type(aesni_derive_subkeys(iv__));
#else
                
                enc_key__ = new AES_KEY;

                if (AES_set_encrypt_key(iv__.data(), 128, enc_key__) != 0)
                {
                    // throw an exception
                    throw std::runtime_error("Unable to init AES subkeys");
                }
#endif
            }
            return enc_key__;
        }

    
    
        void BlockHash::BlockHashImpl::hash(const unsigned char *in,  unsigned char *out)
        {
            
#if USE_AESNI
            aesni_encrypt_xor1(in, *get_key(), out);
#else
            unsigned char *internal_out = out;
            
            if (in == out) {
                // the pointers are equal, we have to alloc some temporary memory
                internal_out = new unsigned char [AES_BLOCK_SIZE];
            }
            

            AES_encrypt(in, internal_out, get_key());
            
            for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {
                out[i] = internal_out[i] ^ in[i];
            }
            
            if (in == out) {
                delete []  internal_out;
            }
#endif            
        }
    
        
        
        void BlockHash::BlockHashImpl::mult_hash(const unsigned char *in, uint64_t in_len,  unsigned char *out)
        {
            if (in_len % AES_BLOCK_SIZE !=0) {
                throw std::invalid_argument("Invalid in_len: in_len%16 != 0");
            }
            
            if (in == NULL) {
                throw std::invalid_argument("in must not be NULL");
            }
            
            if (out == NULL) {
                throw std::invalid_argument("out must not be NULL");
            }

            
#if USE_AESNI
            aesni_encrypt_xor(in, in_len/AES_BLOCK_SIZE, *get_key(), out);
#else
            unsigned char *internal_out = out;

            if (in == out) {
                // the pointers are equal, we have to alloc some temporary memory
                internal_out = new unsigned char [in_len];
            }
            

            for (uint64_t i = 0; i < in_len/AES_BLOCK_SIZE; i++) {
                AES_encrypt(in + i*AES_BLOCK_SIZE, internal_out + i*AES_BLOCK_SIZE, get_key());
            }
            
            for (size_t i = 0; i < in_len; i++) {
                out[i] = internal_out[i] ^ in[i];
            }
            
            if (in == out) {
                delete []  internal_out;
            }
#endif

        }

        
        void BlockHash::hash(const unsigned char *in,  unsigned char *out)
        {
            BlockHash::BlockHashImpl::hash(in, out);
        }
    
        void BlockHash::hash(const unsigned char *in, const size_t out_len, unsigned char *out)
        {
            if (out_len > AES_BLOCK_SIZE) {
                throw std::invalid_argument("out_len is too large. out_len must be less than " + AES_BLOCK_SIZE);
            }

            if (out_len <= 0) {
                throw std::invalid_argument("out_len must be larger than 0");
            }
            
            if (in == NULL) {
                throw std::invalid_argument("in must not be NULL");
            }

            if (out == NULL) {
                throw std::invalid_argument("out must not be NULL");
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
                throw std::invalid_argument("out_len is too large. out_len must be less than " + AES_BLOCK_SIZE);
            }
            
            if (out_len <= 0) {
                throw std::invalid_argument("out_len must be larger than 0");
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
        
        void BlockHash::mult_hash(const unsigned char *in, uint64_t in_len, unsigned char *out)
        {
            BlockHash::BlockHashImpl::mult_hash(in, in_len, out);
        }


    }
}
