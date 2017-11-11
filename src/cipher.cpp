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

#include "cipher.hpp"

#include "random.hpp"

#include <cstring>
#include <exception>
#include <iostream>
#include <iomanip>

#include <openssl/aes.h>
#include <sodium/utils.h>

namespace sse
{

namespace crypto
{

class Cipher::CipherImpl
{
public:
		
	// We use 48 bits IV. 
	// This is enough to encrypt 2^48 blocks which is the security bound of counter mode
	static constexpr uint8_t kIVSize = 6; 

    CipherImpl() = delete;
	
	CipherImpl(Key<kKeySize>&& k);
	
	~CipherImpl();

	void encrypt(const unsigned char* in, const size_t &len, unsigned char* out);
	void encrypt(const std::string &in, std::string &out);
	void decrypt(const unsigned char* in, const size_t &len, unsigned char* out);
	void decrypt(const std::string &in, std::string &out);


private:	
	Key<sizeof(AES_KEY)> aes_enc_key_;
	
	unsigned char iv_[kIVSize];
	uint64_t remaining_block_count_;
};
	

    Cipher::Cipher(Key<kKeySize>&& k) : cipher_imp_(new CipherImpl(std::move(k)))
{	
}

Cipher::~Cipher() 
{ 
	delete cipher_imp_;
}

void Cipher::encrypt(const std::string &in, std::string &out)
{
	cipher_imp_->encrypt(in, out);
}
void Cipher::decrypt(const std::string &in, std::string &out)
{
	cipher_imp_->decrypt(in, out);
}

// Cipher implementation

#define MIN(a,b) (((a) > (b)) ? (b) : (a))

// Compute maximum number of blocks that can be encrypted with the same key
// This number comes from the security reduction of CTR mode (2^48 blocks at most to retain 32 bits of security)
// and from the IV length (not more than 2^(8*kIVSize) different IVs)

Cipher::CipherImpl::CipherImpl(Key<kKeySize>&& k)
    : remaining_block_count_( ((uint64_t) 1) << MIN(48,8*kIVSize) )
{
    
    auto callback = [&k](uint8_t* key_content){
        if (AES_set_encrypt_key(k.unlock_get(), 128, reinterpret_cast<AES_KEY*>(key_content)) != 0)
        {
            // throw an exception
            throw std::runtime_error("Unable to init AES subkeys");
        }
    };
    
    aes_enc_key_ = Key<sizeof(AES_KEY)>(callback);
    k.erase();

    sodium_memzero(iv_, kIVSize);
}

Cipher::CipherImpl::~CipherImpl() 
{ 
}


void Cipher::CipherImpl::encrypt(const unsigned char* in, const size_t &len, unsigned char* out)
{
    if (len == 0) {
        throw std::invalid_argument("The minimum number of bytes to encrypt is 1.");
    }
	if(remaining_block_count_ < ((len/16)+1)){
		// throw an exception
		throw std::runtime_error("Too many blocks were encrypted with the same key. Encrypting using this key is now insecure."); /* LCOV_EXCL_LINE */
	}
	
    unsigned char enc_iv[AES_BLOCK_SIZE];
    unsigned char ecount[AES_BLOCK_SIZE];
    sodium_memzero(ecount, AES_BLOCK_SIZE);
	
	unsigned int num = 0;
	
	memcpy(out, iv_, kIVSize); // copy iv first

    if(kIVSize != AES_BLOCK_SIZE){
		sodium_memzero(enc_iv, AES_BLOCK_SIZE);
    }
    
	memcpy(enc_iv+AES_BLOCK_SIZE-kIVSize, iv_, kIVSize);
	
	// now append the ciphertext
    AES_ctr128_encrypt(in, out+kIVSize, len, reinterpret_cast<const AES_KEY*>(aes_enc_key_.unlock_get()), enc_iv, ecount, &num);
	
    aes_enc_key_.lock();
    
	// erase ecount to avoid (partial) recovery of the last block
	sodium_memzero(ecount, AES_BLOCK_SIZE);
	
	// decrement the block counter
	remaining_block_count_ -= (len/16 +1);
}

void Cipher::CipherImpl::encrypt(const std::string &in, std::string &out)
{
	size_t len = in.size();
    unsigned char *data = new unsigned char[len+kIVSize];

	encrypt((const unsigned char*)in.data(), len, data);
    out = std::string((char *)data, len+kIVSize);

    // erase the buffer
    sodium_memzero(data, len+kIVSize);
    
    delete [] data;
}

void Cipher::CipherImpl::decrypt(const unsigned char* in, const size_t &len, unsigned char* out)
{
    unsigned char ecount[AES_BLOCK_SIZE];
    unsigned char dec_iv[AES_BLOCK_SIZE];
    memset(ecount, 0x00, AES_BLOCK_SIZE);
    memset(dec_iv, 0x00, AES_BLOCK_SIZE);
	
	unsigned int num = 0;
	
	if(kIVSize != AES_BLOCK_SIZE)
		memset(dec_iv, 0, AES_BLOCK_SIZE);
	
	memcpy(dec_iv+AES_BLOCK_SIZE-kIVSize, in, kIVSize); // copy iv first
	
	// now append the ciphertext
  	AES_ctr128_encrypt(in+kIVSize, out, len-kIVSize, reinterpret_cast<const AES_KEY*>(aes_enc_key_.unlock_get()), dec_iv, ecount, &num);
	
    aes_enc_key_.lock();
    
	// erase ecount to avoid (partial) recovery of the last block
	sodium_memzero(ecount, AES_BLOCK_SIZE);
}

void Cipher::CipherImpl::decrypt(const std::string &in, std::string &out)
{
	size_t len = in.size();

    if (len <= kIVSize) {
        throw std::invalid_argument("The minimum number of bytes to decrypt is 1. The minimum length for a decryption input is kIVSize+1");
    }

    unsigned char *data = new unsigned char[len-kIVSize];
	decrypt((const unsigned char*)in.data(), len, data);

    out = std::string((char *)data, len-kIVSize);
    delete [] data;
}
	

}
}
