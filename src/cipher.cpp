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
	
	CipherImpl(const std::array<uint8_t,kKeySize>& k);
	CipherImpl(const uint8_t* k);
	
	~CipherImpl();

	void gen_subkeys(const unsigned char *userKey);
	void reset_iv();

	void encrypt(const unsigned char* in, const size_t &len, unsigned char* out);
	void encrypt(const std::string &in, std::string &out);
	void decrypt(const unsigned char* in, const size_t &len, unsigned char* out);
	void decrypt(const std::string &in, std::string &out);


private:	
	AES_KEY aes_enc_key_;
	
	unsigned char iv_[kIVSize];
	uint64_t remaining_block_count_;
};
	

Cipher::Cipher(const std::array<uint8_t,kKeySize>& k) : cipher_imp_(new CipherImpl(k))
{	
}

Cipher::Cipher(const uint8_t* k) : cipher_imp_(new CipherImpl(k))
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

Cipher::CipherImpl::CipherImpl(const std::array<uint8_t,kKeySize>& k)
    : aes_enc_key_{}, remaining_block_count_(0)
{	
	gen_subkeys(k.data());
	reset_iv();
}

Cipher::CipherImpl::CipherImpl(const uint8_t* k)
    : aes_enc_key_{}, remaining_block_count_(0)
{
	gen_subkeys(k);
	reset_iv();
}

Cipher::CipherImpl::~CipherImpl() 
{ 
	// erase subkeys
	memset(&aes_enc_key_, 0x00, sizeof(AES_KEY));
}

#define MIN(a,b) (((a) > (b)) ? (b) : (a))
void Cipher::CipherImpl::gen_subkeys(const unsigned char *userKey)
{
	if (AES_set_encrypt_key(userKey, 128, &aes_enc_key_) != 0)
	{
		// throw an exception
		throw std::runtime_error("Unable to init AES subkeys");
	}
	
	// Compute maximum number of blocks that can be encrypted with the same key
	// This number comes from the security reduction of CTR mode (2^48 blocks at most to retain 32 bits of security)
	// and from the IV length (not more than 2^(8*kIVSize) different IVs) 
	remaining_block_count_ = ((uint64_t) 1) << MIN(48,8*kIVSize); 
}

void Cipher::CipherImpl::reset_iv()
{
	memset(iv_, 0x00, kIVSize);
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
    memset(ecount, 0x00, AES_BLOCK_SIZE);
	
	unsigned int num = 0;
	
	memcpy(out, iv_, kIVSize); // copy iv first

	if(kIVSize != AES_BLOCK_SIZE)
		memset(enc_iv, 0, AES_BLOCK_SIZE);
	
	memcpy(enc_iv+AES_BLOCK_SIZE-kIVSize, iv_, kIVSize);
	
	// now append the ciphertext
    AES_ctr128_encrypt(in, out+kIVSize, len, &aes_enc_key_, enc_iv, ecount, &num);
	
	// erase ecount to avoid (partial) recovery of the last block
	memset(ecount, 0x00, AES_BLOCK_SIZE);
	
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
    memset(data, 0, len+kIVSize);
    
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
  	AES_ctr128_encrypt(in+kIVSize, out, len-kIVSize, &aes_enc_key_, dec_iv, ecount, &num);
	
	// erase ecount to avoid (partial) recovery of the last block
	memset(ecount, 0x00, AES_BLOCK_SIZE);
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
