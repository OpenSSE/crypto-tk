//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2106 Raphael Bost
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

#include "random.hpp"

#include "aesni/aesni.hpp"

#include <cstring>
#include <algorithm>
#include <array>
#include <fstream>

#include <openssl/aes.h>

namespace sse
{

namespace crypto
{
	
class Drbg::DrbgImpl
{
public:
#if USE_AESNI
    typedef aes_subkeys_type key_type;
#else
    typedef AES_KEY key_type;
#endif
    

	DrbgImpl();
	~DrbgImpl();
	
	void fill();
	void reseed();
	void next(const size_t &byte_count, unsigned char* out);

private:
    static constexpr uint64_t kBlockCount = 64;
    
	key_type aes_key_;
    std::array<unsigned char,16*kBlockCount> buffer_;
    
#if USE_AESNI
    uint64_t iv_;
#else
    unsigned char iv_[AES_BLOCK_SIZE];
#endif
    
    size_t buffer_pos_;
    size_t remaining_bytes_;
	
	static size_t kReseedBytesCount;
};

size_t Drbg::DrbgImpl::kReseedBytesCount = 1024 * 1024 * 1024; // 1 GiB


Drbg::Drbg() : drdg_imp_(new DrbgImpl())
{
}

Drbg::~Drbg()
{
	delete drdg_imp_;
}

void Drbg::reseed()
{
	drdg_imp_->reseed();
}	
	
void Drbg::next(const size_t &byte_count, unsigned char* out)
{
	drdg_imp_->next(byte_count, out);
}


Drbg::DrbgImpl::DrbgImpl()
    : aes_key_{}, buffer_{}, iv_{}, buffer_pos_(0), remaining_bytes_(0)
{
	reseed();
	fill();
}

Drbg::DrbgImpl::~DrbgImpl()
{
	// erase subkeys
	memset(&aes_key_, 0x00, sizeof(AES_KEY));
}

void Drbg::DrbgImpl::reseed()
{
	unsigned char* key_buf = new unsigned char[16];
	std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
	urandom.read((char*) key_buf,16);
	urandom.close();

#if USE_AESNI
    aes_key_ = aesni_derive_subkeys(key_buf);
    iv_ = 0;
#else
	if (AES_set_encrypt_key(key_buf, 128, &aes_key_) != 0)
	{
		// throw an exception
		throw std::runtime_error("Unable to init AES subkeys");
	}
    memset(iv_, 0x00, AES_BLOCK_SIZE);
#endif


	// erase the key buffer
	memset(key_buf, 0x00, 16);
	delete [] key_buf;
	
	remaining_bytes_ = kReseedBytesCount;
}
	
void Drbg::DrbgImpl::fill()
{
	if(remaining_bytes_ < buffer_.size())
	{
		reseed();
	}
	
	remaining_bytes_ -= buffer_.size();
	
	
#if USE_AESNI
    aesni_ctr(kBlockCount, iv_, aes_key_, buffer_.data());
    iv_ += kBlockCount;
#else
    unsigned char ecount[AES_BLOCK_SIZE];
    // memset(ecount, 0x00, AES_BLOCK_SIZE);
    
    unsigned int num = 0;

    AES_ctr128_encrypt(buffer_.data(), buffer_.data(), buffer_.size(), &aes_key_, iv_, ecount, &num);
#endif
    buffer_pos_ = 0;
}
	
void Drbg::DrbgImpl::next(const size_t &byte_count, unsigned char* out)
{
	size_t pos = 0;
    while (pos < byte_count) {
      size_t n = std::min(buffer_.size() - buffer_pos_, byte_count);
      memcpy(out, buffer_.data() + buffer_pos_, n);
      buffer_pos_ += n;
	  pos += n;
	  
      if (buffer_pos_ == buffer_.size())
        fill();
    }
	
}

}
}