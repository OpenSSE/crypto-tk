#include "random.hpp"

#include <openssl/aes.h>

#include <algorithm>
#include <array>
#include <fstream>

namespace sse
{

namespace crypto
{
	
class Drbg::DrbgImpl
{
public:
	DrbgImpl();
	~DrbgImpl();
	
	void fill();
	void reseed();
	void next(const size_t &byte_count, unsigned char* out);

private:
	AES_KEY aes_key_;
    std::array<unsigned char,1024> buffer_;
    unsigned char iv_[AES_BLOCK_SIZE];
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

	if (AES_set_encrypt_key(key_buf, 128, &aes_key_) != 0)
	{
		// throw an exception
		throw std::runtime_error("Unable to init AES subkeys");
	}


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
	
    unsigned char ecount[AES_BLOCK_SIZE];
    // memset(ecount, 0x00, AES_BLOCK_SIZE);
	
	unsigned int num = 0;
	
    AES_ctr128_encrypt(buffer_.data(), buffer_.data(), buffer_.size(), &aes_key_, iv_, ecount, &num);
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