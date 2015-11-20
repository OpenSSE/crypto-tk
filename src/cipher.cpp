#include "cipher.hpp"

#include "random.hpp"

#include <openssl/aes.h>

namespace sse
{

namespace crypto
{

class Cipher::CipherImpl
{
public:
	static constexpr uint8_t kKeySize = 32;

	CipherImpl();
	
	CipherImpl(const std::array<uint8_t,kKeySize>& k);
	
	~CipherImpl();

	void gen_subkeys(const unsigned char *userKey);
	void reset_iv();

	void encrypt(const unsigned char* in, const size_t &len, unsigned char* out);
	void encrypt(const std::string &in, std::string &out);
	void decrypt(const unsigned char* in, const size_t &len, unsigned char* out);
	void decrypt(const std::string &in, std::string &out);


private:	
	AES_KEY aes_enc_key_;
	
	unsigned char iv_[AES_BLOCK_SIZE];
	uint64_t remaining_block_count_;
};
	

Cipher::Cipher() : cipher_imp_(new CipherImpl())
{
}

Cipher::Cipher(const std::array<uint8_t,kKeySize>& k) : cipher_imp_(new CipherImpl(k))
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

Cipher::CipherImpl::CipherImpl()
{
	unsigned char k[kKeySize];
	random_bytes(kKeySize, k);
	gen_subkeys(k);
	reset_iv();
}

Cipher::CipherImpl::CipherImpl(const std::array<uint8_t,kKeySize>& k)
{	
	gen_subkeys(k.data());
	reset_iv();
}

Cipher::CipherImpl::~CipherImpl() 
{ 
	// erase subkeys
	memset(&aes_enc_key_, 0x00, sizeof(AES_KEY));
}

void Cipher::CipherImpl::gen_subkeys(const unsigned char *userKey)
{
	if (!AES_set_encrypt_key(userKey, 128, &aes_enc_key_))
	{
		// throw an exception
	}
	
	remaining_block_count_ = 0xffffffffffffffff; // maximum value;
}

void Cipher::CipherImpl::reset_iv()
{
	memset(iv_, 0x00, AES_BLOCK_SIZE);
}

void Cipher::CipherImpl::encrypt(const unsigned char* in, const size_t &len, unsigned char* out)
{
	if(remaining_block_count_ < len){
		// throw an exception
	}
	
    unsigned char ecount[AES_BLOCK_SIZE];
    memset(ecount, 0x00, AES_BLOCK_SIZE);
	
	unsigned int num = 0;
	
	memcpy(out, iv_, AES_BLOCK_SIZE); // copy iv first
	
	// now append the ciphertext
    AES_ctr128_encrypt(in, out+AES_BLOCK_SIZE, len, &aes_enc_key_, iv_, ecount, &num);
	
	// erase ecount to avoid (partial) recovery of the last block
	memset(ecount, 0x00, AES_BLOCK_SIZE);
}

void Cipher::CipherImpl::encrypt(const std::string &in, std::string &out)
{
	unsigned int len = in.size();
	out.resize(len+AES_BLOCK_SIZE);
	encrypt((unsigned char*)in.data(), len, (unsigned char*)out.data());
}

void Cipher::CipherImpl::decrypt(const unsigned char* in, const size_t &len, unsigned char* out)
{
    unsigned char ecount[AES_BLOCK_SIZE];
    unsigned char dec_iv[AES_BLOCK_SIZE];
    memset(ecount, 0x00, AES_BLOCK_SIZE);
	
	unsigned int num = 0;
	
	memcpy(dec_iv, in, AES_BLOCK_SIZE); // copy iv first
	
	// now append the ciphertext
    AES_ctr128_encrypt(in+AES_BLOCK_SIZE, out, len, &aes_enc_key_, dec_iv, ecount, &num);
	
	// erase ecount to avoid (partial) recovery of the last block
	memset(ecount, 0x00, AES_BLOCK_SIZE);
}

void Cipher::CipherImpl::decrypt(const std::string &in, std::string &out)
{
	unsigned int len = in.size();
	out.resize(len-AES_BLOCK_SIZE);
	decrypt((unsigned char*)in.data(), len, (unsigned char*)out.data());
}
	

}
}