#pragma once

#include <cstdint>
#include <cstring>
#include <cassert>

#include <string>
#include <array>

#include <openssl/hmac.h>

namespace sse
{

namespace crypto
{


/*****
 * PrfKey class
 *
 * A wrapper for cryptographic keys (i.e. array of bytes).
 * Keys are templatized according to the length output: 
 * one must not be able to use the same key for two PRFs 
 * with different output lenght
******/

template <uint8_t NBYTES> class PrfKey
{
public:
	static constexpr uint8_t kKeySize = 32;
		
	PrfKey(const void* k)
	{
		std::memcpy(key_.data(),k,kKeySize);
	};

	PrfKey(const void* k, const uint8_t &len)
	{
		assert(len <= kKeySize);
		uint8_t l = (kKeySize < len) ? kKeySize : len;
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k,l);
	};
	
	PrfKey(const std::string& k)
	{
		uint8_t l = (kKeySize < k.size()) ? kKeySize : k.size();
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k.data(),l);
	}
	
	PrfKey(const std::string& k, const uint8_t &len)
	{
		uint8_t l = (kKeySize < len) ? kKeySize : len;
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k.data(),l);
	}
	
	PrfKey(const std::array<uint8_t,kKeySize>& k) : key_(k)
	{	
	};

	PrfKey(const PrfKey<NBYTES>& k) : key_(k.key_)
	{	
	};

	// Destructor.
	// Set the content of the key to zero before destruction: remove all traces of the key in memory.
	~PrfKey() 
	{ 
		std::fill(key_.begin(), key_.end(), 0); 
	}; 

	const std::array<uint8_t,kKeySize>& key() const
	{
		return key_;
	};
	
	const uint8_t* key_data() const
	{
		return key_.data();
	};
	
	
private:
	std::array<uint8_t,kKeySize> key_;

};


// PRF instantiation
// For now, use OpenSSL's HMAC-512 implementation
template <uint8_t NBYTES> std::array<uint8_t, NBYTES> prf(const PrfKey<NBYTES> &key, const unsigned char* in, const size_t &length)
{
	static_assert(NBYTES != 0, "PRF output length invalid: length must be strictly larger than 0");

	std::array<uint8_t, NBYTES> result;
	
    
	if(NBYTES <= 64){
		HMAC_CTX ctx;
	    unsigned char* buffer;
		unsigned int len = 64;
		
		buffer = new unsigned char [len];
		
		// only need one output bloc of HMAC.
				
		HMAC_CTX_init(&ctx);
		
	    HMAC_Init_ex(&ctx, key.key_data(), PrfKey<NBYTES>::kKeySize, EVP_sha512(), NULL);
		
		HMAC_Update(&ctx, in, length);
		HMAC_Final(&ctx, buffer, &len);
		HMAC_CTX_cleanup(&ctx);
		
		// the buffer must be larger than the result
		assert(NBYTES <= len);
		
		std::memcpy(result.data(), buffer, NBYTES);
		
		delete [] buffer;
	}
	
	
	return result;
}

// Convienience function to run the PRF over a C++ string
template <uint8_t NBYTES> inline std::array<uint8_t, NBYTES> prf(const PrfKey<NBYTES> &key, const std::string &s)
{
	return prf<NBYTES>(key, (unsigned char*)s.data() , s.length());
}

} // namespace crypto
} // namespace sse