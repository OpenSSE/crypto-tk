#pragma once

#include "random.hpp"

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
 * Prf class
 *
 * A wrapper for cryptographic keys pseudo-random function.
 * PRFs are templatized according to the length output: 
 * one must not be able to use the same PRF 
 * with different output lenght
******/

template <uint8_t NBYTES> class Prf
{
public:
	static constexpr uint8_t kKeySize = 32;
		
	Prf()
	{
		random_bytes(kKeySize, key_.data());
	};
	
	Prf(const void* k)
	{
		std::memcpy(key_.data(),k,kKeySize);
	};

	Prf(const void* k, const uint8_t &len)
	{
		assert(len <= kKeySize);
		uint8_t l = (kKeySize < len) ? kKeySize : len;
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k,l);
	};
	
	Prf(const std::string& k)
	{
		uint8_t l = (kKeySize < k.size()) ? kKeySize : k.size();
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k.data(),l);
	}
	
	Prf(const std::string& k, const uint8_t &len)
	{
		uint8_t l = (kKeySize < len) ? kKeySize : len;
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k.data(),l);
	}
	
	Prf(const std::array<uint8_t,kKeySize>& k) : key_(k)
	{	
	};

	Prf(const Prf<NBYTES>& k) : key_(k.key_)
	{	
	};

	// Destructor.
	// Set the content of the key to zero before destruction: remove all traces of the key in memory.
	~Prf() 
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
	
	std::array<uint8_t, NBYTES> prf(const unsigned char* in, const size_t &length) const;
	std::array<uint8_t, NBYTES> prf(const std::string &s) const;
	
private:
	std::array<uint8_t,kKeySize> key_;

};


// PRF instantiation
// For now, use OpenSSL's HMAC-512 implementation
template <uint8_t NBYTES> std::array<uint8_t, NBYTES> Prf<NBYTES>::prf(const unsigned char* in, const size_t &length) const
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
		
	    HMAC_Init_ex(&ctx, key_.data(), kKeySize, EVP_sha512(), NULL);
		
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
template <uint8_t NBYTES> std::array<uint8_t, NBYTES> Prf<NBYTES>::prf(const std::string &s) const
{
	return prf((unsigned char*)s.data() , s.length());
}

} // namespace crypto
} // namespace sse