//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015 Raphael Bost
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

#pragma once

#include "random.hpp"
#include "hash.hpp"

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
	static constexpr uint8_t kKeySize = Hash::kBlockSize;
		
	Prf()
	{
		random_bytes(kKeySize, key_.data());
		gen_padded_keys(key_);
	};
	
	Prf(const void* k)
	{
		std::memcpy(key_.data(),k,kKeySize);
		gen_padded_keys(key_);
	};

	Prf(const void* k, const uint8_t &len)
	{
		assert(len <= kKeySize);
		uint8_t l = (kKeySize < len) ? kKeySize : len;
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k,l);

		gen_padded_keys(key_);
	};
	
	Prf(const std::string& k)
	{
		uint8_t l = (kKeySize < k.size()) ? kKeySize : k.size();
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k.data(),l);

		gen_padded_keys(key_);
	}
	
	Prf(const std::string& k, const uint8_t &len)
	{
		uint8_t l = (kKeySize < len) ? kKeySize : len;
		
		std::memset(key_.data(), 0x00, kKeySize);
		std::memcpy(key_.data(),k.data(),l);

		gen_padded_keys(key_);
	}
	
	Prf(const std::array<uint8_t,kKeySize>& k) : key_(k)
	{	
		gen_padded_keys(k);
	};

	Prf(const Prf<NBYTES>& k) : key_(k.key_), o_key_(k.o_key_), i_key_(k.i_key_)
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
	void gen_padded_keys(const std::array<uint8_t,kKeySize> &key);
	
	std::array<uint8_t,kKeySize> key_;
	std::array<uint8_t,kKeySize> o_key_;
	std::array<uint8_t,kKeySize> i_key_;

};

template <uint8_t NBYTES> void Prf<NBYTES>::gen_padded_keys(const std::array<uint8_t,kKeySize> &key)
{
	memcpy(o_key_.data(), key.data(), kKeySize);
	memcpy(i_key_.data(), key.data(), kKeySize);
	
	for(uint8_t i = 0; i < kKeySize; ++i)
	{
		o_key_[i] ^= 0x5c;
		i_key_[i] ^= 0x36;
	}
}

// PRF instantiation
// For now, use OpenSSL's HMAC-512 implementation
template <uint8_t NBYTES> std::array<uint8_t, NBYTES> Prf<NBYTES>::prf(const unsigned char* in, const size_t &length) const
{
	static_assert(NBYTES != 0, "PRF output length invalid: length must be strictly larger than 0");

	std::array<uint8_t, NBYTES> result;
	
	assert(NBYTES <= sse::crypto::Hash::kDigestSize);
	
	if(NBYTES <= sse::crypto::Hash::kDigestSize){
		// only need one output bloc of HMAC.

	    unsigned char* buffer, *tmp;
		unsigned int i_len = Hash::kBlockSize + length;
		unsigned int o_len = Hash::kBlockSize + Hash::kDigestSize;
		unsigned int buffer_len = (i_len > Hash::kDigestSize) ? i_len : (Hash::kDigestSize);
		
		buffer = new unsigned char [buffer_len];
		tmp = new unsigned char [o_len];
		
		memcpy(buffer, i_key_.data(), Hash::kBlockSize);
		memcpy(buffer + Hash::kBlockSize, in, length);
		
		
		Hash::hash(buffer, i_len, buffer);
		
		memcpy(tmp, o_key_.data(), Hash::kBlockSize);
		memcpy(tmp + Hash::kBlockSize, buffer, Hash::kDigestSize);

		Hash::hash(tmp, Hash::kBlockSize + Hash::kDigestSize, buffer);
		
		std::memcpy(result.data(), buffer, NBYTES);
		
		delete [] buffer;
		delete [] tmp;
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