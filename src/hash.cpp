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

#include "hash.hpp"

#include "hash/sha512.hpp"
#include "hash/blake2b/blake2b.hpp"

#include <cstring>

#include <stdexcept>

namespace sse
{
	
namespace crypto
{
	
using hash_function = hash::blake2b;
	
void Hash::hash(const unsigned char *in, const size_t &len, unsigned char *out)
{
    if(in == NULL)
    {
        throw std::invalid_argument("in is NULL");
    }
    
    if(out == NULL)
    {
        throw std::invalid_argument("out is NULL");
    }

	// memset(out,0x00, kDigestSize);
	static_assert(kDigestSize == hash_function::kDigestSize, "Declared digest size and hash_function digest size do not match");
	static_assert(kBlockSize == hash_function::kBlockSize, "Declared block size and hash_function block size do not match");
	hash_function::hash(in, len, out);
}

void Hash::hash(const unsigned char *in, const size_t &len, const size_t &out_len, unsigned char *out)
{
    if(out_len > kDigestSize)
    {
        throw std::invalid_argument("Invalid output length: out_len > kDigestSize");
    }
    
    if(in == NULL)
    {
        throw std::invalid_argument("in is NULL");
    }
    
    if(out == NULL)
    {
        throw std::invalid_argument("out is NULL");
    }
    
    
	unsigned char digest[kDigestSize];

	hash(in, len, digest);
	memcpy(out, digest, out_len);
}

void Hash::hash(const std::string &in, std::string &out)
{
    unsigned char tmp_out [kDigestSize];
	hash((const unsigned char*)in.data(),in.length(),tmp_out);
    
    out = std::string((char *)tmp_out, kDigestSize);
}

void Hash::hash(const std::string &in, const size_t &out_len, std::string &out)
{
    if(out_len > kDigestSize)
    {
        throw std::invalid_argument("Invalid output length: out_len > kDigestSize");
    }

    unsigned char tmp_out [kDigestSize];

    hash((const unsigned char*)in.data(),in.length(),tmp_out);
    
    out = std::string((char *)tmp_out, out_len);
}

std::string Hash::hash(const std::string &in)
{
	std::string out;
	hash(in,out);
	return out;
}

std::string Hash::hash(const std::string &in, const size_t &out_len)
{
	std::string out;
	hash(in,out_len,out);
	return out;
}

}
}
