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

#include "sha512.hpp"

#include <cstdint>
#include <cstring>

#include <openssl/sha.h>
#include <netinet/in.h>

#include <iostream>
#include <iomanip>
#include <bitset>

using namespace std;


extern "C" void sha512_avx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_rorx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_sse4(const void* M, void* D, uint64_t L);;
extern "C" void sha512_base(const void* M, void* D, uint64_t L);;

#define BYTESWAP64(x) htonll(x)

constexpr uint64_t H[8] = {	0x6a09e667f3bcc908LL, 0xbb67ae8584caa73bLL,
    0x3c6ef372fe94f82bLL, 0xa54ff53a5f1d36f1LL,
    0x510e527fade682d1LL, 0x9b05688c2b3e6c1fLL,
    0x1f83d9abfb41bd6bLL, 0x5be0cd19137e2179LL};
                                            
namespace sse
{
	
namespace crypto
{

namespace hash
{
	
static void sha512_update(const unsigned char *in, unsigned char *digest, const uint64_t &block_len)
{
#ifdef __AVX2__
    sha512_rorx(in, (uint32_t*) digest, block_len);
#elif defined __AVX__
    sha512_avx(in, (uint32_t*) digest, block_len);
#elif defined __SSE4_1__
    sha512_sse4(in, (uint32_t*) digest, block_len);
#else
    sha512_base(in, (uint32_t*) digest, block_len);
#endif
	
}

#ifndef htonll
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#endif 

void sha512::hash(const unsigned char *in, const size_t &len, unsigned char *digest)
{
	unsigned char dbuf[64];
	memcpy(dbuf,H,64);
	

	size_t n_complete_blocks = len >> 7;
	uint64_t rem = len &  ((1<<7) -1);


	// first, hash the complete blocks
	if(n_complete_blocks){
		sha512_update(in, dbuf, n_complete_blocks);
	}
		
	uint8_t n_blocks = (rem < 112) ? 1 : 2;
	
    unsigned char *buffer = new unsigned char [n_blocks*kBlockSize];
	memcpy(buffer, in + (n_complete_blocks << 7),rem);
	buffer[rem] = 0x80;

	//write padding
	memset(buffer+rem+1, 0x00, n_blocks*kBlockSize - rem - 1);
	
	// copy the message length on 8 bytes
	// we do not support messages with more than 2^64-1 bits
	uint64_t bit_length = BYTESWAP64(len << 3);
	memcpy(buffer + n_blocks*kBlockSize-8, &bit_length, 8);
	
	sha512_update(buffer, dbuf, n_blocks);
		
	for(size_t i = 0; i < (kDigestSize >> 3); ++i)
	{
		((uint64_t *)dbuf)[i] = BYTESWAP64(((uint64_t *)dbuf)[i]);
	}
	
	memcpy(digest, dbuf, 64);
	delete [] buffer;
}

}
}
}