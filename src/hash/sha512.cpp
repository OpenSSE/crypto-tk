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

#include "sha512.hpp"

#include <cstdint>
#include <cstring>

#include <openssl/sha.h>

#include <iostream>
#include <iomanip>
#include <bitset>

using namespace std;


extern "C" void sha512_avx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_rorx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_sse4(const void* M, void* D, uint64_t L);;

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
	
void sha512::hash(const unsigned char *in, const size_t &len, unsigned char *out)
{
	// memset(out,0x00, kDigestSize);
	// SHA512_CTX c;
	// SHA512_Init(&c);
	// SHA512_Update(&c, in, len);
	// SHA512_Final(out, &c);
	hash_acc(in, len, out);
}

static void sha512_update(const unsigned char *in, unsigned char *digest, const uint8_t &block_len)
{
#ifdef __AVX2__
    sha512_rorx(in, (uint32_t*) digest, block_len);
#elif defined __AVX__
    sha512_avx(in, (uint32_t*) digest, block_len);
#elif defined __SSE4_1__
    sha512_sse4(in, (uint32_t*) digest, block_len);
#else
	#error Intel SHA-2 code is not supported on this architecture
#endif
	
}

#define BYTESWAP64(x) htonll(x)

void sha512::hash_acc(const unsigned char *in, const uint64_t &len, unsigned char *digest)
{
    // cout << endl;
    // print_128(buffer);
    // cout << endl;

    //use sha 512/256
    
    unsigned char dbuf[64];
    memcpy(digest,H,64);
	

	uint8_t n_complete_blocks = len >> 7;
	uint8_t rem = len &  ((1<<7) -1);


	cout << "Length " << len;
	cout << " ; " << n_complete_blocks << " complete_blocks " << endl;

	// first, hash the complete blocks
	if(n_complete_blocks){
		cout << "At least one complete block" << endl;
		sha512_update(in, digest, n_complete_blocks);
	}
	// for(size_t i = 0; i < (n_complete_blocks << 3); ++i)
	// {
	// 	cout << hex << setw(2) << setfill('0') << (uint)in[i];
	// }
	if(rem < 112) // one block left to hash
	{
	    unsigned char *buffer = new unsigned char [kBlockSize];
	
		// copy the remaining bytes of the input
		memcpy(buffer, in + (n_complete_blocks << 3),rem);
		buffer[rem] = 0x80;
	
		//write padding
		memset(buffer+rem+1, 0x00, kBlockSize - rem - 1);
	
		// copy the message length on 8 bytes
		uint64_t bit_length = BYTESWAP64(len << 3);
		memcpy(buffer + kBlockSize-8, &bit_length, 8);
		// memcpy(buffer + kBlockSize-1, &bit_length, 1);
	
		for(size_t i = 0; i < kBlockSize; ++i)
		{
			// cout  << setw(2) << setfill('0') << (uint)buffer[i];
			cout  << bitset<8>((uint)buffer[i]);
		}
		cout << endl;
	
		// hash
		sha512_update(buffer, digest, 1);
	
		uint64_t *digest_64 = (uint64_t *)digest;
		
		for(size_t i = 0; i < kDigestSize; ++i)
		{
			digest_64[i] = BYTESWAP64(digest_64[i]);
		}
		
		delete buffer;
	}else{ // two blocks to hash
	    unsigned char *buffer = new unsigned char [2*kBlockSize];
		
		memcpy(buffer, in + (n_complete_blocks << 3),rem);
		buffer[rem] = 0x80;
		memset(buffer+rem+1, 0x00, 2*kBlockSize - rem - 1);
		
		
		// copy the message length on 8 bytes
		uint64_t bit_length = BYTESWAP64(len << 3);
		memcpy(buffer + kBlockSize-8, &bit_length, 8);
		// memcpy(buffer + kBlockSize-1, &bit_length, 1);
	
		for(size_t i = 0; i < kBlockSize; ++i)
		{
			// cout  << setw(2) << setfill('0') << (uint)buffer[i];
			cout  << bitset<8>((uint)buffer[i]);
		}
		cout << endl;
	
		// hash
		sha512_update(buffer, digest, 1);
	
		uint64_t *digest_64 = (uint64_t *)digest;
		
		for(size_t i = 0; i < kDigestSize; ++i)
		{
			digest_64[i] = BYTESWAP64(digest_64[i]);
		}
		
		delete buffer;
	}
    cout << dec;
}


}
}
}