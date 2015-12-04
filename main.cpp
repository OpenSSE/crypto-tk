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

#include <iostream>
#include <iomanip>
#include <string>
#include <array>
#include <chrono>


#include <openssl/sha.h>

using namespace std;

extern "C" void sha512_avx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_rorx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_sse4(const void* M, void* D, uint64_t L);;
#define BYTESWAP64(x) htonll(x)

constexpr uint64_t H[8] = {	0x6a09e667f3bcc908LL, 0xbb67ae8584caa73bLL,
    0x3c6ef372fe94f82bLL, 0xa54ff53a5f1d36f1LL,
    0x510e527fade682d1LL, 0x9b05688c2b3e6c1fLL,
    0x1f83d9abfb41bd6bLL, 0x5be0cd19137e2179LL};
	

static void sha512_update_acc(const unsigned char *in, unsigned char *digest, const uint64_t &block_len)
{
#ifdef __AVX2__
#warning AVX2
    sha512_rorx(in, (uint32_t*) digest, block_len);
#elif defined __AVX__
#warning AVX
    sha512_avx(in, (uint32_t*) digest, block_len);
#elif defined __SSE4_1__
#warning SSE4
    sha512_sse4(in, (uint32_t*) digest, block_len);
#else
	#error Intel SHA-2 code is not supported on this architecture
#endif

}


constexpr size_t kBlockSize = 128;
constexpr size_t kDigestSize = 64;

void hash_acc(const unsigned char *in, const uint64_t &len, unsigned char *digest)
{
    unsigned char dbuf[64];
    memcpy(digest,H,64);
	

	size_t n_complete_blocks = len >> 7;
	uint8_t rem = len &  ((1<<7) -1);


	// first, hash the complete blocks
	if(n_complete_blocks){
		sha512_update_acc(in, digest, n_complete_blocks);
	}

	if(rem){
		uint8_t n_blocks = (rem < 112) ? 1 : 2;
		
	    unsigned char *buffer = new unsigned char [n_blocks*kBlockSize];
		memcpy(buffer, in + (n_complete_blocks << 3),rem);
		buffer[rem] = 0x80;
	
		//write padding
		memset(buffer+rem+1, 0x00, n_blocks*kBlockSize - rem - 1);
		
		// copy the message length on 8 bytes
		// we do not support messages with more than 2^64-1 bits
		uint64_t bit_length = BYTESWAP64(len << 3);
		memcpy(buffer + n_blocks*kBlockSize-8, &bit_length, 8);
		
		sha512_update_acc(buffer, digest, n_blocks);
		
		uint64_t *digest_64 = (uint64_t *)digest;
		
		for(size_t i = 0; i < kDigestSize; ++i)
		{
			digest_64[i] = BYTESWAP64(digest_64[i]);
		}
		
	
		delete buffer;
	}
}

using namespace std;


void open_ssl(const unsigned char *in, const uint64_t &len, unsigned char *digest)
{
	SHA512_CTX ctx;
	
	SHA512_Init(&ctx);
	
    unsigned char dbuf[64];
    memcpy(digest,H,64);
	

	size_t n_complete_blocks = len >> 7;
	uint8_t rem = len &  ((1<<7) -1);

	// first, hash the complete blocks
	if(n_complete_blocks){
		SHA512_Update(&ctx, in, n_complete_blocks << 7);
	}

	if(rem){
		uint8_t n_blocks = (rem < 112) ? 1 : 2;
		
	    unsigned char *buffer = new unsigned char [n_blocks*kBlockSize];
		memcpy(buffer, in + (n_complete_blocks << 3),rem);
		buffer[rem] = 0x80;
	
		//write padding
		memset(buffer+rem+1, 0x00, n_blocks*kBlockSize - rem - 1);
		
		// copy the message length on 8 bytes
		// we do not support messages with more than 2^64-1 bits
		uint64_t bit_length = BYTESWAP64(len << 3);
		memcpy(buffer + n_blocks*kBlockSize-8, &bit_length, 8);
		
		SHA512_Update(&ctx, buffer, n_blocks*kBlockSize);
		
		memcpy(digest, ctx.h, 64);
		
		uint64_t *digest_64 = (uint64_t *)digest;
		
		for(size_t i = 0; i < kDigestSize; ++i)
		{
			digest_64[i] = BYTESWAP64(digest_64[i]);
		}
		
	
		delete buffer;
	}
}

int main( int argc, char* argv[] ) {
	// string in = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	// string in = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

	string out_openssl, out_acc;
	out_openssl.resize(kDigestSize);
	out_acc.resize(kDigestSize);

	size_t time_ssl = 0, time_intel = 0;
	size_t bench_count = 1e4;
	size_t step = 1000;
	
    srand ((uint)time(NULL));

	cout << "\r" << 0 << "/"<< bench_count << flush;

	for(size_t j = 0; j < bench_count/step; ++j){
		for(size_t i = 0; i < step; ++i)
		{
			string in(1e5, rand());
		
			auto begin_ssl = std::chrono::high_resolution_clock::now();
			open_ssl((unsigned char*)in.data(), in.length(), (unsigned char*)out_openssl.data());
			auto end_ssl = std::chrono::high_resolution_clock::now();
		
			time_ssl += std::chrono::duration_cast<std::chrono::nanoseconds>(end_ssl-begin_ssl).count();
		
			auto begin_intel = std::chrono::high_resolution_clock::now();
			hash_acc((unsigned char*)in.data(), in.length(), (unsigned char*)out_acc.data());
			auto end_intel = std::chrono::high_resolution_clock::now();
		
			time_intel += std::chrono::duration_cast<std::chrono::nanoseconds>(end_intel-begin_intel).count();
		
		
		}
		cout << "\r" << (j+1)*step << "/"<< bench_count << flush;
	}
	cout << endl;
	cout << "OpenSSL: " << time_ssl << " ms\n";
	cout << "Intel: " << time_intel << " ms\n";
	
	
	return 0;	
}