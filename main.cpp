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

#include <iostream>
#include <iomanip>
#include <string>
#include <array>
#include <vector>
#include <chrono>

#include <cstring>
#include <netinet/in.h>
#include <openssl/sha.h>

#include "../src/hash.hpp"
#include "../src/hmac.hpp"
#include "src/hash/sha512.hpp"

#include "src/tdp.hpp"
#include "src/block_hash.hpp"
#include "src/prg.hpp"

#include "src/aesni/aesni.hpp"


using namespace std;

extern "C" void sha512_avx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_rorx(const void* M, void* D, uint64_t L);;
extern "C" void sha512_sse4(const void* M, void* D, uint64_t L);;
extern "C" void sha512_base(const void* M, void* D, uint64_t L);

#ifndef htonll
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#endif

#define BYTESWAP64(x) htonll(x)
#define UL64(x) x##ULL

constexpr uint64_t H[8] = {	0x6a09e667f3bcc908LL, 0xbb67ae8584caa73bLL,
    0x3c6ef372fe94f82bLL, 0xa54ff53a5f1d36f1LL,
    0x510e527fade682d1LL, 0x9b05688c2b3e6c1fLL,
    0x1f83d9abfb41bd6bLL, 0x5be0cd19137e2179LL};
	

static void sha512_update_acc(const unsigned char *in, unsigned char *digest, const uint64_t &block_len)
{

#ifdef __AVX2__
#pragma message "Use AVX2"
    sha512_rorx(in, (uint32_t*) digest, block_len);
#elif defined __AVX__
#pragma message "Use AVX"
    sha512_avx(in, (uint32_t*) digest, block_len);
#elif defined __SSE4_1__
#pragma message "Use SSE4"
    sha512_sse4(in, (uint32_t*) digest, block_len);
#else
	#error Intel SHA-2 code is not supported on this architecture
#endif

}


constexpr size_t kBlockSize = 128;
constexpr size_t kDigestSize = 64;

static void hash_acc(const unsigned char *in, const uint64_t &len, unsigned char *digest)
{
	unsigned char dbuf[64];
	memcpy(dbuf,H,64);
	

	size_t n_complete_blocks = len >> 7;
	uint64_t rem = len &  ((1<<7) -1);


	// first, hash the complete blocks
	if(n_complete_blocks){
		sha512_update_acc(in, dbuf, n_complete_blocks);
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
	
	cout << "Last block :\n";
	for(size_t i = 0; i < n_blocks*kBlockSize ; i++)
	{
        cout << hex << setw(2) << setfill('0') << (uint) buffer[i];
	}
	cout << endl;
	
	sha512_update_acc(buffer, dbuf, n_blocks);
		
	for(size_t i = 0; i < (kDigestSize >> 3); ++i)
	{
		((uint64_t *)dbuf)[i] = BYTESWAP64(((uint64_t *)dbuf)[i]);
	}
	
	memcpy(digest, dbuf, 64);
	delete [] buffer;
}
	
using namespace std;

static void open_ssl(const unsigned char *in, const uint64_t &len, unsigned char *digest)
{
	SHA512_CTX ctx;
	
	SHA512_Init(&ctx);
	

	size_t n_complete_blocks = len >> 7;
	uint64_t rem = len &  ((1<<7) -1);

	// first, hash the complete blocks
	if(n_complete_blocks){
		SHA512_Update(&ctx, in, n_complete_blocks << 7);
	}

	// if(rem || (len == 0)){
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
				
		cout << "Last block :\n";
		for(size_t i = 0; i < n_blocks*kBlockSize ; i++)
		{
	        cout << hex << setw(2) << setfill('0') << (uint) buffer[i];
		}
		cout << endl;
		
		SHA512_Update(&ctx, buffer, n_blocks*kBlockSize);
		
		memcpy(digest, ctx.h, 64);
		
		uint64_t *digest_64 = (uint64_t *)digest;
		
		for(size_t i = 0; i < kDigestSize; ++i)
		{
			digest_64[i] = BYTESWAP64(digest_64[i]);
		}
		
		// memcpy(digest, dbuf, 64);
	
		delete [] buffer;
	// }
}

static void open_ssl_full(const unsigned char *in, const uint64_t &len, unsigned char *digest)
{
	SHA512_CTX ctx;
	
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, in, len);
	SHA512_Final(digest, &ctx);
	
}

constexpr size_t kKeySize = kBlockSize;


class HashOpenSSLFull
{
public:
    constexpr static size_t kDigestSize = sse::crypto::Hash::kDigestSize;
    constexpr static size_t kBlockSize = sse::crypto::Hash::kBlockSize;
	
    static void hash(const unsigned char *in, const size_t &len, unsigned char *out)
	{
		open_ssl_full(in, len, out);
	}
	
};

class HashOpenSSL
{
public:
    constexpr static size_t kDigestSize = sse::crypto::Hash::kDigestSize;
    constexpr static size_t kBlockSize = sse::crypto::Hash::kBlockSize;
	
    static void hash(const unsigned char *in, const size_t &len, unsigned char *out)
	{
		open_ssl(in, len, out);
	}
	
};

class Local
{
public:
    constexpr static size_t kDigestSize = sse::crypto::Hash::kDigestSize;
    constexpr static size_t kBlockSize = sse::crypto::Hash::kBlockSize;
	
    static void hash(const unsigned char *in, const size_t &len, unsigned char *out)
	{
		hash_acc(in, len, out);
	}
	
};


static void benchmarks()
{
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
			open_ssl((const unsigned char*)in.data(), in.length(), (unsigned char*)out_openssl.data());
			auto end_ssl = std::chrono::high_resolution_clock::now();
		
			time_ssl += std::chrono::duration_cast<std::chrono::nanoseconds>(end_ssl-begin_ssl).count();
		
			auto begin_intel = std::chrono::high_resolution_clock::now();
			hash_acc((const unsigned char*)in.data(), in.length(), (unsigned char*)out_acc.data());
			auto end_intel = std::chrono::high_resolution_clock::now();
		
			time_intel += std::chrono::duration_cast<std::chrono::nanoseconds>(end_intel-begin_intel).count();
		
		
		}
		cout << "\r" << (j+1)*step << "/"<< bench_count << flush;
	}
	cout << endl;
	cout << "OpenSSL: " << time_ssl << " ms\n";
	cout << "Intel: " << time_intel << " ms\n";

}

static void test_hash()
{
	// string in = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	// string in = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	
	array<uint8_t,kKeySize> k;
	k.fill(0x0b);
	
	string in = "Hi There";
	// string in(1e6, 'a');
	
	sse::crypto::HMac<HashOpenSSLFull> hmac_full_ssl(k.data(),20);
	sse::crypto::HMac<HashOpenSSL> hmac_ssl(k.data(),20);
	sse::crypto::HMac<Local> hmac_local(k.data(),20);
	sse::crypto::HMac<sse::crypto::hash::sha512> hmac_lib(k.data(),20);
	
	cout << "====== FULL SSL ======\n";
	auto result_full_ssl = hmac_full_ssl.hmac((const unsigned char*)in.data(), in.length());
	cout << "\n\n";

	cout << "====== HOME SSL ======\n";
	auto result_ssl = hmac_ssl.hmac((const unsigned char*)in.data(), in.length());
	cout << "\n\n";

	cout << "====== LOCAL ======\n";
	auto result_local = hmac_local.hmac((const unsigned char*)in.data(), in.length());
	cout << "\n\n";
	
	cout << "====== LIB ======\n";
	auto result_lib = hmac_local.hmac((const unsigned char*)in.data(), in.length());
	cout << "\n\n";
	
	
	for(unsigned char c : result_full_ssl)
	{
        cout << hex << setw(2) << setfill('0') << (uint) c;
	}
	cout << "\n\n";
	for(unsigned char c : result_ssl)
	{
        cout << hex << setw(2) << setfill('0') << (uint) c;
	}
	cout << "\n\n";
	for(unsigned char c : result_local)
	{
        cout << hex << setw(2) << setfill('0') << (uint) c;
	}
	cout << "\n\n";
	for(unsigned char c : result_lib)
	{
        cout << hex << setw(2) << setfill('0') << (uint) c;
	}
	cout << "\n\n";
	
	
	return;

}

static void tdp()
{
    sse::crypto::TdpInverse tdp;
    
    cout << tdp.private_key() << endl;
    
    std::string in = tdp.sample();
    
    cout << "Original input:\n" << endl;
    for(unsigned char c : in)
    {
        cout << hex << setw(2) << setfill('0') << (uint) c;
    }

    std::string out = tdp.eval(in);
    
    cout << "\n\nOutput:\n" << endl;
    for(unsigned char c : out)
    {
        cout << hex << setw(2) << setfill('0') << (uint) c;
    }
    
    std::string dec = tdp.invert(out);
    
    cout << "\n\nDecrypted input:\n" << endl;
    for(unsigned char c : dec)
    {
        cout << hex << setw(2) << setfill('0') << (uint) c;
    }
    
    cout << endl;
}

static void bench_mult_invert_tdp()
{
    for (size_t i = 1; i < 100; i++) {
        sse::crypto::TdpInverse tdp_inv;
        
        string pk = tdp_inv.public_key();
        
        sse::crypto::Tdp tdp(pk);
        size_t mult_count = i;
        
        string sample = tdp_inv.sample();
        string goal, v;
        
        auto begin_mult = std::chrono::high_resolution_clock::now();
        goal = tdp_inv.invert_mult(sample, mult_count);
        auto end_mult = std::chrono::high_resolution_clock::now();
        
        std::chrono::duration<double, std::milli> time_mult = end_mult - begin_mult;
        std::cout << "Mult " << mult_count << ": " << time_mult.count() << " ms" << std::endl;

        
        v = sample;
        auto begin_iter = std::chrono::high_resolution_clock::now();

        for (size_t j = 0; j < mult_count; j++) {
            v = tdp_inv.invert(v);
        }
        auto end_iter = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double, std::milli> time_iter = end_iter - begin_iter;
        std::cout << "Iter " << mult_count << ": " << time_iter.count() << " ms" << std::endl;
        std::cout << std::endl;
    }

}


static void bench_hash_block()
{
    size_t N_sample = 1e7;
    
    sse::crypto::BlockHash::hash(std::string(16, 0x00));

    std::chrono::duration<double, std::nano> bh_time;
    for (size_t i = 0; i < N_sample; i++) {
        size_t in[4] = {i, 2*i, 3*i ,4*i};
        unsigned char out[16];
        
        auto begin_t = std::chrono::high_resolution_clock::now();
        sse::crypto::BlockHash::hash((unsigned char*)in, out);
        auto end_t = std::chrono::high_resolution_clock::now();
        
        bh_time += end_t - begin_t;
    }

    std::chrono::duration<double, std::nano> hash_time;
    for (size_t i = 0; i < N_sample; i++) {
        size_t in[4] = {i, 2*i, 3*i ,4*i};
        std::string in_string((char *)in, 16);
        
        auto begin_t = std::chrono::high_resolution_clock::now();
        std::string out = sse::crypto::Hash::hash(in_string);
        auto end_t = std::chrono::high_resolution_clock::now();
        
        hash_time += end_t - begin_t;
    }

    std::cout << "Block Hash: " << bh_time.count() << std::endl;
    std::cout << "Regular Hash: " << hash_time.count() << std::endl;
}

static void bench_prg()
{
    size_t N_sample = 1e7;
    
    std::array<uint8_t,16> key = {{0x00}};
    std::array<uint8_t,16*8> out;
    
    std::chrono::duration<double, std::nano> prg_time;
    auto begin_t = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < N_sample; i++) {
        sse::crypto::Prg::derive(key, 0, out);
        std::copy(out.begin(), out.begin()+16, key.begin());
    }
    auto end_t = std::chrono::high_resolution_clock::now();
    prg_time = end_t - begin_t;
    
    std::cout << "Prg time: " << prg_time.count() << std::endl;
//    std::cout << "Cycles: " << (double)sse::crypto::tick_counter/N_sample << std::endl;
}

int main( int argc, char* argv[] ) {
    bench_prg();
    return 0;
}