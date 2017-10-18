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


/*******
 *  hashing.cpp
 *
 *  Implementation of SHA-512's test vector verification.
 *  Reference vectors are taken from NIST's test vectors.
 ********/

#include "../src/hash.hpp"
#include "../src/hash/sha512.hpp"
#include "../src/hash/blake2s/blake2s.hpp"
#include "../src/hash/blake2b/blake2b.hpp"

#include "blake2_kat.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <array>

#include "gtest/gtest.h"

using namespace std;

TEST(sha_512, test_vector_1)
{

	string in = "abc";
    std::array<uint8_t, sse::crypto::hash::sha512::kDigestSize> out;
    
	sse::crypto::hash::sha512::hash((const unsigned char*)in.data(), in.length(), (unsigned char*)out.data());
	
	uint8_t reference[] = {
					0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
					0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
					0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 
					0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
				};
			
    string ref_string((char*)reference, sse::crypto::hash::sha512::kDigestSize);
    string out_string((char*)out.data(), sse::crypto::hash::sha512::kDigestSize);
    
    
    ASSERT_EQ(out_string, ref_string);
}

TEST(sha_512, test_vector_2)
{
	string in = "";
    std::array<uint8_t, sse::crypto::hash::sha512::kDigestSize> out;

    sse::crypto::hash::sha512::hash((const unsigned char*)in.data(), in.length(), (unsigned char*)out.data());
	
	uint8_t reference[] = {
					0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 
					0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
					0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 
					0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
				};
												
    string ref_string((char*)reference, sse::crypto::hash::sha512::kDigestSize);
    string out_string((char*)out.data(), sse::crypto::hash::sha512::kDigestSize);
    
    ASSERT_EQ(out_string, ref_string);
}

TEST(sha_512, test_vector_3)
{
	string in = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    std::array<uint8_t, sse::crypto::hash::sha512::kDigestSize> out;
	
	sse::crypto::hash::sha512::hash((const unsigned char*)in.data(), in.length(), (unsigned char*)out.data());
	
	uint8_t reference[] = {
					0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16, 
					0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35,
					0x96, 0xfd, 0x15, 0xc1, 0x3b, 0x1b, 0x07, 0xf9, 0xaa, 0x1d, 0x3b, 0xea, 0x57, 0x78, 0x9c, 0xa0,
					0x31, 0xad, 0x85, 0xc7, 0xa7, 0x1d, 0xd7, 0x03, 0x54, 0xec, 0x63, 0x12, 0x38, 0xca, 0x34, 0x45
				};
   
    string ref_string((char*)reference, sse::crypto::hash::sha512::kDigestSize);
    string out_string((char*)out.data(), sse::crypto::hash::sha512::kDigestSize);
    
    ASSERT_EQ(out_string, ref_string);
}

TEST(sha_512, test_vector_4)
{
	string in = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    std::array<uint8_t, sse::crypto::hash::sha512::kDigestSize> out;

    sse::crypto::hash::sha512::hash((const unsigned char*)in.data(), in.length(), (unsigned char*)out.data());
	
	uint8_t reference[] = {
					0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f, 
					0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18,
					0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
					0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09
				};
												
    string ref_string((char*)reference, sse::crypto::hash::sha512::kDigestSize);
    string out_string((char*)out.data(), sse::crypto::hash::sha512::kDigestSize);
    
    ASSERT_EQ(out_string, ref_string);
}

TEST(sha_512, test_vector_5)
{
	string in(1e6, 'a');
    std::array<uint8_t, sse::crypto::hash::sha512::kDigestSize> out;

    sse::crypto::hash::sha512::hash((const unsigned char*)in.data(), in.length(), (unsigned char*)out.data());
	
	uint8_t reference[] = {
					0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64, 0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63, 
					0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28, 0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb,
					0xde, 0x0f, 0xf2, 0x44, 0x87, 0x7e, 0xa6, 0x0a, 0x4c, 0xb0, 0x43, 0x2c, 0xe5, 0x77, 0xc3, 0x1b,
					0xeb, 0x00, 0x9c, 0x5c, 0x2c, 0x49, 0xaa, 0x2e, 0x4e, 0xad, 0xb2, 0x17, 0xad, 0x8c, 0xc0, 0x9b
				};
												
    string ref_string((char*)reference, sse::crypto::hash::sha512::kDigestSize);
    string out_string((char*)out.data(), sse::crypto::hash::sha512::kDigestSize);
    
    ASSERT_EQ(out_string, ref_string);
}

TEST(blake2,blake2s)
{
    // use the test vectors in header blake2_kat.h
    constexpr size_t IN_LENGTH = 256;
    constexpr size_t HASH_LENGTH = 256;
    
    uint8_t in[IN_LENGTH] = {0};
    uint8_t hash[HASH_LENGTH] = {0};
    
    for (size_t i = 0; i < sizeof(in); ++i){
        in[i] = i;
    }

    for (size_t i = 0; i < sizeof(in); ++i){
        sse::crypto::hash::blake2s::hash(in, i, hash);
        
        string ref_string(reinterpret_cast<const char*>(blake2s_kat[i]), sse::crypto::hash::blake2s::kDigestSize);
        string out_string((char*)hash, sse::crypto::hash::blake2s::kDigestSize);

        ASSERT_EQ(ref_string, out_string);
    }
}

TEST(blake2,blake2b)
{
    // use the test vectors in header blake2_kat.h
    constexpr size_t IN_LENGTH = 256;
    constexpr size_t HASH_LENGTH = 256;
    
    uint8_t in[IN_LENGTH] = {0};
    uint8_t hash[HASH_LENGTH] = {0};
    
    for (size_t i = 0; i < sizeof(in); ++i){
        in[i] = i;
    }
    
    for (size_t i = 0; i < sizeof(in); ++i){
        sse::crypto::hash::blake2b::hash(in, i, hash);
        
        string ref_string(reinterpret_cast<const char*>(blake2b_kat[i]), sse::crypto::hash::blake2b::kDigestSize);
        string out_string((char*)hash, sse::crypto::hash::blake2b::kDigestSize);
        
        ASSERT_EQ(ref_string, out_string);
    }
}


TEST(hash, consistency)
{
    for (size_t i = 1; i < sse::crypto::Hash::kDigestSize; i++) {
        std::string in = std::to_string(i);
        std::string out, trunc_out;
        std::array<uint8_t, sse::crypto::Hash::kDigestSize> out_array;
        std::array<uint8_t, sse::crypto::Hash::kDigestSize> trunc_out_array;
        
        out = sse::crypto::Hash::hash(in);
        trunc_out = sse::crypto::Hash::hash(in, i);
        sse::crypto::Hash::hash(reinterpret_cast<const uint8_t*>(in.data()), in.size(), out_array.data());
        sse::crypto::Hash::hash(reinterpret_cast<const uint8_t*>(in.data()), in.size(), i, trunc_out_array.data());
        
        ASSERT_EQ(trunc_out, std::string(out.begin(), out.begin()+i));
        ASSERT_EQ(out, std::string(out_array.begin(), out_array.end()));
        ASSERT_EQ(trunc_out, std::string(trunc_out_array.begin(), trunc_out_array.begin()+i));
    }
}

TEST(hash, exceptions)
{
    std::string in;
    std::string out;
    
    ASSERT_THROW(sse::crypto::Hash::hash(in, sse::crypto::Hash::kDigestSize + 1), std::invalid_argument);
    
    ASSERT_THROW(sse::crypto::Hash::hash(reinterpret_cast<const uint8_t*>(in.data()), 0, NULL), std::invalid_argument);
    ASSERT_THROW(sse::crypto::Hash::hash(NULL, 0, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);

    ASSERT_THROW(sse::crypto::Hash::hash(reinterpret_cast<const uint8_t*>(in.data()), 0, sse::crypto::Hash::kDigestSize + 1, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);
    ASSERT_THROW(sse::crypto::Hash::hash(NULL, 0, sse::crypto::Hash::kDigestSize - 1, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data()))), std::invalid_argument);
    ASSERT_THROW(sse::crypto::Hash::hash(reinterpret_cast<const uint8_t*>(in.data()), 0, sse::crypto::Hash::kDigestSize - 1, NULL), std::invalid_argument);

}
