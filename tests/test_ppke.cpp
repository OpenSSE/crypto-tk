//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Raphael Bost
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

#include "../tests/test_tdp.hpp"

#include "../src/ppke/GMPpke.h"

#include <iostream>
#include <iomanip>
#include <string>

#include "boost_test_include.hpp"

using namespace std;

#define SERIALIZATION_TEST_COUNT 100
#define ENCRYPTION_TEST_COUNT 50


void test_relic_serialization_ZR()
{
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::ZR z((int)i);
        
        std::array<uint8_t, BN_BYTES> bytes;
        z.writeBytes(bytes.data());
        
        relicxx::ZR y(bytes.data(), bytes.size());

        
        BOOST_CHECK(z == y);
    }
    
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::ZR z = group.randomZR();
        
        std::array<uint8_t, BN_BYTES> bytes;
        z.writeBytes(bytes.data());
        
        relicxx::ZR y(bytes.data(), bytes.size());
        
        
        BOOST_CHECK(z == y);
    }
 

}

void test_relic_serialization_G1()
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G1 z = group.randomG1();
        
        std::array<uint8_t, relicxx::G1::kByteSize> bytes;
        z.writeBytes(bytes.data(), false);
        
        relicxx::G1 y(bytes.data(), false);
        
        
        BOOST_CHECK(z == y);
    }
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G1 z = group.randomG1();
        
        std::array<uint8_t, relicxx::G1::kCompactByteSize> bytes;
        z.writeBytes(bytes.data(), true);
        
        relicxx::G1 y(bytes.data(), true);
        
        
        BOOST_CHECK(z == y);
    }
}

void test_ppke_serialization()
{
    
}

void test_relic_serialization_G2()
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G2 z = group.randomG2();
        
        std::array<uint8_t, relicxx::G2::kByteSize> bytes;
        z.writeBytes(bytes.data(), false);
        
        relicxx::G2 y(bytes.data(), false);
        
        
        BOOST_CHECK(z == y);
    }
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G2 z = group.randomG2();
        
        std::array<uint8_t, relicxx::G2::kCompactByteSize> bytes;
        z.writeBytes(bytes.data(), true);
        
        relicxx::G2 y(bytes.data(), true);
        
        
        BOOST_CHECK(z == y);
    }

}


//void test_ppke_serialization();
void test_pseudo_random_ppke()
{
    sse::crypto::Prf<sse::crypto::kPrfOutputSize> key_prf;
    
    sse::crypto::Gmppke ppke;
    sse::crypto::GmppkePublicKey pk;
    sse::crypto::GmppkePrivateKey sk;
    sse::crypto::GmppkeSecretParameters sp;
    
    ppke.keygen(key_prf, pk, sk, sp);
    
    typedef uint64_t M_type;
    
    
    //    size_t puncture_count = 10;
    
    //    std::vector<size_t> puncture_count_list = {0, 1, 2};
    std::vector<size_t> puncture_count_list = {0, 1, 2, 5, 10, 15, 20, 30, 40};
    
    size_t current_p_count = 0;
    
    std::vector<sse::crypto::GmppkePrivateKeyShare> keyshares;
    keyshares.push_back(ppke.sk0Gen(key_prf, sp, 0));
    
    for (size_t p : puncture_count_list) {
        
        if (p > current_p_count) {
            
//            size_t n_punctures = p-current_p_count;
//            std::cout << "Puncture the key " << n_punctures << " times...";
            
//            std::chrono::duration<double, std::milli> puncture_time(0);
            
            // add new punctures
            for ( ; current_p_count < p; current_p_count++) {
                sse::crypto::tag_type punctured_tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
                punctured_tag[15] = current_p_count&0xFF;
                punctured_tag[14] = (current_p_count>>8)&0xFF;
                punctured_tag[13] = (current_p_count>>16)&0xFF;
                punctured_tag[12] = (current_p_count>>24)&0xFF;
                punctured_tag[11] = (current_p_count>>32)&0xFF;
                punctured_tag[10] = (current_p_count>>40)&0xFF;
                punctured_tag[9] = (current_p_count>>48)&0xFF;
                //            punctured_tag[8] = (current_p_count>>56)&0xFF;
                punctured_tag[8] = 0xFF;
                
//                auto t_start = std::chrono::high_resolution_clock::now();
                
                auto share = ppke.skShareGen(key_prf, sp, current_p_count+1, punctured_tag);
                //                ppke.puncture(pk, sk, punctured_tag);
                
//                auto t_end = std::chrono::high_resolution_clock::now();
                
                keyshares.push_back(share);
                
//                puncture_time += t_end - t_start;
                
            }
            
//            std::cout << "Done\n";
//            std::cout << "Average puncturing time: " << puncture_time.count()/n_punctures << " ms/puncture" << std::endl;
            // update accordingly the first key share
            keyshares[0] = ppke.sk0Gen(key_prf, sp, current_p_count);
            
        }
//        std::chrono::duration<double, std::milli> encrypt_time(0);
//        std::chrono::duration<double, std::milli> sp_encrypt_time(0);
//        std::chrono::duration<double, std::milli> decrypt_time(0);
        
//        std::cout << "Running " << bench_count << " encryption/decryptions with " << current_p_count << " punctures...";
        
        
        
        for (size_t i = 0; i < ENCRYPTION_TEST_COUNT; i++) {
            M_type M;
            
            sse::crypto::random_bytes(sizeof(M_type), (uint8_t*) &M);
            
            sse::crypto::tag_type tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
            tag[0] = i&0xFF;
            tag[1] = (i>>8)&0xFF;
            tag[2] = (i>>16)&0xFF;
            tag[3] = (i>>24)&0xFF;
            tag[4] = (i>>32)&0xFF;
            tag[5] = (i>>40)&0xFF;
            tag[6] = (i>>48)&0xFF;
            tag[7] = (i>>56)&0xFF;
            
//            auto t_start = std::chrono::high_resolution_clock::now();
            auto ct = ppke.encrypt<M_type>(pk, M, tag);
//            auto t_end = std::chrono::high_resolution_clock::now();
            
//            encrypt_time += t_end - t_start;
            
//            t_start = std::chrono::high_resolution_clock::now();
            auto ct2 = ppke.encrypt<M_type>(sp, M, tag);
//            t_end = std::chrono::high_resolution_clock::now();
            
//            sp_encrypt_time += t_end - t_start;
            
//            t_start = std::chrono::high_resolution_clock::now();
            M_type dec_M = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);
//            t_end = std::chrono::high_resolution_clock::now();
//            decrypt_time += t_end - t_start;
            
            M_type dec_M2 = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);
            
            BOOST_CHECK(M == dec_M);
            BOOST_CHECK(M == dec_M2);
        }
        
//        std::cout << "Done. \n";
//        std::cout << "Encryption: " << encrypt_time.count()/bench_count << " ms" << std::endl;
//        std::cout << "Encryption with secret: " << sp_encrypt_time.count()/bench_count << " ms" << std::endl;
//        std::cout << "Decryption: " << decrypt_time.count()/bench_count << " ms" << std::endl;
//        
    }
}
