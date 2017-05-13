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

#define SERIALIZATION_TEST_COUNT 500
#define SERIALIZATION_PUNCT_COUNT 50
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


void test_ppke_serialization()
{
    sse::crypto::Prf<sse::crypto::kPrfOutputSize> key_prf;
    
    sse::crypto::Gmppke ppke;
    sse::crypto::GmppkePublicKey pk;
    sse::crypto::GmppkePrivateKey sk;
    sse::crypto::GmppkeSecretParameters sp;
    
    ppke.keygen(key_prf, pk, sk, sp);
    
    typedef uint64_t M_type;
    
    
    size_t current_p_count = 0;
    
    std::vector<sse::crypto::GmppkePrivateKeyShare> keyshares;
    keyshares.push_back(ppke.sk0Gen(key_prf, sp, 0));
    
    for ( ; current_p_count < SERIALIZATION_PUNCT_COUNT; current_p_count++) {
        sse::crypto::tag_type punctured_tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
        punctured_tag[15] = current_p_count&0xFF;
        punctured_tag[14] = (current_p_count>>8)&0xFF;
        punctured_tag[13] = (current_p_count>>16)&0xFF;
        punctured_tag[12] = (current_p_count>>24)&0xFF;
        punctured_tag[11] = (current_p_count>>32)&0xFF;
        punctured_tag[10] = (current_p_count>>40)&0xFF;
        punctured_tag[9] = (current_p_count>>48)&0xFF;
        punctured_tag[8] = 0xFF;
        
        
        auto share = ppke.skShareGen(key_prf, sp, current_p_count+1, punctured_tag);
        
        std::array<uint8_t, sse::crypto::GmppkePrivateKeyShare::kByteSize> share_data;
        share.writeBytes(share_data.data());
        
        sse::crypto::GmppkePrivateKeyShare serialized_share(share_data.data());
        
        BOOST_CHECK(share == serialized_share);
        
        keyshares.push_back(share);
    }

    keyshares[0] = ppke.sk0Gen(key_prf, sp, current_p_count);


    std::array<uint8_t, sse::crypto::GmppkePrivateKeyShare::kByteSize> share_data;
    keyshares[0].writeBytes(share_data.data());

    sse::crypto::GmppkePrivateKeyShare serialized_share(share_data.data());
    
    BOOST_CHECK(keyshares[0] == serialized_share);


    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
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
        
        auto ct = ppke.encrypt<M_type>(pk, M, tag);

        std::array<uint8_t, sse::crypto::GmmppkeCT<M_type>::kByteSize> ct_data;
        ct.writeBytes(ct_data.data());
        sse::crypto::GmmppkeCT<M_type> serialized_ct(ct_data.data());

        BOOST_CHECK(ct == serialized_ct);
    }
}

void test_pseudo_random_ppke()
{
    sse::crypto::Prf<sse::crypto::kPrfOutputSize> key_prf;
    
    sse::crypto::Gmppke ppke;
    sse::crypto::GmppkePublicKey pk;
    sse::crypto::GmppkePrivateKey sk;
    sse::crypto::GmppkeSecretParameters sp;
    
    ppke.keygen(key_prf, pk, sk, sp);
    
    typedef uint64_t M_type;
    
    
    std::vector<size_t> puncture_count_list = {0, 1, 2, 5, 10, 15, 20, 30, 40};
    
    size_t current_p_count = 0;
    
    std::vector<sse::crypto::GmppkePrivateKeyShare> keyshares;
    keyshares.push_back(ppke.sk0Gen(key_prf, sp, 0));
    
    for (size_t p : puncture_count_list) {
        
        if (p > current_p_count) {
            
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
                punctured_tag[8] = 0xFF;
                
                auto share = ppke.skShareGen(key_prf, sp, current_p_count+1, punctured_tag);
                
                keyshares.push_back(share);
            }
            
            keyshares[0] = ppke.sk0Gen(key_prf, sp, current_p_count);
            
        }
        
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
            
            auto ct = ppke.encrypt<M_type>(pk, M, tag);
            auto ct2 = ppke.encrypt<M_type>(sp, M, tag);
            M_type dec_M = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);
            M_type dec_M2 = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);
            
            BOOST_CHECK(M == dec_M);
            BOOST_CHECK(M == dec_M2);
        }
    }
}
