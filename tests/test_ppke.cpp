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

#include "../src/ppke/GMPpke.h"
#include "../src/puncturable_enc.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <memory>


#include "gtest/gtest.h"

using namespace std;

#define SERIALIZATION_TEST_COUNT 500
#define SERIALIZATION_PUNCT_COUNT 50
#define ENCRYPTION_TEST_COUNT 10

#define ARITHMETIC_TEST_COUNT 100

TEST(relic, serialization_ZR)
{
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::ZR z((int)i);
        
        std::array<uint8_t, RELIC_BN_BYTES> bytes;
        z.writeBytes(bytes.data());
        
        relicxx::ZR y(bytes.data(), bytes.size());
        
        ASSERT_EQ(z, y);
        
        
        auto vec_bytes = z.getBytes();
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));
        
        std::string i_str = std::to_string(i);
        relicxx::ZR zr_str(i_str.c_str());
        ASSERT_EQ(z, zr_str);
    }
    
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::ZR z = group.randomZR();
        
        std::array<uint8_t, RELIC_BN_BYTES> bytes;
        z.writeBytes(bytes.data());
        
        relicxx::ZR y(bytes.data(), bytes.size());
        
        ASSERT_EQ(z, y);
        
        
        auto vec_bytes = z.getBytes();
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));

        ASSERT_TRUE(group.ismember(y));
    }
 

}

TEST(relic, serialization_G1)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G1 z = group.randomG1();
        
        std::array<uint8_t, relicxx::G1::kByteSize> bytes;
        z.writeBytes(bytes.data(), false);
        
        relicxx::G1 y(bytes.data(), false);
        
        
        ASSERT_EQ(z, y);
        
        auto vec_bytes = z.getBytes();
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));
        
        ASSERT_TRUE(group.ismember(y));
    }
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G1 z = group.randomG1();
        
        std::array<uint8_t, relicxx::G1::kCompactByteSize> bytes;
        z.writeBytes(bytes.data(), true);
        
        relicxx::G1 y(bytes.data(), true);
        
        
        ASSERT_EQ(z, y);
        
        auto vec_bytes = z.getBytes(true);
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));

        ASSERT_TRUE(group.ismember(y));
    }
}

TEST(relic, serialization_G2)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G2 z = group.randomG2();
        
        std::array<uint8_t, relicxx::G2::kByteSize> bytes;
        z.writeBytes(bytes.data(), false);
        
        relicxx::G2 y(bytes.data(), false);
        
        
        ASSERT_EQ(z, y);

        auto vec_bytes = z.getBytes();
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));

        ASSERT_TRUE(group.ismember(y));
    }
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::G2 z = group.randomG2();
        
        std::array<uint8_t, relicxx::G2::kCompactByteSize> bytes;
        z.writeBytes(bytes.data(), true);
        
        relicxx::G2 y(bytes.data(), true);
        
        
        ASSERT_EQ(z, y);
    
        auto vec_bytes = z.getBytes(true);
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));

        ASSERT_TRUE(group.ismember(y));
    }

}

TEST(relic, serialization_GT)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::GT z = group.randomGT();
        
        std::array<uint8_t, relicxx::GT::kByteSize> bytes;
        z.writeBytes(bytes.data(), false);
        
        relicxx::GT y(bytes.data(), false);
        
        
        ASSERT_EQ(z, y);
        
        auto vec_bytes = z.getBytes();
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));

        ASSERT_TRUE(group.ismember(y));
    }
    
    for (size_t i = 0; i < SERIALIZATION_TEST_COUNT; i++) {
        
        relicxx::GT z = group.randomGT();
        
        std::array<uint8_t, relicxx::GT::kCompactByteSize> bytes;
        z.writeBytes(bytes.data(), true);
        
        relicxx::GT y(bytes.data(), true);
        
        
        ASSERT_EQ(z, y);
        
        auto vec_bytes = z.getBytes(true);
        ASSERT_EQ(vec_bytes.size(), bytes.size());
        ASSERT_TRUE(std::equal(vec_bytes.begin(), vec_bytes.end(), bytes.begin()));
  
        ASSERT_TRUE(group.ismember(y));
    }
    
}

TEST(relic, arithmetic_ZR)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < ARITHMETIC_TEST_COUNT; i++) {
        
        relicxx::ZR z1 = group.randomZR();
        relicxx::ZR z2 = group.randomZR();
        relicxx::ZR z3 = group.randomZR();
        relicxx::ZR z4 = group.randomZR();
        
        ASSERT_EQ(z1+z2, z2+z1);
        ASSERT_EQ(group.add(z3, z4), group.add(z4, z3));
        ASSERT_EQ(group.sub(z1, z2), group.add(group.neg(z2), z1));
        ASSERT_EQ(group.mul(z3, z4), group.mul(z4, z3));
        
        
        ASSERT_EQ(group.div(z1, z2), group.mul(group.inv(z2), z1));
        ASSERT_EQ(group.div(z2, z1), group.inv(group.div(z1, z2)));

        ASSERT_EQ(z1<<1, z1*2);
        ASSERT_EQ(z2<<2, z2*4);
        ASSERT_EQ(z3<<3, z3*8);
        ASSERT_EQ(z4<<4, z4*16);

        ASSERT_EQ(group.exp(z1, (int) 42), group.exp(z1, relicxx::ZR(42)));
        ASSERT_EQ(group.exp(z2, (int) 10), group.exp(z2, relicxx::ZR(10)));
        ASSERT_EQ(group.exp(z3, (int) 4675), group.exp(z3, relicxx::ZR(4675)));
        ASSERT_EQ(group.exp(z4, (int) 233453451), group.exp(z4, relicxx::ZR(233453451)));
    }
    
}


TEST(relic, arithmetic_G1)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < ARITHMETIC_TEST_COUNT; i++) {
        
        relicxx::G1 z1 = group.randomG1();
        relicxx::G1 z2 = group.randomG1();
        relicxx::G1 z3 = group.randomG1();
        relicxx::G1 z4 = group.randomG1();
        
        ASSERT_EQ(z1+z2, z2+z1);
        ASSERT_EQ(z3+z4, z4+z3);
        ASSERT_EQ(z1-z2, (-z2) + z1);
        ASSERT_EQ(group.mul(z3, z4), group.mul(z4, z3));
        
        
        ASSERT_EQ(group.div(z1, z2), group.mul(group.inv(z2), z1));
        ASSERT_EQ(group.div(z2, z1), group.inv(group.div(z1, z2)));
        
        ASSERT_EQ(group.exp(z1, (int) 42), group.exp(z1, relicxx::ZR(42)));
        ASSERT_EQ(group.exp(z2, (int) 10), group.exp(z2, relicxx::ZR(10)));
        ASSERT_EQ(group.exp(z3, (int) 4675), group.exp(z3, relicxx::ZR(4675)));
        ASSERT_EQ(group.exp(z4, (int) 233453451), group.exp(z4, relicxx::ZR(233453451)));
    }
    
}

TEST(relic, arithmetic_G2)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < ARITHMETIC_TEST_COUNT; i++) {
        
        relicxx::G2 z1 = group.randomG2();
        relicxx::G2 z2 = group.randomG2();
        relicxx::G2 z3 = group.randomG2();
        relicxx::G2 z4 = group.randomG2();
        
        ASSERT_EQ(z1+z2, z2+z1);
        ASSERT_EQ(z3+z4, z4+z3);
        ASSERT_EQ(z1-z2, (-z2) + z1);
        ASSERT_EQ(group.mul(z3, z4), group.mul(z4, z3));
        
        
        ASSERT_EQ(group.div(z1, z2), group.mul(group.inv(z2), z1));
        ASSERT_EQ(group.div(z2, z1), group.inv(group.div(z1, z2)));
        
        ASSERT_EQ(group.exp(z1, (int) 42), group.exp(z1, relicxx::ZR(42)));
        ASSERT_EQ(group.exp(z2, (int) 10), group.exp(z2, relicxx::ZR(10)));
        ASSERT_EQ(group.exp(z3, (int) 4675), group.exp(z3, relicxx::ZR(4675)));
        ASSERT_EQ(group.exp(z4, (int) 233453451), group.exp(z4, relicxx::ZR(233453451)));
    }
    
}

TEST(relic, arithmetic_GT)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < ARITHMETIC_TEST_COUNT; i++) {
        
        relicxx::GT z1 = group.randomGT();
        relicxx::GT z2 = group.randomGT();
        relicxx::GT z3 = group.randomGT();
        relicxx::GT z4 = group.randomGT();
        
        ASSERT_EQ(group.mul(z3, z4), group.mul(z4, z3));
        
        
        ASSERT_EQ(group.div(z1, z2), group.mul(group.inv(z2), z1));
        ASSERT_EQ(group.div(z2, z1), group.inv(group.div(z1, z2)));
        
        ASSERT_EQ(group.exp(z1, (int) 42), group.exp(z1, relicxx::ZR(42)));
        ASSERT_EQ(group.exp(z2, (int) 10), group.exp(z2, relicxx::ZR(10)));
        ASSERT_EQ(group.exp(z3, (int) 4675), group.exp(z3, relicxx::ZR(4675)));
        ASSERT_EQ(group.exp(z4, (int) 233453451), group.exp(z4, relicxx::ZR(233453451)));
    }
    
}

TEST(relic, pairing)
{
    relicxx::PairingGroup group;
    
    for (size_t i = 0; i < ARITHMETIC_TEST_COUNT; i++) {
        
        relicxx::G1 z1 = group.randomG1();
        relicxx::G2 z2 = group.randomG2();
        
        relicxx::GT p12 = group.pair(z1,z2);
        
        relicxx::ZR e1 = group.randomZR();
        relicxx::ZR e2 = group.randomZR();
        
        
        ASSERT_EQ(group.pair(power(z1,e1),z2), power(p12,e1));
        ASSERT_EQ(group.pair(z1,power(z2,e2)), power(p12,e2));
        ASSERT_EQ(group.pair(power(z1,e1),power(z2,e2)), power(p12,e1*e2));
    }
    
}

TEST(ppke, serialization)
{
    std::array<uint8_t, sse::crypto::Gmppke::kPRFKeySize> master_key;
    sse::crypto::random_bytes(master_key);
    
    sse::crypto::Prf<sse::crypto::kPPKEPrfOutputSize> key_prf(master_key.data(), master_key.size());
    
    sse::crypto::Gmppke ppke;
    sse::crypto::GmppkePublicKey pk;
    sse::crypto::GmppkePrivateKey sk;
    sse::crypto::GmppkeSecretParameters sp;
    
    ppke.keygen(master_key, pk, sk, sp);
    
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
        
        ASSERT_EQ(share, serialized_share);
        
        keyshares.push_back(share);
    }

    keyshares[0] = ppke.sk0Gen(key_prf, sp, current_p_count);


    std::array<uint8_t, sse::crypto::GmppkePrivateKeyShare::kByteSize> share_data;
    keyshares[0].writeBytes(share_data.data());

    sse::crypto::GmppkePrivateKeyShare serialized_share(share_data.data());
    
    ASSERT_EQ(keyshares[0], serialized_share);


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

        ASSERT_EQ(ct, serialized_ct);
    }
}

TEST(ppke, probabilitic_correctness)
{
    
    sse::crypto::Gmppke ppke;
    sse::crypto::GmppkePublicKey pk;
    sse::crypto::GmppkePrivateKey sk;
    sse::crypto::GmppkeSecretParameters sp;
    
    ppke.keygen(pk, sk, sp);
    
    typedef uint64_t M_type;
    
    
    std::vector<size_t> puncture_count_list = {0, 1, 2, 5, 10};
    
    size_t current_p_count = 0;
    
    
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
                
                ppke.puncture(pk, sk, punctured_tag);
            }
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
            M_type dec_M = ppke.decrypt(sk, ct2);
            M_type dec_M2 = ppke.decrypt(sk, ct2);
            
            ASSERT_EQ(M, dec_M);
            ASSERT_EQ(M, dec_M2);
        }
    }
}

TEST(ppke, deterministic_correctness)
{
    sse::crypto::Prf<sse::crypto::kPPKEPrfOutputSize> key_prf;
    
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
            
            ASSERT_EQ(M, dec_M);
            ASSERT_EQ(M, dec_M2);
        }
    }
    
    for (auto share : keyshares) {
        if (share.get_tag() == sse::crypto::Gmppke::NULLTAG) { // first key share
            ASSERT_THROW(ppke.encrypt<M_type>(pk, 0, share.get_tag() ), std::invalid_argument);
        }else{
            auto ct = ppke.encrypt<M_type>(pk, 0, share.get_tag() );
            
            ASSERT_THROW(ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct), sse::crypto::PuncturedCiphertext);
        }
    }

}

TEST(puncturable, correctness)
{
    std::array<uint8_t, 16> master_key;
    for (size_t i = 0; i < master_key.size(); i++) {
        master_key[i] = 1 << i;
    }
    
    sse::crypto::PuncturableEncryption encryptor(master_key);

    typedef uint64_t M_type;
    
    
    size_t current_p_count = 0;
    
    sse::crypto::punct::punctured_key_type punctured_key;
    punctured_key.push_back(encryptor.initial_keyshare(0));
    
    for ( ; current_p_count < 5; current_p_count++) {
        sse::crypto::tag_type punctured_tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
        punctured_tag[15] = current_p_count&0xFF;
        punctured_tag[14] = (current_p_count>>8)&0xFF;
        punctured_tag[13] = (current_p_count>>16)&0xFF;
        punctured_tag[12] = (current_p_count>>24)&0xFF;
        punctured_tag[11] = (current_p_count>>32)&0xFF;
        punctured_tag[10] = (current_p_count>>40)&0xFF;
        punctured_tag[9] = (current_p_count>>48)&0xFF;
        punctured_tag[8] = 0xFF;
        
        
        auto share = encryptor.inc_puncture(current_p_count+1, punctured_tag);
        
        punctured_key.push_back(share);
    }
    
    punctured_key[0] = encryptor.initial_keyshare(current_p_count);
    
    
    sse::crypto::PuncturableDecryption decryptor(punctured_key);

    for (size_t i = 0; i < ENCRYPTION_TEST_COUNT; i++) {
        M_type M = i, dec_M;
        
        sse::crypto::tag_type tag{{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};
        tag[0] = i&0xFF;
        tag[1] = (i>>8)&0xFF;
        tag[2] = (i>>16)&0xFF;
        tag[3] = (i>>24)&0xFF;
        tag[4] = (i>>32)&0xFF;
        tag[5] = (i>>40)&0xFF;
        tag[6] = (i>>48)&0xFF;
        tag[7] = (i>>56)&0xFF;
        tag[8] = 0xCC;

        auto ct = encryptor.encrypt(M, tag);
        bool success = decryptor.decrypt(ct, dec_M);

        ASSERT_TRUE(success);
        ASSERT_EQ(M, dec_M);

    }
    
    for (auto share : punctured_key) {
        
        if (sse::crypto::punct::extract_tag(share) == sse::crypto::Gmppke::NULLTAG) { // first key share
            ASSERT_THROW(encryptor.encrypt(0, sse::crypto::punct::extract_tag(share)), std::invalid_argument);
        }else{
            auto ct = encryptor.encrypt(0, sse::crypto::punct::extract_tag(share) );
            
            M_type tmp;
            
            ASSERT_FALSE(decryptor.decrypt(ct, tmp));
        }
    }
}
