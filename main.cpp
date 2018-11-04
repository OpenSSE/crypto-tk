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

#include "src/hash/sha512.hpp"
#include "src/mbedtls/bignum.h"
#include "src/mbedtls/rsa.h"
#include "src/ppke/GMPpke.hpp"

#include <chrono>
#include <cstring>
#include <netinet/in.h>

#include <array>
#include <iomanip>
#include <iostream>
#include <sse/crypto/hash.hpp>
#include <sse/crypto/hmac.hpp>
#include <sse/crypto/key.hpp>
#include <sse/crypto/prg.hpp>
#include <sse/crypto/random.hpp>
#include <sse/crypto/set_hash.hpp>
#include <sse/crypto/tdp.hpp>
#include <sse/crypto/utils.hpp>
#include <string>
#include <vector>

#include <openssl/sha.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

using namespace std;

int mbedTLS_rng_wrap(void* arg, unsigned char* out, size_t len)
{
    sse::crypto::random_bytes(len, out);
    return 0;
}

extern "C" void sha512_avx(const void* M, void* D, uint64_t L);
;
extern "C" void sha512_rorx(const void* M, void* D, uint64_t L);
;
extern "C" void sha512_sse4(const void* M, void* D, uint64_t L);
;
extern "C" void sha512_base(const void* M, void* D, uint64_t L);

#ifndef htonll
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#endif

#define BYTESWAP64(x) htonll(x)
#define UL64(x) x##ULL

constexpr uint64_t H[8] = {0x6a09e667f3bcc908LL,
                           0xbb67ae8584caa73bLL,
                           0x3c6ef372fe94f82bLL,
                           0xa54ff53a5f1d36f1LL,
                           0x510e527fade682d1LL,
                           0x9b05688c2b3e6c1fLL,
                           0x1f83d9abfb41bd6bLL,
                           0x5be0cd19137e2179LL};


static void sha512_update_acc(const unsigned char* in,
                              unsigned char*       digest,
                              const uint64_t&      block_len)
{
#ifdef __AVX2__
#pragma message "Use AVX2"
    sha512_rorx(in, (uint32_t*)digest, block_len);
#elif defined __AVX__
#pragma message "Use AVX"
    sha512_avx(in, (uint32_t*)digest, block_len);
#elif defined __SSE4_1__
#pragma message "Use SSE4"
    sha512_sse4(in, (uint32_t*)digest, block_len);
#else
#error Intel SHA-2 code is not supported on this architecture
#endif
}


constexpr size_t kBlockSize  = 128;
constexpr size_t kDigestSize = 64;

static void hash_acc(const unsigned char* in,
                     const uint64_t&      len,
                     unsigned char*       digest)
{
    unsigned char dbuf[64];
    memcpy(dbuf, H, 64);


    size_t   n_complete_blocks = len >> 7;
    uint64_t rem               = len & ((1 << 7) - 1);


    // first, hash the complete blocks
    if (n_complete_blocks) {
        sha512_update_acc(in, dbuf, n_complete_blocks);
    }

    uint8_t n_blocks = (rem < 112) ? 1 : 2;

    unsigned char* buffer = new unsigned char[n_blocks * kBlockSize];
    memcpy(buffer, in + (n_complete_blocks << 7), rem);
    buffer[rem] = 0x80;

    // write padding
    memset(buffer + rem + 1, 0x00, n_blocks * kBlockSize - rem - 1);

    // copy the message length on 8 bytes
    // we do not support messages with more than 2^64-1 bits
    uint64_t bit_length = BYTESWAP64(len << 3);
    memcpy(buffer + n_blocks * kBlockSize - 8, &bit_length, 8);

    cout << "Last block :\n";
    for (size_t i = 0; i < n_blocks * kBlockSize; i++) {
        cout << hex << setw(2) << setfill('0') << (uint)buffer[i];
    }
    cout << endl;

    sha512_update_acc(buffer, dbuf, n_blocks);

    for (size_t i = 0; i < (kDigestSize >> 3); ++i) {
        ((uint64_t*)dbuf)[i] = BYTESWAP64(((uint64_t*)dbuf)[i]);
    }

    memcpy(digest, dbuf, 64);
    delete[] buffer;
}

using namespace std;

static void open_ssl(const unsigned char* in,
                     const uint64_t&      len,
                     unsigned char*       digest)
{
    SHA512_CTX ctx;

    SHA512_Init(&ctx);


    size_t   n_complete_blocks = len >> 7;
    uint64_t rem               = len & ((1 << 7) - 1);

    // first, hash the complete blocks
    if (n_complete_blocks) {
        SHA512_Update(&ctx, in, n_complete_blocks << 7);
    }

    // if(rem || (len == 0)){
    uint8_t n_blocks = (rem < 112) ? 1 : 2;

    unsigned char* buffer = new unsigned char[n_blocks * kBlockSize];
    memcpy(buffer, in + (n_complete_blocks << 7), rem);
    buffer[rem] = 0x80;

    // write padding
    memset(buffer + rem + 1, 0x00, n_blocks * kBlockSize - rem - 1);

    // copy the message length on 8 bytes
    // we do not support messages with more than 2^64-1 bits
    uint64_t bit_length = BYTESWAP64(len << 3);
    memcpy(buffer + n_blocks * kBlockSize - 8, &bit_length, 8);

    cout << "Last block :\n";
    for (size_t i = 0; i < n_blocks * kBlockSize; i++) {
        cout << hex << setw(2) << setfill('0') << (uint)buffer[i];
    }
    cout << endl;

    SHA512_Update(&ctx, buffer, n_blocks * kBlockSize);

    memcpy(digest, ctx.h, 64);

    uint64_t* digest_64 = (uint64_t*)digest;

    for (size_t i = 0; i < kDigestSize; ++i) {
        digest_64[i] = BYTESWAP64(digest_64[i]);
    }

    // memcpy(digest, dbuf, 64);

    delete[] buffer;
    // }
}

static void open_ssl_full(const unsigned char* in,
                          const uint64_t&      len,
                          unsigned char*       digest)
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
    constexpr static size_t kBlockSize  = sse::crypto::Hash::kBlockSize;

    static void hash(const unsigned char* in,
                     const size_t&        len,
                     unsigned char*       out)
    {
        open_ssl_full(in, len, out);
    }
};

class HashOpenSSL
{
public:
    constexpr static size_t kDigestSize = sse::crypto::Hash::kDigestSize;
    constexpr static size_t kBlockSize  = sse::crypto::Hash::kBlockSize;

    static void hash(const unsigned char* in,
                     const size_t&        len,
                     unsigned char*       out)
    {
        open_ssl(in, len, out);
    }
};

class Local
{
public:
    constexpr static size_t kDigestSize = sse::crypto::Hash::kDigestSize;
    constexpr static size_t kBlockSize  = sse::crypto::Hash::kBlockSize;

    static void hash(const unsigned char* in,
                     const size_t&        len,
                     unsigned char*       out)
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
    size_t step        = 1000;

    srand((uint)time(NULL));

    cout << "\r" << 0 << "/" << bench_count << flush;

    for (size_t j = 0; j < bench_count / step; ++j) {
        for (size_t i = 0; i < step; ++i) {
            string in(1e5, rand());

            auto begin_ssl = std::chrono::high_resolution_clock::now();
            open_ssl((const unsigned char*)in.data(),
                     in.length(),
                     reinterpret_cast<unsigned char*>(
                         const_cast<char*>(out_openssl.data())));
            auto end_ssl = std::chrono::high_resolution_clock::now();

            time_ssl += std::chrono::duration_cast<std::chrono::nanoseconds>(
                            end_ssl - begin_ssl)
                            .count();

            auto begin_intel = std::chrono::high_resolution_clock::now();
            hash_acc((const unsigned char*)in.data(),
                     in.length(),
                     reinterpret_cast<unsigned char*>(
                         const_cast<char*>(out_acc.data())));
            auto end_intel = std::chrono::high_resolution_clock::now();

            time_intel += std::chrono::duration_cast<std::chrono::nanoseconds>(
                              end_intel - begin_intel)
                              .count();
        }
        cout << "\r" << (j + 1) * step << "/" << bench_count << flush;
    }
    cout << endl;
    cout << "OpenSSL: " << time_ssl << " ms\n";
    cout << "Intel: " << time_intel << " ms\n";
}

static void tdp()
{
    sse::crypto::TdpInverse tdp;

    cout << tdp.private_key() << endl;

    std::string in = tdp.sample();

    cout << "Original input:\n" << endl;
    for (unsigned char c : in) {
        cout << hex << setw(2) << setfill('0') << (uint)c;
    }

    std::string out = tdp.eval(in);

    cout << "\n\nOutput:\n" << endl;
    for (unsigned char c : out) {
        cout << hex << setw(2) << setfill('0') << (uint)c;
    }

    std::string dec = tdp.invert(out);

    cout << "\n\nDecrypted input:\n" << endl;
    for (unsigned char c : dec) {
        cout << hex << setw(2) << setfill('0') << (uint)c;
    }

    cout << endl;
}

static void bench_rsa()
{
    for (size_t i = 1; i < 20; i++) {
        sse::crypto::TdpInverse tdp_inv;

        //        string pk = tdp_inv.public_key();

        //        sse::crypto::Tdp tdp(pk);

        string v1 = tdp_inv.sample(), v2;

        auto begin_tdp    = std::chrono::high_resolution_clock::now();
        v2                = tdp_inv.invert(v1);
        auto end_tdp_priv = std::chrono::high_resolution_clock::now();
        v2                = tdp_inv.eval(v1);
        auto end_tdp_pub  = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double, std::milli> time_tdp_priv
            = end_tdp_priv - begin_tdp;
        std::chrono::duration<double, std::milli> time_tdp_pub
            = end_tdp_pub - end_tdp_priv;
        std::cout << "OpenSSL (private): " << time_tdp_priv.count() << " ms"
                  << std::endl;
        std::cout << "OpenSSL (public): " << time_tdp_pub.count() << " ms"
                  << std::endl;

        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa, 0, 0);

        mbedtls_rsa_gen_key(&rsa, mbedTLS_rng_wrap, NULL, 2048, 0x10001L);
        mbedtls_mpi   a;
        unsigned char a_buffer[256], b_buffer[256];

        mbedtls_mpi_init(&a);
        mbedtls_mpi_fill_random(&a, 256, mbedTLS_rng_wrap, NULL);
        mbedtls_mpi_mod_mpi(&a, &a, &rsa.N);
        mbedtls_mpi_write_binary(&a, a_buffer, 256);

        auto begin_mbed = std::chrono::high_resolution_clock::now();
        mbedtls_rsa_private(&rsa, mbedTLS_rng_wrap, NULL, a_buffer, b_buffer);
        auto end_mbed_priv = std::chrono::high_resolution_clock::now();
        mbedtls_rsa_public(&rsa, a_buffer, b_buffer);
        auto end_mbed_pub = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double, std::milli> time_mbed_priv
            = end_mbed_priv - begin_mbed;
        std::chrono::duration<double, std::milli> time_mbed_pub
            = end_mbed_pub - end_mbed_priv;
        std::cout << "mbedTLS (private): " << time_mbed_priv.count() << " ms"
                  << std::endl;
        std::cout << "mbedTLS (public): " << time_mbed_pub.count() << " ms"
                  << std::endl;
    }
}


static void ppke()
{
    std::array<uint8_t, 32> master_key;
    for (size_t i = 0; i < master_key.size(); i++) {
        master_key[i] = 1 << i;
    }

    sse::crypto::Gmppke                 ppke;
    sse::crypto::GmppkePublicKey        pk;
    sse::crypto::GmppkePrivateKey       sk;
    sse::crypto::GmppkeSecretParameters sp;

    ppke.keygen(sse::crypto::Key<32>(master_key.data()), pk, sk, sp);

    typedef uint64_t M_type;


    //    size_t puncture_count = 10;
    size_t bench_count = 200;

    std::vector<size_t> puncture_count_list = {0, 1, 2};
    //    std::vector<size_t> puncture_count_list = {0, 1, 2, 5, 10, 15, 20, 30,
    //    40 , 50, 100};

    size_t current_p_count = 0;

    for (size_t p : puncture_count_list) {
        if (p > current_p_count) {
            size_t n_punctures = p - current_p_count;
            std::cout << "Puncture the key " << n_punctures << " times...";

            std::chrono::duration<double, std::milli> puncture_time(0);

            // add new punctures
            for (; current_p_count < p; current_p_count++) {
                sse::crypto::tag_type punctured_tag{{0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00}};
                punctured_tag[15] = current_p_count & 0xFF;
                punctured_tag[14] = (current_p_count >> 8) & 0xFF;
                punctured_tag[13] = (current_p_count >> 16) & 0xFF;
                punctured_tag[12] = (current_p_count >> 24) & 0xFF;
                punctured_tag[11] = (current_p_count >> 32) & 0xFF;
                punctured_tag[10] = (current_p_count >> 40) & 0xFF;
                punctured_tag[9]  = (current_p_count >> 48) & 0xFF;
                //            punctured_tag[8] = (current_p_count>>56)&0xFF;
                punctured_tag[8] = 0xFF;

                auto t_start = std::chrono::high_resolution_clock::now();

                ppke.puncture(pk, sk, punctured_tag);

                auto t_end = std::chrono::high_resolution_clock::now();
                puncture_time += t_end - t_start;
            }

            std::cout << "Done\n";
            std::cout << "Average puncturing time: "
                      << puncture_time.count() / n_punctures << " ms/puncture"
                      << std::endl;
        }
        std::chrono::duration<double, std::milli> encrypt_time(0);
        std::chrono::duration<double, std::milli> sp_encrypt_time(0);
        std::chrono::duration<double, std::milli> decrypt_time(0);

        std::cout << "Running " << bench_count
                  << " encryption/decryptions with " << current_p_count
                  << " punctures...";

        for (size_t i = 0; i < bench_count; i++) {
            M_type M;

            sse::crypto::random_bytes(sizeof(M_type), (uint8_t*)&M);

            sse::crypto::tag_type tag{{0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00}};
            tag[0] = i & 0xFF;
            tag[1] = (i >> 8) & 0xFF;
            tag[2] = (i >> 16) & 0xFF;
            tag[3] = (i >> 24) & 0xFF;
            tag[4] = (i >> 32) & 0xFF;
            tag[5] = (i >> 40) & 0xFF;
            tag[6] = (i >> 48) & 0xFF;
            tag[7] = (i >> 56) & 0xFF;

            auto t_start = std::chrono::high_resolution_clock::now();
            auto ct      = ppke.encrypt<M_type>(pk, M, tag);
            auto t_end   = std::chrono::high_resolution_clock::now();

            encrypt_time += t_end - t_start;

            t_start  = std::chrono::high_resolution_clock::now();
            auto ct2 = ppke.encrypt<M_type>(sp, M, tag);
            t_end    = std::chrono::high_resolution_clock::now();

            sp_encrypt_time += t_end - t_start;

            t_start      = std::chrono::high_resolution_clock::now();
            M_type dec_M = ppke.decrypt(sk, ct2);
            t_end        = std::chrono::high_resolution_clock::now();
            decrypt_time += t_end - t_start;

            M_type dec_M2 = ppke.decrypt(sk, ct2);

            if (M == dec_M) {
                //            std::cout << " \t OK!" << std::endl;
            } else {
                std::cout << "Puncturable encryption error!" << std::endl;
                std::cout << "M: " << hex << M;
                std::cout << "\t decrypted M: " << hex << dec_M << dec;
                std::cout << std::endl;
            }

            if (M == dec_M2) {
                //            std::cout << " \t OK!" << std::endl;
            } else {
                std::cout << "Puncturable encryption error!" << std::endl;
                std::cout << "M: " << hex << M;
                std::cout << "\t decrypted M (from CT2): " << hex << dec_M2
                          << dec;
                std::cout << std::endl;
            }
        }

        std::cout << "Done. \n";
        std::cout << "Encryption: " << encrypt_time.count() / bench_count
                  << " ms" << std::endl;
        std::cout << "Encryption with secret: "
                  << sp_encrypt_time.count() / bench_count << " ms"
                  << std::endl;
        std::cout << "Decryption: " << decrypt_time.count() / bench_count
                  << " ms" << std::endl;
    }
}

static void deterministic_key_ppke()
{
    std::array<uint8_t, 32> master_key;
    for (size_t i = 0; i < master_key.size(); i++) {
        master_key[i] = 1 << i;
    }
    sse::crypto::Prf<sse::crypto::kPPKEPrfOutputSize> key_prf(
        (sse::crypto::Key<32>(master_key.data())));

    std::cout << "Deterministic key generation\n";

    sse::crypto::Gmppke                 ppke;
    sse::crypto::GmppkePublicKey        pk;
    sse::crypto::GmppkePrivateKey       sk;
    sse::crypto::GmppkeSecretParameters sp;

    ppke.keygen(sse::crypto::Key<32>(master_key.data()), pk, sk, sp);

    typedef uint64_t M_type;

    std::cout << "Key share size: "
              << sse::crypto::GmppkePrivateKeyShare::kByteSize << "B\n";
    std::cout << "Ciphertext size: "
              << sse::crypto::GmmppkeCT<M_type>::kByteSize << "B\n";

    size_t bench_count = 200;

    std::vector<size_t> puncture_count_list
        = {0, 1, 2, 5, 10, 15, 20, 30, 40, 50, 100};

    size_t current_p_count = 0;

    std::vector<sse::crypto::GmppkePrivateKeyShare> keyshares;
    keyshares.push_back(ppke.sk0Gen(key_prf, sp, 0));

    for (size_t p : puncture_count_list) {
        if (p > current_p_count) {
            size_t n_punctures = p - current_p_count;
            std::cout << "Puncture the key " << n_punctures << " times...";

            std::chrono::duration<double, std::milli> puncture_time(0);

            // add new punctures
            for (; current_p_count < p; current_p_count++) {
                sse::crypto::tag_type punctured_tag{{0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00,
                                                     0x00}};
                punctured_tag[15] = current_p_count & 0xFF;
                punctured_tag[14] = (current_p_count >> 8) & 0xFF;
                punctured_tag[13] = (current_p_count >> 16) & 0xFF;
                punctured_tag[12] = (current_p_count >> 24) & 0xFF;
                punctured_tag[11] = (current_p_count >> 32) & 0xFF;
                punctured_tag[10] = (current_p_count >> 40) & 0xFF;
                punctured_tag[9]  = (current_p_count >> 48) & 0xFF;
                //            punctured_tag[8] = (current_p_count>>56)&0xFF;
                punctured_tag[8] = 0xFF;

                auto t_start = std::chrono::high_resolution_clock::now();

                auto share = ppke.skShareGen(
                    key_prf, sp, current_p_count + 1, punctured_tag);

                auto t_end = std::chrono::high_resolution_clock::now();

                keyshares.push_back(share);

                puncture_time += t_end - t_start;
            }

            std::cout << "Done\n";
            std::cout << "Average puncturing time: "
                      << puncture_time.count() / n_punctures << " ms/puncture"
                      << std::endl;
            // update accordingly the first key share
            keyshares[0] = ppke.sk0Gen(key_prf, sp, current_p_count);
        }
        std::chrono::duration<double, std::milli> encrypt_time(0);
        std::chrono::duration<double, std::milli> sp_encrypt_time(0);
        std::chrono::duration<double, std::milli> decrypt_time(0);

        std::cout << "Running " << bench_count
                  << " encryption/decryptions with " << current_p_count
                  << " punctures...";


        for (size_t i = 0; i < bench_count; i++) {
            M_type M;

            sse::crypto::random_bytes(sizeof(M_type), (uint8_t*)&M);

            sse::crypto::tag_type tag{{0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00}};
            tag[0] = i & 0xFF;
            tag[1] = (i >> 8) & 0xFF;
            tag[2] = (i >> 16) & 0xFF;
            tag[3] = (i >> 24) & 0xFF;
            tag[4] = (i >> 32) & 0xFF;
            tag[5] = (i >> 40) & 0xFF;
            tag[6] = (i >> 48) & 0xFF;
            tag[7] = (i >> 56) & 0xFF;

            auto t_start = std::chrono::high_resolution_clock::now();
            auto ct      = ppke.encrypt<M_type>(pk, M, tag);
            auto t_end   = std::chrono::high_resolution_clock::now();

            encrypt_time += t_end - t_start;

            t_start  = std::chrono::high_resolution_clock::now();
            auto ct2 = ppke.encrypt<M_type>(sp, M, tag);
            t_end    = std::chrono::high_resolution_clock::now();

            sp_encrypt_time += t_end - t_start;

            t_start = std::chrono::high_resolution_clock::now();
            M_type dec_M
                = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);
            t_end = std::chrono::high_resolution_clock::now();
            decrypt_time += t_end - t_start;

            M_type dec_M2
                = ppke.decrypt(sse::crypto::GmppkePrivateKey(keyshares), ct2);

            if (M == dec_M) {
                //            std::cout << " \t OK!" << std::endl;
            } else {
                std::cout << "Puncturable encryption error!" << std::endl;
                std::cout << "M: " << hex << M;
                std::cout << "\t decrypted M: " << hex << dec_M << dec;
                std::cout << std::endl;
            }

            if (M == dec_M2) {
                //            std::cout << " \t OK!" << std::endl;
            } else {
                std::cout << "Puncturable encryption error!" << std::endl;
                std::cout << "M: " << hex << M;
                std::cout << "\t decrypted M (from CT2): " << hex << dec_M2
                          << dec;
                std::cout << std::endl;
            }
        }

        std::cout << "Done. \n";
        std::cout << "Encryption: " << encrypt_time.count() / bench_count
                  << " ms" << std::endl;
        std::cout << "Encryption with secret: "
                  << sp_encrypt_time.count() / bench_count << " ms"
                  << std::endl;
        std::cout << "Decryption: " << decrypt_time.count() / bench_count
                  << " ms" << std::endl;
    }
}

void relic()
{
    sse::crypto::Prf<sse::crypto::kPPKEPrfOutputSize> key_prf;

    relicxx::PairingGroup group;

    //    relicxx::ZR rho_1 = group.pseudoRandomZR(key_prf, ("param_rho_1"));
    //    relicxx::ZR rho_2 = group.pseudoRandomZR(key_prf, ("param_rho_2"));

    std::array<uint8_t, sse::crypto::kPPKEPrfOutputSize> out_1
        = key_prf.prf(("1"));
    std::array<uint8_t, sse::crypto::kPPKEPrfOutputSize> out_2
        = key_prf.prf(("2"));

    if (out_1 == out_2) {
        cout << "EQUALITY" << endl;
    }

    //    cout << rho_1 << endl;
    //    cout << rho_2 << endl;
}


void elligator()
{
    sse::crypto::SetHash a, b, c;

    string elt_1 = "toto";
    string elt_2 = "titi";

    a.add_element(elt_1);
    a.add_element(elt_2);

    b.add_element(elt_2);
    b.add_element(elt_1);

    assert(a == b);

    a.add_set(b);

    b.add_element(elt_2);
    b.add_element(elt_1);

    assert(a == b);

    //    a.remove_set(b);
    //    assert(a == c);


    //    uint8_t p[crypto_core_ed25519_BYTES];
    //    uint8_t q[crypto_core_ed25519_BYTES];
    //    uint8_t r[crypto_core_ed25519_BYTES];
    //
    //    uint8_t zero [crypto_scalarmult_ed25519_SCALARBYTES];
    //    memset(zero, 0x00, crypto_scalarmult_ed25519_SCALARBYTES);
    //
    //    uint8_t rnd [crypto_scalarmult_ed25519_SCALARBYTES];
    //    randombytes_buf(rnd, crypto_scalarmult_ed25519_SCALARBYTES);
    //
    //    int ret;
    //
    //    ret = crypto_scalarmult_ed25519_base(p, rnd);
    //    assert(ret == 0);
    //
    //    ret = crypto_scalarmult_ed25519_base(q, rnd);
    //    assert(ret == 0);
    //
    //    ret = crypto_core_ed25519_sub(r, p, q);
    //    assert(ret == 0);
    //
    //    assert(crypto_core_ed25519_is_valid_point(p));
    //    assert(crypto_core_ed25519_is_valid_point(q));
    ////    assert(crypto_core_ed25519_is_valid_point(r));
    //
    //    crypto_core_ed25519_add(q, p, r);
    //
    //    assert(sodium_memcmp(p,q,crypto_core_ed25519_BYTES) == 0);
}

int main(int argc, char* argv[])
{
    sse::crypto::init_crypto_lib();

    //    sse::crypto::test_keys();
    //    bench_rsa();
    elligator();
    //    tdp();

    sse::crypto::cleanup_crypto_lib();

    return 0;
}
