
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

#ifdef WITH_OPENSSL
#pragma message "Use OpenSSL"

#include "tdp_impl_openssl.hpp"

#include "prf.hpp"
#include "random.hpp"

#include <cstring>

#include <exception>
#include <iomanip>
#include <iostream>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


namespace sse {

namespace crypto {


static_assert(Tdp::kMessageSize == TdpInverse::kMessageSize,
              "Constants kMessageSize of Tdp and TdpInverse do not match");

#define RSA_MODULUS_SIZE (TdpInverse::kMessageSize * 8)

#define RSA_PK 0x10001L // RSA_F4 for OpenSSL


#define BN_num_bytes_U(a) static_cast<unsigned int>(BN_num_bytes((a)))

// A drop-in replacement of BIO_set_close that is C++11 friendly
#define OpenSSE_BIO_set_close(b, c)                                            \
    BIO_ctrl(b, BIO_CTRL_SET_CLOSE, (c), nullptr)

// A drop-in replacement of BN_mod that is C++11 friendly
#define OpenSSE_BN_mod(rem, m, d, ctx) BN_div(nullptr, (rem), (m), (d), (ctx))

// OpenSSL implementation of the trapdoor permutation

TdpImpl_OpenSSL::TdpImpl_OpenSSL() = default;

TdpImpl_OpenSSL::TdpImpl_OpenSSL(const std::string& pk)
{
    // create a BIO from the std::string
    BIO* mem;

    // Some old implementation OpenSSL declares BIO_new_mem_buf( void *, int)
    // instead BIO_new_mem_buf( const void *, int)
    // silence the warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    mem = BIO_new_mem_buf(
        const_cast<void*>(reinterpret_cast<const void*>(pk.data())),
        static_cast<int>(pk.length()));
#pragma GCC diagnostic pop

    // read the key from the BIO
    rsa_key_ = PEM_read_bio_RSA_PUBKEY(mem, nullptr, nullptr, nullptr);

    if (rsa_key_ == nullptr) {
        BIO_free(mem);
        throw std::runtime_error(
            "Error when initializing the RSA key from public key.");
    }

    // close and destroy the BIO
    if (OpenSSE_BIO_set_close(mem, BIO_CLOSE)
        != 1) // So BIO_free() leaves BUF_MEM alone
    {
        // always returns 1 ...
    }
    BIO_free(mem);
}

TdpImpl_OpenSSL::TdpImpl_OpenSSL(const TdpImpl_OpenSSL& tdp)
{
    set_rsa_key(RSAPublicKey_dup(tdp.rsa_key_)); /* LCOV_EXCL_LINE */
}

TdpImpl_OpenSSL& TdpImpl_OpenSSL::operator=(const TdpImpl_OpenSSL& t)
{
    if (this != &t) {
        set_rsa_key(RSAPublicKey_dup(t.rsa_key_)); /* LCOV_EXCL_LINE */
    }

    return *this;
}

inline RSA* TdpImpl_OpenSSL::get_rsa_key() const
{
    return rsa_key_;
}

inline void TdpImpl_OpenSSL::set_rsa_key(RSA* k)
{
    if (k == nullptr) {
        throw std::invalid_argument(
            "Invalid input: k == nullptr."); /* LCOV_EXCL_LINE */
    }
    if (rsa_key_ != nullptr) {
        RSA_free(rsa_key_);
    }
    rsa_key_ = k;
    RSA_blinding_off(rsa_key_);
}

inline size_t TdpImpl_OpenSSL::rsa_size() const
{
    return (static_cast<size_t>(RSA_size(get_rsa_key())));
}

// NOLINTNEXTLINE(modernize-use-equals-default)
TdpImpl_OpenSSL::~TdpImpl_OpenSSL()
{
    RSA_free(rsa_key_);
}

std::string TdpImpl_OpenSSL::public_key() const
{
    int ret;

    // initialize a buffer
    BIO* bio = BIO_new(BIO_s_mem());

    // write the key to the buffer
    ret = PEM_write_bio_RSA_PUBKEY(bio, rsa_key_);

    if (ret != 1) {
        /* LCOV_EXCL_START */
        BIO_free(bio);
        throw std::runtime_error("Error when serializing the RSA public key.");
        /* LCOV_EXCL_START */
    }


    // put the buffer in a std::string
    size_t len = BIO_ctrl_pending(bio);
    void*  buf = malloc(len);

    int read_bytes = BIO_read(bio, buf, static_cast<int>(len));

    if (read_bytes == 0) {
        /* LCOV_EXCL_START */
        BIO_free(bio);
        free(buf);
        throw std::runtime_error("Error when reading BIO.");
        /* LCOV_EXCL_STOP */
    }

    std::string v(reinterpret_cast<const char*>(buf), len);

    BIO_free(bio);
    free(buf);

    return v;
}

void TdpImpl_OpenSSL::eval(const std::string& in, std::string& out) const
{
    if (in.size() != rsa_size()) {
        throw std::invalid_argument("Invalid TDP input size. Input size should "
                                    "be kMessageSpaceSize bytes long.");
    }

    std::array<uint8_t, kMessageSpaceSize> in_array;


    memcpy(in_array.data(), in.data(), kMessageSpaceSize);

    auto out_array = eval(in_array);

    out = std::string(out_array.begin(), out_array.end());
}


std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> TdpImpl_OpenSSL::eval(
    const std::array<uint8_t, kMessageSpaceSize>& in) const
{
    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> out;


    if (in.size() != rsa_size()) {
        throw std::runtime_error(
            "Invalid TDP input size. Input size should be kMessageSpaceSize "
            "bytes long."); /* LCOV_EXCL_LINE */
    }

    BN_CTX* ctx = BN_CTX_new();

    BIGNUM* x = BN_new();
    BN_bin2bn(in.data(), static_cast<int>(in.size()), x);

    BIGNUM* y = BN_new();

    BN_mod_exp(y, x, get_rsa_key()->e, get_rsa_key()->n, ctx);

    // Unless there is a bug in OpenSSL, the number of bytes used by y, should
    // be less than the size of the message.
    assert(BN_num_bytes_U(y) <= kMessageSpaceSize);

    // bn2bin returns a BIG endian array, so be careful ...
    size_t pos = kMessageSpaceSize - BN_num_bytes_U(y);
    // set the leading bytes to 0
    std::fill(out.begin(), out.begin() + pos, 0);
    BN_bn2bin(y, out.data() + pos);

    BN_free(y);
    BN_free(x);
    BN_CTX_free(ctx);

    return out;
}


std::string TdpImpl_OpenSSL::sample() const
{
    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> tmp
        = sample_array();

    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> TdpImpl_OpenSSL::
    sample_array() const
{
    // I don't really trust OpenSSL PRNG, but this is the simplest way
    int                                    ret;
    BIGNUM*                                rnd;
    std::array<uint8_t, kMessageSpaceSize> out;
    std::fill(out.begin(), out.end(), 0);

    rnd = BN_new();

    ret = BN_rand_range(rnd, rsa_key_->n);
    if (ret != 1) {
        /* LCOV_EXCL_START */
        BN_free(rnd);
        throw std::runtime_error(
            "Invalid random number generation."); /* LCOV_EXCL_LINE */
        /* LCOV_EXCL_STOP */
    }
    size_t offset = kMessageSpaceSize - BN_num_bytes_U(rnd);

    BN_bn2bin(rnd, out.data() + offset);
    BN_free(rnd);

    return out;
}

std::string TdpImpl_OpenSSL::generate(const Prf<Tdp::kRSAPrfSize>& prg,
                                      const std::string&           seed) const
{
    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> tmp
        = generate_array(prg, seed);

    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> TdpImpl_OpenSSL::
    generate_array(const Prf<Tdp::kRSAPrfSize>& prg,
                   const std::string&           seed) const
{
    std::array<uint8_t, Tdp::kRSAPrfSize> rnd = prg.prf(seed);

    BIGNUM* rnd_bn;
    BIGNUM* rnd_mod;
    BN_CTX* ctx = BN_CTX_new();

    rnd_bn = BN_bin2bn(rnd.data(), Tdp::kRSAPrfSize, nullptr);

    // now, take rnd_bn mod N
    rnd_mod = BN_new();

    OpenSSE_BN_mod(rnd_mod, rnd_bn, rsa_key_->n, ctx);


    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> out;
    std::fill(out.begin(), out.end(), 0);
    size_t offset = kMessageSpaceSize - BN_num_bytes_U(rnd_mod);

    BN_bn2bin(rnd_mod, out.data() + offset);

    BN_free(rnd_bn);
    BN_free(rnd_mod);
    BN_CTX_free(ctx);

    return out;
}

std::string TdpImpl_OpenSSL::generate(
    Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
    const std::string&                     seed) const
{
    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> tmp
        = generate_array(std::move(key), seed);

    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> TdpImpl_OpenSSL::
    generate_array(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                   const std::string&                     seed) const
{
    Prf<Tdp::kRSAPrfSize> prg(std::move(key));

    return generate_array(prg, seed);
}


std::unique_ptr<TdpImpl> TdpImpl_OpenSSL::duplicate() const
{
    return std::unique_ptr<TdpImpl>(new TdpImpl_OpenSSL(*this));
}

TdpInverseImpl_OpenSSL::TdpInverseImpl_OpenSSL()
{
    int ret;

    // initialize the key
    set_rsa_key(RSA_new());

    // generate a new random key

    uint64_t e   = RSA_PK;
    BIGNUM*  bne = BN_new();
    ret          = BN_set_word(bne, e);
    if (ret != 1) {
        /* LCOV_EXCL_START */
        BN_free(bne);
        throw std::runtime_error("Invalid BIGNUM initialization.");
        /* LCOV_EXCL_STOP */
    }

    ret = RSA_generate_key_ex(get_rsa_key(), RSA_MODULUS_SIZE, bne, nullptr);
    if (ret != 1) {
        /* LCOV_EXCL_START */
        BN_free(bne);
        throw std::runtime_error("Invalid RSA key generation.");
        /* LCOV_EXCL_STOP */
    }

    // initialize the useful variables
    phi_ = BN_new();
    p_1_ = BN_dup(get_rsa_key()->p);
    q_1_ = BN_dup(get_rsa_key()->q);
    BN_sub_word(p_1_, 1);
    BN_sub_word(q_1_, 1);

    BN_CTX* ctx = BN_CTX_new();

    BN_mul(phi_, p_1_, q_1_, ctx);

    BN_CTX_free(ctx);
    BN_free(bne);
}

TdpInverseImpl_OpenSSL::TdpInverseImpl_OpenSSL(const std::string& sk)
{
    // create a BIO from the std::string
    BIO* mem;

    // Some old implementation OpenSSL declares BIO_new_mem_buf( void *, int)
    // instead BIO_new_mem_buf( const void *, int)
    // silence the warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    mem = BIO_new_mem_buf(
        const_cast<void*>(reinterpret_cast<const void*>(sk.data())),
        static_cast<int>(sk.length()));
#pragma GCC diagnostic pop


    EVP_PKEY* evpkey;
    evpkey = PEM_read_bio_PrivateKey(mem, nullptr, nullptr, nullptr);

    if (evpkey == nullptr) {
        BIO_free(mem);
        throw std::runtime_error("Error when reading the RSA private key.");
    }

    // read the key from the BIO
    set_rsa_key(EVP_PKEY_get1_RSA(evpkey));
    EVP_PKEY_free(evpkey);


    // close and destroy the BIO
    if (OpenSSE_BIO_set_close(mem, BIO_CLOSE)
        != 1) // So BIO_free() leaves BUF_MEM alone
    {
        // always returns 1 ...
    }

    BIO_free(mem);

    // initialize the useful variables
    phi_ = BN_new();
    p_1_ = BN_dup(get_rsa_key()->p);
    q_1_ = BN_dup(get_rsa_key()->q);
    BN_sub_word(p_1_, 1);
    BN_sub_word(q_1_, 1);

    BN_CTX* ctx = BN_CTX_new();
    BN_mul(phi_, p_1_, q_1_, ctx);
    BN_CTX_free(ctx);
}

// NOLINTNEXTLINE(modernize-use-equals-default)
TdpInverseImpl_OpenSSL::~TdpInverseImpl_OpenSSL()
{
    BN_free(phi_);
    BN_free(p_1_);
    BN_free(q_1_);
}

std::string TdpInverseImpl_OpenSSL::private_key() const
{
    int ret;

    // create an EVP encapsulation
    EVP_PKEY* evpkey = EVP_PKEY_new();
    ret              = EVP_PKEY_set1_RSA(evpkey, get_rsa_key());
    if (ret != 1) {
        /* LCOV_EXCL_START */
        EVP_PKEY_free(evpkey);
        throw std::runtime_error("Invalid EVP initialization.");
        /* LCOV_EXCL_STOP */
    }

    // initialize a buffer
    BIO* bio = BIO_new(BIO_s_mem());

    // write the key to the buffer
    ret = PEM_write_bio_PKCS8PrivateKey(
        bio, evpkey, nullptr, nullptr, 0, nullptr, nullptr);
    if (ret != 1) {
        /* LCOV_EXCL_START */
        EVP_PKEY_free(evpkey);
        BIO_free(bio);
        throw std::runtime_error("Failure when writing private KEY.");
        /* LCOV_EXCL_STOP */
    }

    // put the buffer in a std::string
    size_t len = BIO_ctrl_pending(bio);
    void*  buf = malloc(len);

    int read_bytes = BIO_read(bio, buf, static_cast<int>(len));
    if (read_bytes == 0) {
        /* LCOV_EXCL_START */
        EVP_PKEY_free(evpkey);
        BIO_free(bio);
        free(buf);

        throw std::runtime_error("Error when reading BIO.");
        /* LCOV_EXCL_STOP */
    }


    std::string v(reinterpret_cast<const char*>(buf), len);

    EVP_PKEY_free(evpkey);
    BIO_free_all(bio);
    free(buf);

    return v;
}


void TdpInverseImpl_OpenSSL::invert(const std::string& in,
                                    std::string&       out) const
{
    int                                          ret;
    std::array<unsigned char, kMessageSpaceSize> rsa_out;

    if (in.size() != kMessageSpaceSize) {
        throw std::invalid_argument("Invalid TDP input size. Input size should "
                                    "be kMessageSpaceSize bytes long.");
    }

    ret = RSA_private_decrypt(static_cast<int>(in.size()),
                              reinterpret_cast<const unsigned char*>(in.data()),
                              rsa_out.data(),
                              get_rsa_key(),
                              RSA_NO_PADDING);

    if (ret < 0) {
        /* LCOV_EXCL_START */
        throw std::runtime_error(
            "Error while inverting the trapdoor permutation");
        /* LCOV_EXCL_STOP */
    }

    out = std::string(reinterpret_cast<char*>(rsa_out.data()),
                      static_cast<size_t>(ret));
}

std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> TdpInverseImpl_OpenSSL::
    invert(const std::array<uint8_t, kMessageSpaceSize>& in) const
{
    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> out;

    RSA_private_decrypt(static_cast<int>(in.size()),
                        in.data(),
                        out.data(),
                        get_rsa_key(),
                        RSA_NO_PADDING);

    return out;
}

std::array<uint8_t, TdpInverseImpl_OpenSSL::kMessageSpaceSize>
TdpInverseImpl_OpenSSL::invert_mult(
    const std::array<uint8_t, kMessageSpaceSize>& in,
    uint32_t                                      order) const
{
    if (order == 0) {
        return in;
    }

    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> out;


    if (in.size() != rsa_size()) {
        throw std::invalid_argument(
            "Invalid TDP input size. Input size should be kMessageSpaceSize "
            "bytes long."); /* LCOV_EXCL_LINE */
    }

    BN_CTX* ctx      = BN_CTX_new();
    BIGNUM* bn_order = BN_new();
    BIGNUM* d_p      = BN_new();
    BIGNUM* d_q      = BN_new();
    BN_set_word(bn_order, order);

    BN_mod_exp(d_p, get_rsa_key()->d, bn_order, p_1_, ctx);
    BN_mod_exp(d_q, get_rsa_key()->d, bn_order, q_1_, ctx);

    BIGNUM* x = BN_new();
    BN_bin2bn(in.data(), static_cast<int>(in.size()), x);

    BIGNUM* y_p = BN_new();
    BIGNUM* y_q = BN_new();
    BIGNUM* h   = BN_new();
    BIGNUM* y   = BN_new();

    BN_mod_exp(y_p, x, d_p, get_rsa_key()->p, ctx);
    BN_mod_exp(y_q, x, d_q, get_rsa_key()->q, ctx);

    BN_mod_sub(h, y_p, y_q, get_rsa_key()->p, ctx);
    BN_mod_mul(h, h, get_rsa_key()->iqmp, get_rsa_key()->p, ctx);

    BN_mul(y, h, get_rsa_key()->q, ctx);
    BN_add(y, y, y_q);


    // bn2bin returns a BIG endian array, so be careful ...
    size_t pos = kMessageSpaceSize - BN_num_bytes_U(y);
    // set the leading bytes to 0
    std::fill(out.begin(), out.begin() + pos, 0);
    BN_bn2bin(y, out.data() + pos);

    BN_free(bn_order);
    BN_free(d_p);
    BN_free(d_q);
    BN_free(y_p);
    BN_free(y_q);
    BN_free(h);
    BN_free(y);
    BN_free(x);
    BN_CTX_free(ctx);

    return out;
}

void TdpInverseImpl_OpenSSL::invert_mult(const std::string& in,
                                         std::string&       out,
                                         uint32_t           order) const
{
    std::array<uint8_t, kMessageSpaceSize> in_array;

    memcpy(in_array.data(), in.data(), kMessageSpaceSize);

    auto out_array = invert_mult(in_array, order);

    out = std::string(out_array.begin(), out_array.end());
}


TdpMultPoolImpl_OpenSSL::TdpMultPoolImpl_OpenSSL(const std::string& sk,
                                                 const uint8_t      size)
    : TdpImpl_OpenSSL(sk), keys_count_(size - 1)
{
    if (size == 0) {
        throw std::invalid_argument(
            "Invalid Multiple TDP pool input size. Pool size should be > 0.");
    }

    keys_ = new RSA*[keys_count_];

    keys_[0] = RSAPublicKey_dup(get_rsa_key());
    BN_mul_word(keys_[0]->e, RSA_PK);

    for (uint8_t i = 1; i < keys_count_; i++) {
        keys_[i] = RSAPublicKey_dup(keys_[i - 1]);
        BN_mul_word(keys_[i]->e, RSA_PK);
    }
}

TdpMultPoolImpl_OpenSSL::TdpMultPoolImpl_OpenSSL(
    const TdpMultPoolImpl_OpenSSL& pool_impl)
    : TdpImpl_OpenSSL(pool_impl), keys_count_(pool_impl.keys_count_)
{
    keys_ = new RSA*[keys_count_];

    for (uint8_t i = 0; i < keys_count_; i++) {
        keys_[i] = RSAPublicKey_dup(pool_impl.keys_[i]);
    }
}

TdpMultPoolImpl_OpenSSL& TdpMultPoolImpl_OpenSSL::operator=(
    const TdpMultPoolImpl_OpenSSL& t)
{
    if (this != &t) {
        for (uint8_t i = 0; i < keys_count_; i++) {
            RSA_free(keys_[i]);
        }

        if (keys_count_ != t.keys_count_) {
            // realloc the key array
            delete[] keys_;
            keys_count_ = t.keys_count_;
            keys_       = new RSA*[keys_count_];
        }

        for (uint8_t i = 0; i < keys_count_; i++) {
            keys_[i] = RSAPublicKey_dup(t.keys_[i]);
        }
    }
    return *this;
}


TdpMultPoolImpl_OpenSSL::~TdpMultPoolImpl_OpenSSL()
{
    for (uint8_t i = 0; i < keys_count_; i++) {
        RSA_free(keys_[i]);
    }
    delete[] keys_;
}

std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize>
TdpMultPoolImpl_OpenSSL::eval_pool(
    const std::array<uint8_t, kMessageSpaceSize>& in,
    const uint8_t                                 order) const
{
    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> out;

    RSA* key = nullptr;

    // NOLINTNEXTLINE(bugprone-branch-clone)
    if (order == 1) {
        // regular eval
        key = get_rsa_key();
    } else if (order <= maximum_order()) {
        // get the right RSA context, i.e. the one in keys_[order-1]
        key = keys_[order - 2];
    } else {
        throw std::invalid_argument(
            "Invalid order for this TDP pool. The input order must be less "
            "than the maximum order supported by the pool, and strictly "
            "positive.");
    }

    RSA_public_encrypt(static_cast<int>(in.size()),
                       in.data(),
                       out.data(),
                       key,
                       RSA_NO_PADDING);

    return out;
}


void TdpMultPoolImpl_OpenSSL::eval_pool(const std::string& in,
                                        std::string&       out,
                                        const uint8_t      order) const
{
    if (in.size() != rsa_size()) {
        throw std::invalid_argument("Invalid TDP input size. Input size should "
                                    "be kMessageSpaceSize bytes long.");
    }

    std::array<uint8_t, kMessageSpaceSize> a_in;
    std::array<uint8_t, kMessageSpaceSize> a_out;

    memcpy(a_in.data(), in.data(), kMessageSpaceSize);

    a_out = eval_pool(a_in, order);

    out = std::string(a_out.begin(), a_out.end());
}

uint8_t TdpMultPoolImpl_OpenSSL::maximum_order() const
{
    return keys_count_ + 1;
}

std::unique_ptr<TdpMultPoolImpl> TdpMultPoolImpl_OpenSSL::duplicate_pool() const
{
    return std::unique_ptr<TdpMultPoolImpl>(new TdpMultPoolImpl_OpenSSL(*this));
}

} // namespace crypto
} // namespace sse
#endif
