
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2016 Raphael Bost
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

#include "tdp.hpp"

#include "prf.hpp"
#include "random.hpp"

#include <cstring>
#include <exception>
#include <iostream>
#include <iomanip>

#define SSE_CRYPTO_TDP_IMPL_MBEDTLS 1
#define SSE_CRYPTO_TDP_IMPL_OPENSSL 2

#define SSE_CRYPTO_TDP_IMPL SSE_CRYPTO_TDP_IMPL_MBEDTLS

#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#else

#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"
#include "mbedtls/rsa_io.h"

#endif


namespace sse
{

namespace crypto
{
	
    
static_assert(Tdp::kMessageSize == TdpInverse::kMessageSize, "Constants kMessageSize of Tdp and TdpInverse do not match");

#define RSA_MODULUS_SIZE TdpInverse::kMessageSize*8
    
#define RSA_PK 0x10001L // RSA_F4 for OpenSSL
    

class TdpImpl
{
public:
    static constexpr uint kMessageSpaceSize = Tdp::kMessageSize;
    
    TdpImpl(const std::string& pk);
    TdpImpl(const TdpImpl& tdp);
    
    virtual ~TdpImpl();
    
#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)
    RSA* get_rsa_key() const;
    void set_rsa_key(RSA* k);
#else
//    mbedtls_rsa_context* get_rsa_key() const;
//    void set_rsa_key(RSA* k);
#endif
    size_t rsa_size() const;
    
    std::string public_key() const;
    
    void eval(const std::string &in, std::string &out) const;
    std::array<uint8_t, kMessageSpaceSize> eval(const std::array<uint8_t, kMessageSpaceSize> &in) const;

    std::string sample() const;
    std::array<uint8_t, kMessageSpaceSize> sample_array() const;

    std::string generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;
    std::array<uint8_t, kMessageSpaceSize> generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;
    std::string generate(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const;
    std::array<uint8_t, kMessageSpaceSize> generate_array(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const;
    
protected:
    TdpImpl();

#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)
    RSA* rsa_key_;
#else
    mutable mbedtls_rsa_context rsa_key_;
#endif
};

class TdpInverseImpl : public TdpImpl
{
public:
    TdpInverseImpl();
    TdpInverseImpl(const std::string& sk);
    TdpInverseImpl(const TdpInverseImpl& tdp);
    ~TdpInverseImpl();

    std::string private_key() const;
    void invert(const std::string &in, std::string &out) const;
    std::array<uint8_t, kMessageSpaceSize> invert(const std::array<uint8_t, kMessageSpaceSize> &in) const;

    std::array<uint8_t, kMessageSpaceSize> invert_mult(const std::array<uint8_t, kMessageSpaceSize> &in, uint32_t order) const;
    void invert_mult(const std::string &in, std::string &out, uint32_t order) const;
    
private:
#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)
    BIGNUM *phi_, *p_1_, *q_1_;
#else
    mbedtls_mpi phi_, p_1_, q_1_;
#endif
};

class TdpMultPoolImpl : public TdpImpl
{
public:
    TdpMultPoolImpl(const std::string& sk, const uint8_t size);
    TdpMultPoolImpl(const TdpMultPoolImpl& pool_impl);

    ~TdpMultPoolImpl();
    
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> eval(const std::array<uint8_t, kMessageSpaceSize> &in, const uint8_t order) const;
    void eval(const std::string &in, std::string &out, const uint8_t order) const;

    uint8_t maximum_order() const;
    uint8_t pool_size() const;
private:
#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)
    RSA **keys_;
#else
    mbedtls_rsa_context* keys_;
#endif

    uint8_t keys_count_;
};
    

#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)
// OpenSSL implementation of the trapdoor permutation
    
TdpImpl::TdpImpl() : rsa_key_(NULL)
{
}
TdpImpl::TdpImpl(const std::string& pk) : rsa_key_(NULL)
{
    // create a BIO from the std::string
    BIO *mem;

    // Some old implementation OpenSSL declares BIO_new_mem_buf( void *, int)
    // instead BIO_new_mem_buf( const void *, int)
    // silence the warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    mem = BIO_new_mem_buf(((void*)pk.data()), (int)pk.length());
#pragma GCC diagnostic pop
    
    // read the key from the BIO
    rsa_key_ = PEM_read_bio_RSA_PUBKEY(mem,NULL,NULL,NULL);

    if(rsa_key_ == NULL)
    {
        throw std::runtime_error("Error when initializing the RSA key from public key.");
    }
    
    // close and destroy the BIO
    if(BIO_set_close(mem, BIO_NOCLOSE) != 1) // So BIO_free() leaves BUF_MEM alone
    {
        // always returns 1 ...
    }
    BIO_free(mem);
}
    
TdpImpl::TdpImpl(const TdpImpl& tdp)
{
    set_rsa_key(RSAPublicKey_dup(tdp.rsa_key_)); /* LCOV_EXCL_LINE */
}
    

inline RSA* TdpImpl::get_rsa_key() const
{
    return rsa_key_;
}
    
inline void TdpImpl::set_rsa_key(RSA* k)
{
    if(k == NULL)
    {
        throw std::invalid_argument("Invalid input: k == NULL."); /* LCOV_EXCL_LINE */
    }

    rsa_key_ = k;
    RSA_blinding_off(rsa_key_);
}

inline size_t TdpImpl::rsa_size() const
{
    return ((size_t) RSA_size(get_rsa_key()));
}

TdpImpl::~TdpImpl()
{
    RSA_free(rsa_key_);
}

std::string TdpImpl::public_key() const
{
    int ret;
    
    // initialize a buffer
    BIO *bio = BIO_new(BIO_s_mem());
    
    // write the key to the buffer
    ret = PEM_write_bio_RSA_PUBKEY(bio, rsa_key_);

    if(ret != 1)
    {
        throw std::runtime_error("Error when serializing the RSA public key."); /* LCOV_EXCL_LINE */
    }
    

    // put the buffer in a std::string
    size_t len = BIO_ctrl_pending(bio);
    void *buf = malloc(len);
    
    int read_bytes = BIO_read(bio, buf, (int)len);
    
    if(read_bytes == 0)
    {
        throw std::runtime_error("Error when reading BIO."); /* LCOV_EXCL_LINE */
    }

    std::string v(reinterpret_cast<const char*>(buf), len);
    
    BIO_free_all(bio);
    free(buf);
    
    return v;
}

void TdpImpl::eval(const std::string &in, std::string &out) const
{
    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }

    std::array<uint8_t, kMessageSpaceSize> in_array;
    
    
    memcpy(in_array.data(), in.data(), kMessageSpaceSize);
    
    auto out_array = eval(in_array);
    
    out = std::string(out_array.begin(), out_array.end());
}
    

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::eval(const std::array<uint8_t, kMessageSpaceSize> &in) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    
    
    if(in.size() != rsa_size())
    {
        throw std::runtime_error("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long."); /* LCOV_EXCL_LINE */
    }
    
    BN_CTX* ctx = BN_CTX_new();

    BIGNUM *x = BN_new();
    BN_bin2bn(in.data(), (unsigned int)in.size(), x);
    
    BIGNUM *y = BN_new();
    
    BN_mod_exp(y,x,get_rsa_key()->e, get_rsa_key()->n, ctx);
    
    
    // bn2bin returns a BIG endian array, so be careful ...
    size_t pos = kMessageSpaceSize - BN_num_bytes(y);
    // set the leading bytes to 0
    std::fill(out.begin(), out.begin()+pos, 0);
    BN_bn2bin(y, out.data()+pos);
    
    BN_free(y);
    BN_free(x);
    BN_CTX_free(ctx);
    
    return out;
}


std::string TdpImpl::sample() const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> tmp = sample_array();
    
    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::sample_array() const
{
    // I don't really trust OpenSSL PRNG, but this is the simplest way
    int ret;
    BIGNUM *rnd;
    std::array<uint8_t, kMessageSpaceSize> out;
    std::fill(out.begin(), out.end(), 0);

    rnd = BN_new();
    
    ret = BN_rand_range(rnd, rsa_key_->n);
    if(ret != 1)
    {
        throw std::runtime_error("Invalid random number generation."); /* LCOV_EXCL_LINE */
    }
    size_t offset = kMessageSpaceSize - BN_num_bytes(rnd);
    
    BN_bn2bin(rnd, out.data()+offset);
    BN_free(rnd);
    
    return out;
}

std::string TdpImpl::generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> tmp = generate_array(prg, seed);
    
    return std::string(tmp.begin(), tmp.end());
}
    
std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    std::array<uint8_t, Tdp::kRSAPrgSize> rnd = prg.prf(seed);
    
    BIGNUM *rnd_bn, *rnd_mod;
    BN_CTX *ctx = BN_CTX_new();
    
    rnd_bn = BN_bin2bn(rnd.data(), Tdp::kRSAPrgSize, NULL);
    
    // now, take rnd_bn mod N
    rnd_mod = BN_new();
    
    BN_mod(rnd_mod, rnd_bn, rsa_key_->n, ctx);
    
    
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    std::fill(out.begin(), out.end(), 0);
    size_t offset = kMessageSpaceSize - BN_num_bytes(rnd_mod);
    
    BN_bn2bin(rnd_mod, out.data()+offset);
    
    BN_free(rnd_bn);
    BN_free(rnd_mod);
    BN_CTX_free(ctx);
    
    return out;
}

std::string TdpImpl::generate(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> tmp = generate_array(std::move(key), seed);
    
    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::generate_array(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    Prf<Tdp::kRSAPrgSize> prg(std::move(key));
    
    return generate_array(prg, seed);
}

TdpInverseImpl::TdpInverseImpl()
{
    int ret;
    
    // initialize the key
    set_rsa_key(RSA_new());
    
    // generate a new random key
    
    unsigned long e = RSA_PK;
    BIGNUM *bne = NULL;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if(ret != 1)
    {
        throw std::runtime_error("Invalid BIGNUM initialization."); /* LCOV_EXCL_LINE */
    }
    
    ret = RSA_generate_key_ex(get_rsa_key(), RSA_MODULUS_SIZE, bne, NULL);
    if(ret != 1)
    {
        throw std::runtime_error("Invalid RSA key generation."); /* LCOV_EXCL_LINE */
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

TdpInverseImpl::TdpInverseImpl(const std::string& sk)
{
    // create a BIO from the std::string
    BIO *mem;
    
    // Some old implementation OpenSSL declares BIO_new_mem_buf( void *, int)
    // instead BIO_new_mem_buf( const void *, int)
    // silence the warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    mem = BIO_new_mem_buf(((void*)sk.data()), (int)sk.length());
#pragma GCC diagnostic pop


    EVP_PKEY* evpkey;
    evpkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);

    if(evpkey == NULL)
    {
        throw std::runtime_error("Error when reading the RSA private key.");
    }

    // read the key from the BIO
    set_rsa_key( EVP_PKEY_get1_RSA(evpkey));

    
    // close and destroy the BIO
    if(BIO_set_close(mem, BIO_NOCLOSE) != 1) // So BIO_free() leaves BUF_MEM alone
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

TdpInverseImpl::TdpInverseImpl(const TdpInverseImpl& tdp)
{
    set_rsa_key(RSAPrivateKey_dup(tdp.rsa_key_));

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
    
TdpInverseImpl::~TdpInverseImpl()
{
    BN_free(phi_);
    BN_free(p_1_);
    BN_free(q_1_);
}

std::string TdpInverseImpl::private_key() const
{
    int ret;
    
    // create an EVP encapsulation
    EVP_PKEY* evpkey = EVP_PKEY_new();
    ret = EVP_PKEY_set1_RSA(evpkey, get_rsa_key());
    if(ret != 1)
    {
        throw std::runtime_error("Invalid EVP initialization."); /* LCOV_EXCL_LINE */
    }
    
    // initialize a buffer
    BIO *bio = BIO_new(BIO_s_mem());
    
    // write the key to the buffer
    ret = PEM_write_bio_PKCS8PrivateKey(bio, evpkey, NULL, NULL, 0, NULL, NULL);
    if(ret != 1)
    {
        throw std::runtime_error("Failure when writing private KEY."); /* LCOV_EXCL_LINE */
    }
    
    // put the buffer in a std::string
    size_t len = BIO_ctrl_pending(bio);
    void *buf = malloc(len);
    
    int read_bytes = BIO_read(bio, buf, (int)len);
    if(read_bytes == 0)
    {
        throw std::runtime_error("Error when reading BIO."); /* LCOV_EXCL_LINE */
    }
    
    
    std::string v(reinterpret_cast<const char*>(buf), len);
    
    EVP_PKEY_free(evpkey);
    BIO_free_all(bio);
    free(buf);
    
    return v;
}


void TdpInverseImpl::invert(const std::string &in, std::string &out) const
{
    int ret;
    //	alloc on the stack
    unsigned char *rsa_out = (unsigned char *)alloca(sizeof(unsigned char)*(rsa_size()));

    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }
 
    ret = RSA_private_decrypt((int)in.size(), (const unsigned char*)in.data(), rsa_out, get_rsa_key(), RSA_NO_PADDING);
    
    
    out = std::string((char*)rsa_out,ret);
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpInverseImpl::invert(const std::array<uint8_t, kMessageSpaceSize> &in) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    
    RSA_private_decrypt((int)in.size(), (const unsigned char*)in.data(), out.data(), get_rsa_key(), RSA_NO_PADDING);
    
    return out;
}

std::array<uint8_t, TdpInverseImpl::kMessageSpaceSize> TdpInverseImpl::invert_mult(const std::array<uint8_t, kMessageSpaceSize> &in, uint32_t order) const
{
    if (order == 0) {
        return in;
    }
    
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    
    
    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long."); /* LCOV_EXCL_LINE */
    }
    
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM *bn_order = BN_new();
    BIGNUM *d_p = BN_new();
    BIGNUM *d_q = BN_new();
    BN_set_word(bn_order, order);
    
    BN_mod_exp(d_p, get_rsa_key()->d, bn_order, p_1_, ctx);
    BN_mod_exp(d_q, get_rsa_key()->d, bn_order, q_1_, ctx);
    
    BIGNUM *x = BN_new();
    BN_bin2bn(in.data(), (unsigned int)in.size(), x);
    
    BIGNUM *y_p = BN_new();
    BIGNUM *y_q = BN_new();
    BIGNUM *h = BN_new();
    BIGNUM *y = BN_new();
    
    BN_mod_exp(y_p,x,d_p, get_rsa_key()->p, ctx);
    BN_mod_exp(y_q,x,d_q, get_rsa_key()->q, ctx);
    
    BN_mod_sub(h, y_p, y_q, get_rsa_key()->p, ctx);
    BN_mod_mul(h, h, get_rsa_key()->iqmp, get_rsa_key()->p, ctx);
    
    BN_mul(y, h, get_rsa_key()->q, ctx);
    BN_add(y, y, y_q);
    
    
    // bn2bin returns a BIG endian array, so be careful ...
    size_t pos = kMessageSpaceSize - BN_num_bytes(y);
    // set the leading bytes to 0
    std::fill(out.begin(), out.begin()+pos, 0);
    BN_bn2bin(y, out.data()+pos);
    
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

void TdpInverseImpl::invert_mult(const std::string &in, std::string &out, uint32_t order) const
{
    std::array<uint8_t, kMessageSpaceSize> in_array;
    
    memcpy(in_array.data(), in.data(), kMessageSpaceSize);
    
    auto out_array = invert_mult(in_array, order);
    
    out = std::string(out_array.begin(), out_array.end());
}


TdpMultPoolImpl::TdpMultPoolImpl(const std::string& sk, const uint8_t size)
: TdpImpl(sk), keys_count_(size-1)
{
    if (size == 0) {
        throw std::invalid_argument("Invalid Multiple TDP pool input size. Pool size should be > 0.");
    }
    
    keys_ = new RSA* [keys_count_];
    
    keys_[0] = RSAPublicKey_dup(get_rsa_key());
    BN_mul_word(keys_[0]->e, RSA_PK);

    for (uint8_t i = 1; i < keys_count_; i++) {
        
        keys_[i] = RSAPublicKey_dup(keys_[i-1]);
        BN_mul_word(keys_[i]->e, RSA_PK);
    }
    
}

TdpMultPoolImpl::TdpMultPoolImpl(const TdpMultPoolImpl& pool_impl)
: TdpImpl(pool_impl), keys_count_(pool_impl.keys_count_)
{
    keys_ = new RSA* [keys_count_];
    
    for (uint8_t i = 0; i < keys_count_; i++) {
        
        keys_[i] = RSAPublicKey_dup(pool_impl.keys_[i]);
    }

}
    
TdpMultPoolImpl::~TdpMultPoolImpl()
{
    for (uint8_t i = 0; i < keys_count_; i++) {
        RSA_free(keys_[i]);
    }
    delete [] keys_;
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpMultPoolImpl::eval(const std::array<uint8_t, kMessageSpaceSize> &in, const uint8_t order) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;

    if (order == 1) {
        // regular eval
        RSA_public_encrypt((int)in.size(), (const unsigned char*)in.data(), out.data(), get_rsa_key(), RSA_NO_PADDING);

    }else if(order <= maximum_order()){
        // get the right RSA context, i.e. the one in keys_[order-1]
        RSA_public_encrypt((int)in.size(), (const unsigned char*)in.data(), out.data(), keys_[order-2], RSA_NO_PADDING);
    }else{
        throw std::invalid_argument("Invalid order for this TDP pool. The input order must be less than the maximum order supported by the pool, and strictly positive.");
    }
    
    return out;
}


void TdpMultPoolImpl::eval(const std::string &in, std::string &out, const uint8_t order) const
{
    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }
    
    std::array<uint8_t, kMessageSpaceSize> a_in, a_out;
    memcpy(a_in.data(), in.data(), kMessageSpaceSize);

    a_out = eval(a_in, order);
    
    out = std::string(a_out.begin(), a_out.end());
    
}

uint8_t TdpMultPoolImpl::maximum_order() const
{
    return keys_count_+1;
}
uint8_t TdpMultPoolImpl::pool_size() const
{
    return keys_count_+1;
}

#else // (SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)
    
// mbedTLS implementation of the trapdoor permutation

TdpImpl::TdpImpl()
{
    mbedtls_rsa_init(&rsa_key_, 0, 0);
}
TdpImpl::TdpImpl(const std::string& pk)
{
    mbedtls_rsa_init(&rsa_key_, 0, 0);
    
    // parse the public key
    if(mbedtls_rsa_parse_public_key( &rsa_key_, reinterpret_cast<const unsigned char*>(pk.c_str()), pk.length()+1 ) != 0)
    {
        throw std::runtime_error("Invalid RSA public key");
    }
    
    if(mbedtls_rsa_check_pubkey(&rsa_key_) != 0)
    {
        throw std::runtime_error("Invalid public key generated during the TDP initialization"); /* LCOV_EXCL_LINE */
    }

}

TdpImpl::TdpImpl(const TdpImpl& tdp)
{
    mbedtls_rsa_init(&rsa_key_, 0, 0); /* LCOV_EXCL_LINE */
    if(mbedtls_rsa_copy(&rsa_key_, &tdp.rsa_key_) != 0)
    {
        throw std::runtime_error("Error when copying an RSA private key"); /* LCOV_EXCL_LINE */
    }
    
    if(mbedtls_rsa_check_pubkey(&rsa_key_) != 0)
    {
        throw std::runtime_error("Invalid public key generated by the TDP copy constructor"); /* LCOV_EXCL_LINE */
    }
}


//inline mbedtls_rsa_context* TdpImpl::get_rsa_key() const
//{
//    return &rsa_key_;
//}
//
//inline void TdpImpl::set_rsa_key(RSA* k)
//{
//    if(k == NULL)
//    {
//        throw std::invalid_argument("Invalid input: k == NULL."); /* LCOV_EXCL_LINE */
//    }
//
//    rsa_key_ = k;
//    RSA_blinding_off(rsa_key_);
//}

inline size_t TdpImpl::rsa_size() const
{
    return rsa_key_.len;
}

TdpImpl::~TdpImpl()
{
    mbedtls_rsa_free(&rsa_key_);
}

std::string TdpImpl::public_key() const
{
    int ret;
    unsigned char buf[5000];
    
    ret = mbedtls_rsa_write_pubkey_pem( const_cast<mbedtls_rsa_context*>(&rsa_key_), buf, sizeof( buf ));

    if (ret != 0) {
        throw std::runtime_error("Error when serializing the RSA public key. Error code: " + std::to_string(ret)); /* LCOV_EXCL_LINE */
    }
    std::string v(reinterpret_cast<const char*>(buf));
    
    return v;
}

void TdpImpl::eval(const std::string &in, std::string &out) const
{
    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }
    
    std::array<uint8_t, kMessageSpaceSize> in_array;
    
    
    memcpy(in_array.data(), in.data(), kMessageSpaceSize);
    
    auto out_array = eval(in_array);
    
    out = std::string(out_array.begin(), out_array.end());
}

//std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::eval(const std::array<uint8_t, kMessageSpaceSize> &in) const
//{
//    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
//
//
//    if(in.size() != rsa_size())
//    {
//        throw std::runtime_error("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long."); /* LCOV_EXCL_LINE */
//    }
//
//    int ret;
//    unsigned char *rsa_in = (unsigned char *)alloca(sizeof(unsigned char)*(rsa_size()+1));
//    unsigned char *rsa_out = (unsigned char *)alloca(sizeof(unsigned char)*(rsa_size()+1));
//
//    memcpy(rsa_in, in.data(), rsa_size());
//    rsa_in[rsa_size()] = '\0';
////        memcpy(rsa_in, in.data(), rsa_size());
////        rsa_out[rsa_size()] = '\0';
//
//    ret = mbedtls_rsa_public(&rsa_key_, rsa_in, rsa_out);
//    if (ret != 0) {
//        throw std::runtime_error("Error when computing the RSA public operation"); /* LCOV_EXCL_LINE */
//    }
//
//
//    memcpy(out.data(), rsa_out, rsa_size());
//
//    return out;
//}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::eval(const std::array<uint8_t, kMessageSpaceSize> &in) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;


    if(in.size() != rsa_size())
    {
        throw std::runtime_error("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long."); /* LCOV_EXCL_LINE */
    }

    int ret;
    mbedtls_mpi x;
    mbedtls_mpi_init(&x);

    // deserialize the integer
    ret = mbedtls_mpi_read_binary( &x, in.data(), in.size() );

    if (ret != 0) {
        throw std::runtime_error("Unable to read the TDP input"); /* LCOV_EXCL_LINE */
    }

    // in case we were given an input larger than the RSA modulus
    ret = mbedtls_mpi_mod_mpi(&x,&x,&rsa_key_.N);
    if (ret != 0) {
        throw std::runtime_error("Error when reducing the RSA input mod N"); /* LCOV_EXCL_LINE */
    }

    // calling mbedtls_rsa_public is not ideal here as it would require us to re-serialize the input

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &rsa_key_->mutex ) != 0 )
        throw std::runtime_error("Unable to lock the RSA context"); /* LCOV_EXCL_LINE */
#endif

    ret = mbedtls_mpi_exp_mod( &x, &x, &rsa_key_.E, &rsa_key_.N, &rsa_key_.RN );


#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &rsa_key_->mutex ) != 0 )
        throw std::runtime_error("Unable to unlock the RSA context"); /* LCOV_EXCL_LINE */
#endif

    if (ret != 0) {
        throw std::runtime_error("Error during the modular exponentiation"); /* LCOV_EXCL_LINE */
    }

    mbedtls_mpi_write_binary(&x, out.data(), out.size());

    return out;
}


std::string TdpImpl::sample() const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> tmp = sample_array();
    
    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::sample_array() const
{
    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    std::array<uint8_t, kMessageSpaceSize> out;
    std::fill(out.begin(), out.end(), 0);
    
    int ret = 0;
    
    ret = mbedtls_mpi_fill_random( &x, Tdp::kRSAPrgSize, mbedTLS_rng_wrap, NULL );
    
    if (ret != 0) {
        throw std::runtime_error("Error during random TDP message generation"); /* LCOV_EXCL_LINE */

    }
    
    ret = mbedtls_mpi_mod_mpi(&x, &x, &rsa_key_.N);
    
    if (ret != 0) {
        throw std::runtime_error("Error modulo computation"); /* LCOV_EXCL_LINE */
        
    }

    mbedtls_mpi_write_binary(&x, out.data(), out.size());

    return out;
}

std::string TdpImpl::generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> tmp = generate_array(prg, seed);
    
    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    std::array<uint8_t, Tdp::kRSAPrgSize> rnd = prg.prf(seed);
    
    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    std::array<uint8_t, kMessageSpaceSize> out;
    std::fill(out.begin(), out.end(), 0);
    
    int ret = 0;
    
    ret = mbedtls_mpi_read_binary( &x, rnd.data(), rnd.size() );
    
    if (ret != 0) {
        throw std::runtime_error("Unable to read the randomness input"); /* LCOV_EXCL_LINE */
    }

    // take the randomness mod N
    // it is ok to do that as we took randomness large enough
    // so that the bias of the obtained x is negligible
    ret = mbedtls_mpi_mod_mpi(&x,&x,&rsa_key_.N);
    if (ret != 0) {
        throw std::runtime_error("Error when reducing the RSA input mod N"); /* LCOV_EXCL_LINE */
    }

    mbedtls_mpi_write_binary(&x, out.data(), out.size());
    
    return out;
}

std::string TdpImpl::generate(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> tmp = generate_array(std::move(key), seed);
    
    return std::string(tmp.begin(), tmp.end());
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::generate_array(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    Prf<Tdp::kRSAPrgSize> prg(std::move(key));
    
    return generate_array(prg, seed);
}

TdpInverseImpl::TdpInverseImpl()
{
    int ret;
    
    // initialize the key
    mbedtls_rsa_init( &rsa_key_, 0, 0 );
    mbedtls_mpi_init(&phi_);
    mbedtls_mpi_init(&p_1_);
    mbedtls_mpi_init(&q_1_);

    // generate a new random key
    ret = mbedtls_rsa_gen_key(&rsa_key_, mbedTLS_rng_wrap, NULL, RSA_MODULUS_SIZE, RSA_PK);

    
    if (ret != 0) {
        throw std::runtime_error("Unable to inialize a new TDP private key. Error code: " + std::to_string(ret)); /* LCOV_EXCL_LINE */
    }
    
    if(mbedtls_rsa_check_pubkey(&rsa_key_) != 0)
    {
        throw std::runtime_error("Invalid private key generated during the Inverse TDP initialization"); /* LCOV_EXCL_LINE */
    }

    if(mbedtls_mpi_sub_int(&p_1_, &rsa_key_.P, 1) != 0)
    {
        throw std::runtime_error("Failed MPI substraction");
    }
    if(mbedtls_mpi_sub_int(&q_1_, &rsa_key_.Q, 1) != 0)
    {
        throw std::runtime_error("Failed MPI substraction");
    }
    if(mbedtls_mpi_mul_mpi(&phi_, &p_1_, &q_1_) != 0)
    {
        throw std::runtime_error("Failed MPI multiplication");
    }
}

TdpInverseImpl::TdpInverseImpl(const std::string& sk)
{
    int ret;
    
    // initialize the key
    mbedtls_rsa_init( &rsa_key_, 0, 0 );
    mbedtls_mpi_init(&phi_);
    mbedtls_mpi_init(&p_1_);
    mbedtls_mpi_init(&q_1_);

    // do not forget the '\0' character
    ret = mbedtls_rsa_parse_key( &rsa_key_, reinterpret_cast<const unsigned char*>(sk.c_str()), sk.length()+1, 0, 0);
    
    if (ret != 0) {
        throw std::runtime_error("Error when reading the RSA private key. Error code: " + std::to_string(ret)); /* LCOV_EXCL_LINE */
    }
    
    if(mbedtls_rsa_check_pubkey(&rsa_key_) != 0)
    {
        throw std::runtime_error("Invalid private key generated during the Inverse TDP initialization from existing secret key"); /* LCOV_EXCL_LINE */
    }

    if(mbedtls_mpi_sub_int(&p_1_, &rsa_key_.P, 1) != 0)
    {
        throw std::runtime_error("Failed MPI substraction");
    }
    if(mbedtls_mpi_sub_int(&q_1_, &rsa_key_.Q, 1) != 0)
    {
        throw std::runtime_error("Failed MPI substraction");
    }
    if(mbedtls_mpi_mul_mpi(&phi_, &p_1_, &q_1_) != 0)
    {
        throw std::runtime_error("Failed MPI multiplication");
    }
}

TdpInverseImpl::TdpInverseImpl(const TdpInverseImpl& tdp)
{
    mbedtls_rsa_init(&rsa_key_, 0, 0); /* LCOV_EXCL_LINE */
    mbedtls_mpi_init(&phi_);
    mbedtls_mpi_init(&p_1_);
    mbedtls_mpi_init(&q_1_);

    if(mbedtls_rsa_copy(&rsa_key_, &tdp.rsa_key_) != 0) /* LCOV_EXCL_LINE */
    {
        throw std::runtime_error("Error when copying an RSA private key");
    }
    
    if(mbedtls_rsa_check_pubkey(&rsa_key_) != 0)
    {
        throw std::runtime_error("Invalid private key generated by the Inverse TDP copy constructor"); /* LCOV_EXCL_LINE */
    }

    if(mbedtls_mpi_sub_int(&p_1_, &rsa_key_.P, 1) != 0)
    {
        throw std::runtime_error("Failed MPI substraction");
    }
    if(mbedtls_mpi_sub_int(&q_1_, &rsa_key_.Q, 1) != 0)
    {
        throw std::runtime_error("Failed MPI substraction");
    }
    if(mbedtls_mpi_mul_mpi(&phi_, &p_1_, &q_1_) != 0)
    {
        throw std::runtime_error("Failed MPI multiplication");
    }
    
}

TdpInverseImpl::~TdpInverseImpl()
{
    mbedtls_mpi_free(&p_1_);
    mbedtls_mpi_free(&q_1_);
    mbedtls_mpi_free(&phi_);
}

std::string TdpInverseImpl::private_key() const
{
    int ret;
    unsigned char buf[5000];
    
    ret = mbedtls_rsa_write_key_pem( &rsa_key_, buf, sizeof( buf ));
    
    if (ret != 0) {
        throw std::runtime_error("Error when serializing the RSA private key. Error code: " + std::to_string(ret)); /* LCOV_EXCL_LINE */
    }
    std::string v(reinterpret_cast<const char*>(buf));
    
    return v;
}


void TdpInverseImpl::invert(const std::string &in, std::string &out) const
{
    int ret;
    //    alloc on the stack
    unsigned char *rsa_out = (unsigned char *)alloca(sizeof(unsigned char)*(rsa_size()));
    
    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }
    
    ret = mbedtls_rsa_private(&rsa_key_, mbedTLS_rng_wrap, NULL, reinterpret_cast<const unsigned char*>(in.data()), rsa_out);
    
    if (ret != 0) {
        throw std::invalid_argument("Error during the RSA private key operation. Code: " + std::to_string(ret));

    }
    
    out = std::string((char*)rsa_out,rsa_size());
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpInverseImpl::invert(const std::array<uint8_t, kMessageSpaceSize> &in) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    
    int ret = mbedtls_rsa_private(&rsa_key_, mbedTLS_rng_wrap, NULL, in.data(), out.data());
    
    if (ret != 0) {
        throw std::invalid_argument("Error during the RSA private key operation. Code: " + std::to_string(ret));
        
    }

    return out;
}

// returns X = A^E mod N, even when N is even
// CAUTION!!!!: be aware that a timing attack would reveal E,
// contrary to mbedtls_mpi_exp_mod
static int insecure_mod_exp(mbedtls_mpi* X, const mbedtls_mpi* A, const uint64_t E,  const mbedtls_mpi* N)
{
    int ret = 0;
    mbedtls_mpi_lset(X, 1);
    mbedtls_mpi base;
    mbedtls_mpi_init(&base);
    
    uint64_t exp = E;
    
    mbedtls_mpi_copy(&base, A);
    mbedtls_mpi_mod_mpi(&base, &base, N);
    
    while (exp > 0) {
        if (exp%2 == 1) {
            mbedtls_mpi_mul_mpi(X, X, &base);
            mbedtls_mpi_mod_mpi(X, X, N);
        }
        exp >>= 1;
        mbedtls_mpi_mul_mpi(&base, &base, &base);
        mbedtls_mpi_mod_mpi(&base, &base, N);
    }
    
    mbedtls_mpi_free(&base);
    return ret;
}

std::array<uint8_t, TdpInverseImpl::kMessageSpaceSize> TdpInverseImpl::invert_mult(const std::array<uint8_t, kMessageSpaceSize> &in, uint32_t order) const
{
    // we have to reimplement everything by hand here
    // for the moment, this is not a very secure implementation:
    // it does not use blinding when available
#warning Potentially insecure RSA implementation
    if (order == 0) {
        return in;
    }
    
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    
    
    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long."); /* LCOV_EXCL_LINE */
    }
    
    int ret;
    mbedtls_mpi x, mpi_order, d_p, d_q;
    mbedtls_mpi y_p, y_q;
    mbedtls_mpi h, y;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&mpi_order);
    mbedtls_mpi_init(&d_p);
    mbedtls_mpi_init(&d_q);
    mbedtls_mpi_init(&y_p);
    mbedtls_mpi_init(&y_q);
    mbedtls_mpi_init(&h);
    mbedtls_mpi_init(&y);
    
    // deserialize the integer
    ret = mbedtls_mpi_read_binary( &x, in.data(), in.size() );
    
    // in case we were given an input larger than the RSA modulus
    //    ret = mbedtls_mpi_mod_mpi(&x,&x,&rsa_key_.N);
    //    if (ret != 0) {
    //        throw std::runtime_error("Error when reducing the RSA input mod N"); /* LCOV_EXCL_LINE */
    //    }
    
    if (ret != 0) {
        throw std::runtime_error("Unable to read the TDP input"); /* LCOV_EXCL_LINE */
    }
    
    // load the order
    mbedtls_mpi_lset(&mpi_order, order);
    
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( &rsa_key_->mutex ) != 0 )
        throw std::runtime_error("Unable to lock the RSA context"); /* LCOV_EXCL_LINE */
#endif
    
    // there is an issue with the following code:
    // mbedTLS mpi library does not allow for a modular exponentiation
    // where the module is even. And we were actually relying on that
    // to compute the adjusted exponent
    //    mbedtls_mpi_exp_mod(&d_p, &rsa_key_.DP, &mpi_order, &p_1_, NULL);
    //    mbedtls_mpi_exp_mod(&d_q, &rsa_key_.DQ, &mpi_order, &q_1_, NULL);

    // instead, we implemented the insecure_mod_exp function
    // it is definitely less secure than mbedtls_mpi_exp_mod
    // but it works with even modulis
    insecure_mod_exp(&d_p, &rsa_key_.DP, order, &p_1_);
    insecure_mod_exp(&d_q, &rsa_key_.DQ, order, &q_1_);
    
    mbedtls_mpi_exp_mod(&y_p, &x, &d_p,&rsa_key_.P, &rsa_key_.RP);
    mbedtls_mpi_exp_mod(&y_q, &x, &d_q,&rsa_key_.Q, &rsa_key_.RQ);
    
    /*
     * Y = (YP - YQ) * (Q^-1 mod P) mod P
     */
    
    mbedtls_mpi_sub_mpi( &y, &y_p, &y_q );
    mbedtls_mpi_mul_mpi( &y_p, &y, &rsa_key_.QP );
    mbedtls_mpi_mod_mpi( &y, &y_p, &rsa_key_.P );
    
    /*
     * Y = YQ + Y * Q
     */
    mbedtls_mpi_mul_mpi( &y_p, &y, &rsa_key_.Q);
    mbedtls_mpi_add_mpi(&y, &y_q, &y_p);
    
    ////    BN_mod_sub(h, y_p, y_q, get_rsa_key()->p, ctx);
    //    mbedtls_mpi_sub_mpi(&h, &y_p, &y_q);
    //    mbedtls_mpi_mod_mpi(&h, &h, &rsa_key_.P);
    //
    ////    BN_mod_mul(h, h, get_rsa_key()->iqmp, get_rsa_key()->p, ctx);
    //    mbedtls_mpi_mul_mpi(&h, &h, &rsa_key_.QP);
    //    mbedtls_mpi_mod_mpi(&h, &h, &rsa_key_.P);
    //
    //
    //    mbedtls_mpi_mul_mpi(&y, &h, &rsa_key_.Q);
    //    mbedtls_mpi_add_mpi(&y, &y, &y_q);
    
    
    // calling mbedtls_rsa_public is not ideal here as it would require us to re-serialize the input
    
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &rsa_key_->mutex ) != 0 )
        throw std::runtime_error("Unable to unlock the RSA context"); /* LCOV_EXCL_LINE */
#endif
    
    if (ret != 0) {
        throw std::runtime_error("Error during the modular exponentiation"); /* LCOV_EXCL_LINE */
    }
    
    mbedtls_mpi_write_binary(&y, out.data(), out.size());
    
    return out;
}

void TdpInverseImpl::invert_mult(const std::string &in, std::string &out, uint32_t order) const
{
    std::array<uint8_t, kMessageSpaceSize> in_array;
    
    memcpy(in_array.data(), in.data(), kMessageSpaceSize);
    
    auto out_array = invert_mult(in_array, order);
    
    out = std::string(out_array.begin(), out_array.end());
}


TdpMultPoolImpl::TdpMultPoolImpl(const std::string& sk, const uint8_t size)
: TdpImpl(sk), keys_count_(size-1)
{
    if (size == 0) {
        throw std::invalid_argument("Invalid Multiple TDP pool input size. Pool size should be > 0.");
    }
    
    keys_ = new mbedtls_rsa_context[keys_count_];
    
    mbedtls_rsa_init(keys_,0,0);
    mbedtls_rsa_copy(keys_, &rsa_key_);

    mbedtls_mpi_mul_int(&keys_[0].E, &keys_[0].E, RSA_PK);
    
    if(mbedtls_rsa_check_pubkey(&keys_[0]) != 0)
    {
        throw std::runtime_error("Invalid public key generated during the TDP pool initialization");
    }

    for (uint8_t i = 1; i < keys_count_; i++) {
        mbedtls_rsa_init(&keys_[i],0,0);
        mbedtls_rsa_copy(&keys_[i], &keys_[i-1]);
        
        mbedtls_mpi_mul_int(&keys_[i].E, &keys_[i-1].E, RSA_PK);
        
        if(mbedtls_rsa_check_pubkey(&keys_[i]) != 0)
        {
            throw std::runtime_error("Invalid public key generated during the TDP pool initialization");
        }
    }
    
}

TdpMultPoolImpl::TdpMultPoolImpl(const TdpMultPoolImpl& pool_impl)
: TdpImpl(pool_impl), keys_count_(pool_impl.keys_count_)
{
    keys_ = new mbedtls_rsa_context[keys_count_];

    for (uint8_t i = 0; i < keys_count_; i++) {
        mbedtls_rsa_init(&keys_[i],0,0);

        mbedtls_rsa_copy(&keys_[i], &pool_impl.keys_[i]);
        
        
        if(mbedtls_rsa_check_pubkey(&keys_[i]) != 0)
        {
            throw std::runtime_error("Invalid public key generated by the TDP pool copy constructor");
        }
    }
}

TdpMultPoolImpl::~TdpMultPoolImpl()
{
    for (uint8_t i = 0; i < keys_count_; i++) {
        mbedtls_rsa_free(&keys_[i]);
    }
    delete [] keys_;
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpMultPoolImpl::eval(const std::array<uint8_t, kMessageSpaceSize> &in, const uint8_t order) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    mbedtls_rsa_context* key;
    if (order == 1) {
        // regular eval
        key = &rsa_key_;
        
    }else if(order <= maximum_order()){
        // get the right RSA context, i.e. the one in keys_[order-1]
        key = &keys_[order-2];
    }else{
        throw std::invalid_argument("Invalid order for this TDP pool. The input order must be less than the maximum order supported by the pool, and strictly positive.");
    }
    
    
    
    if(in.size() != rsa_size())
    {
        throw std::runtime_error("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long."); /* LCOV_EXCL_LINE */
    }
    
    int ret;
    mbedtls_mpi x;
    mbedtls_mpi_init(&x);
    
    // deserialize the integer
    ret = mbedtls_mpi_read_binary( &x, in.data(), in.size() );
    
    if (ret != 0) {
        throw std::runtime_error("Unable to read the TDP input"); /* LCOV_EXCL_LINE */
    }
    
    // in case we were given an input larger than the RSA modulus
    //    ret = mbedtls_mpi_mod_mpi(&x,&x,&key->N);
    //    if (ret != 0) {
    //        throw std::runtime_error("Error when reducing the RSA input mod N"); /* LCOV_EXCL_LINE */
    //    }
    
    // calling mbedtls_rsa_public is not ideal here as it would require us to re-serialize the input
    
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_lock( key->mutex ) != 0 )
        throw std::runtime_error("Unable to lock the RSA context"); /* LCOV_EXCL_LINE */
#endif
    
    ret = mbedtls_mpi_exp_mod( &x, &x, &key->E, &key->N, &key->RN );
    
    
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( key->mutex ) != 0 )
        throw std::runtime_error("Unable to unlock the RSA context"); /* LCOV_EXCL_LINE */
#endif
    
    if (ret != 0) {
        throw std::runtime_error("Error during the modular exponentiation"); /* LCOV_EXCL_LINE */
    }
    
    mbedtls_mpi_write_binary(&x, out.data(), out.size());
    
    return out;
}


void TdpMultPoolImpl::eval(const std::string &in, std::string &out, const uint8_t order) const
{
    if(in.size() != rsa_size())
    {
        throw std::invalid_argument("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }
    
    std::array<uint8_t, kMessageSpaceSize> a_in, a_out;
    memcpy(a_in.data(), in.data(), kMessageSpaceSize);
    
    a_out = eval(a_in, order);
    
    out = std::string(a_out.begin(), a_out.end());
    
}

uint8_t TdpMultPoolImpl::maximum_order() const
{
    return keys_count_+1;
}
uint8_t TdpMultPoolImpl::pool_size() const
{
    return keys_count_+1;
}
    
#endif
Tdp::Tdp(const std::string& sk) : tdp_imp_(new TdpImpl(sk))
{
}

Tdp::Tdp(const Tdp& t) : tdp_imp_(new TdpImpl(*t.tdp_imp_))
{
        
}

Tdp::~Tdp()
{
    delete tdp_imp_;
    tdp_imp_ = NULL;
}

Tdp& Tdp::operator=(const Tdp& t)
{
    if (tdp_imp_ != t.tdp_imp_) {
        delete tdp_imp_;
        tdp_imp_ = new TdpImpl(*t.tdp_imp_);
    }
    
    return *this;
}
    
std::string Tdp::public_key() const
{
    return tdp_imp_->public_key();
}
    
std::string Tdp::sample() const
{
    return tdp_imp_->sample();
}

std::array<uint8_t, Tdp::kMessageSize> Tdp::sample_array() const
{
    return tdp_imp_->sample_array();
}

std::string Tdp::generate(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    return tdp_imp_->generate(std::move(key), seed);
}
std::array<uint8_t, Tdp::kMessageSize> Tdp::generate_array(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    return tdp_imp_->generate_array(std::move(key), seed);
}

std::string Tdp::generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    return tdp_imp_->generate(prg, seed);
}
std::array<uint8_t, Tdp::kMessageSize> Tdp::generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    return tdp_imp_->generate_array(prg, seed);
}

void Tdp::eval(const std::string &in, std::string &out) const
{
    tdp_imp_->eval(in, out);
}

std::string Tdp::eval(const std::string &in) const
{
    std::string out;
    tdp_imp_->eval(in, out);
    
    return out;
}

std::array<uint8_t, Tdp::kMessageSize> Tdp::eval(const std::array<uint8_t, kMessageSize> &in) const
{
    return tdp_imp_->eval(in);
}

TdpInverse::TdpInverse() : tdp_inv_imp_(new TdpInverseImpl())
{
}

TdpInverse::TdpInverse(const std::string& sk) : tdp_inv_imp_(new TdpInverseImpl(sk))
{
}

TdpInverse::TdpInverse(const TdpInverse& tdp) : tdp_inv_imp_(new TdpInverseImpl(*tdp.tdp_inv_imp_))
{
}

TdpInverse& TdpInverse::operator=(const TdpInverse& t)
{
    if (tdp_inv_imp_ != t.tdp_inv_imp_) {
        delete tdp_inv_imp_;
        tdp_inv_imp_ = new TdpInverseImpl(*t.tdp_inv_imp_);
    }
    return *this;
}

TdpInverse::~TdpInverse()
{
    delete tdp_inv_imp_;
    tdp_inv_imp_ = NULL;
}

std::string TdpInverse::public_key() const
{
    return tdp_inv_imp_->public_key();
}

std::string TdpInverse::private_key() const
{
    return tdp_inv_imp_->private_key();
}

std::string TdpInverse::sample() const
{
    return tdp_inv_imp_->sample();
}

std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::sample_array() const
{
    return tdp_inv_imp_->sample_array();
}

std::string TdpInverse::generate(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    return tdp_inv_imp_->generate(std::move(key), seed);
}
std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::generate_array(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    return tdp_inv_imp_->generate_array(std::move(key), seed);
}

std::string TdpInverse::generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    return tdp_inv_imp_->generate(prg, seed);
}
std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    return tdp_inv_imp_->generate_array(prg, seed);
}

void TdpInverse::eval(const std::string &in, std::string &out) const
{
    tdp_inv_imp_->eval(in, out);
}

std::string TdpInverse::eval(const std::string &in) const
{
    std::string out;
    tdp_inv_imp_->eval(in, out);
    
    return out;
}

std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::eval(const std::array<uint8_t, kMessageSize> &in) const
{
    return tdp_inv_imp_->eval(in);
}

void TdpInverse::invert(const std::string &in, std::string &out) const
{
    tdp_inv_imp_->invert(in, out);
}

std::string TdpInverse::invert(const std::string &in) const
{
    std::string out;
    tdp_inv_imp_->invert(in, out);
    
    return out;
}

std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::invert(const std::array<uint8_t, kMessageSize> &in) const
{
    return tdp_inv_imp_->invert(in);
}
  
void TdpInverse::invert_mult(const std::string &in, std::string &out, uint32_t order) const
{
    tdp_inv_imp_->invert_mult(in, out, order);
}

std::string TdpInverse::invert_mult(const std::string &in, uint32_t order) const
{
    std::string out;
    tdp_inv_imp_->invert_mult(in, out, order);
    
    return out;
}

std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::invert_mult(const std::array<uint8_t, kMessageSize> &in, uint32_t order) const
{
    return tdp_inv_imp_->invert_mult(in, order);
}

TdpMultPool::TdpMultPool(const std::string& pk, const uint8_t size) : tdp_pool_imp_(new TdpMultPoolImpl(pk, size))
{
}
    
TdpMultPool::TdpMultPool(const TdpMultPool& pool) :
    tdp_pool_imp_(new TdpMultPoolImpl(*pool.tdp_pool_imp_))
{
        
}

TdpMultPool& TdpMultPool::operator=(const TdpMultPool& t)
{
    if (tdp_pool_imp_ != t.tdp_pool_imp_) {
        delete tdp_pool_imp_;
        tdp_pool_imp_ = new TdpMultPoolImpl(*t.tdp_pool_imp_);
    }
    return *this;
}


TdpMultPool::~TdpMultPool()
{
    delete tdp_pool_imp_;
    tdp_pool_imp_ = NULL;
}

std::string TdpMultPool::public_key() const
{
    return tdp_pool_imp_->public_key();
}

std::string TdpMultPool::sample() const
{
    return tdp_pool_imp_->sample();
}

std::array<uint8_t, TdpMultPool::kMessageSize> TdpMultPool::sample_array() const
{
    return tdp_pool_imp_->sample_array();
}

std::string TdpMultPool::generate(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    return tdp_pool_imp_->generate(std::move(key), seed);
}
std::array<uint8_t, TdpMultPool::kMessageSize> TdpMultPool::generate_array(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const
{
    return tdp_pool_imp_->generate_array(std::move(key), seed);
}

std::string TdpMultPool::generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    return tdp_pool_imp_->generate(prg, seed);
}
std::array<uint8_t, TdpMultPool::kMessageSize> TdpMultPool::generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const
{
    return tdp_pool_imp_->generate_array(prg, seed);
}

void TdpMultPool::eval(const std::string &in, std::string &out, uint8_t order) const
{
    tdp_pool_imp_->eval(in, out, order);
}

std::string TdpMultPool::eval(const std::string &in, uint8_t order) const
{
    std::string out;
    tdp_pool_imp_->eval(in, out, order);
    
    return out;
}

std::array<uint8_t, Tdp::kMessageSize> TdpMultPool::eval(const std::array<uint8_t, kMessageSize> &in, uint8_t order) const
{
    return tdp_pool_imp_->eval(in, order);
}
    
void TdpMultPool::eval(const std::string &in, std::string &out) const
{
    static_cast<TdpImpl*>(tdp_pool_imp_)->eval(in, out);
}

std::string TdpMultPool::eval(const std::string &in) const
{
    std::string out;
    static_cast<TdpImpl*>(tdp_pool_imp_)->eval(in, out);
    
    return out;
}

std::array<uint8_t, Tdp::kMessageSize> TdpMultPool::eval(const std::array<uint8_t, kMessageSize> &in) const
{
    return static_cast<TdpImpl*>(tdp_pool_imp_)->eval(in);
}

uint8_t TdpMultPool::maximum_order() const
{
    return tdp_pool_imp_->maximum_order();
}
    
uint8_t TdpMultPool::pool_size() const
{
    return tdp_pool_imp_->pool_size();
}

}
}
