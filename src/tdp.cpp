
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

#include "random.hpp"

#include <cstring>
#include <exception>
#include <iostream>
#include <iomanip>

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace sse
{

namespace crypto
{
	
    
static_assert(Tdp::kMessageSize == TdpInverse::kMessageSize, "Constants kMessageSize of Tdp and TdpInverse do not match");

#define RSA_MODULUS_SIZE TdpInverse::kMessageSize/8

class TdpImpl
{
public:
    static constexpr uint kMessageSpaceSize = Tdp::kMessageSize;
    
    TdpImpl();
    TdpImpl(const std::string& sk);
    
    ~TdpImpl();
    
    
    RSA* get_rsa_key() const;
    void set_rsa_key(RSA* k);
    uint rsa_size() const;
    
    std::string public_key() const;
    void eval(const std::string &in, std::string &out) const;
    std::array<uint8_t, kMessageSpaceSize> eval(const std::array<uint8_t, kMessageSpaceSize> &in) const;

    std::string sample() const;
    std::array<uint8_t, kMessageSpaceSize> sample_array() const;
private:
    RSA *rsa_key_;
    
};

class TdpInverseImpl : public TdpImpl
{
public:
    TdpInverseImpl();
    TdpInverseImpl(const std::string& sk);
    
    std::string private_key() const;
    void invert(const std::string &in, std::string &out) const;
    std::array<uint8_t, kMessageSpaceSize> invert(const std::array<uint8_t, kMessageSpaceSize> &in) const;
};

TdpImpl::TdpImpl() : rsa_key_(NULL)
{
    
}
TdpImpl::TdpImpl(const std::string& pk) : rsa_key_(NULL)
{
    // create a BIO from the std::string
    BIO *mem;
    mem = BIO_new_mem_buf(((void*)pk.data()), (int)pk.length());
    
    // read the key from the BIO
    rsa_key_ = PEM_read_bio_RSAPublicKey(mem,NULL,NULL,NULL);

    if(rsa_key_ == NULL)
    {
        throw std::runtime_error("Error when initializing the RSA key from public key.");
    }
    
    // close and destroy the BIO
    BIO_set_close(mem, BIO_NOCLOSE); // So BIO_free() leaves BUF_MEM alone
    BIO_free(mem);
}
    
inline RSA* TdpImpl::get_rsa_key() const
{
    return rsa_key_;
}
    
inline void TdpImpl::set_rsa_key(RSA* k)
{
    if(k == NULL)
    {
        throw std::runtime_error("Invalid input: k == NULL.");
    }

    rsa_key_ = k;
}

inline uint TdpImpl::rsa_size() const
{
    return ((uint) RSA_size(get_rsa_key()));
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
    ret = PEM_write_bio_RSAPublicKey(bio, rsa_key_);

    if(ret != 1)
    {
        throw std::runtime_error("Error when serializing the RSA public key.");
    }
    

    // put the buffer in a std::string
    size_t len = BIO_ctrl_pending(bio);
    void *buf = malloc(len);
    
    int read_bytes = BIO_read(bio, buf, (int)len);
    
    if(read_bytes == 0)
    {
        throw std::runtime_error("Error when reading BIO.");
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
        throw std::runtime_error("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }

    unsigned char rsa_out[RSA_size(rsa_key_)];
    
    RSA_public_encrypt((int)in.size(), (unsigned char*)in.data(), rsa_out, rsa_key_, RSA_NO_PADDING);
    
    out = std::string((char*)rsa_out,RSA_size(rsa_key_));
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::eval(const std::array<uint8_t, kMessageSpaceSize> &in) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;

    RSA_public_encrypt((int)in.size(), (unsigned char*)in.data(), out.data(), rsa_key_, RSA_NO_PADDING);
    
    return out;
}

std::string TdpImpl::sample() const
{
    // I don't really trust OpenSSL PRNG, but this is the simplest way
    int ret;
    BIGNUM *rnd;
    
    rnd = BN_new();
    
    ret = BN_rand_range(rnd, rsa_key_->n);
    if(ret != 1)
    {
        throw std::runtime_error("Invalid random number generation.");
    }
    
    unsigned char *buf = new unsigned char[BN_num_bytes(rnd)];
    BN_bn2bin(rnd, buf);
    
    std::string v(reinterpret_cast<const char*>(buf), BN_num_bytes(rnd));
    
    BN_free(rnd);
    delete [] buf;
    
    return v;
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpImpl::sample_array() const
{
    // I don't really trust OpenSSL PRNG, but this is the simplest way
    int ret;
    BIGNUM *rnd;
    std::array<uint8_t, kMessageSpaceSize> out;
    
    rnd = BN_new();
    
    ret = BN_rand_range(rnd, rsa_key_->n);
    if(ret != 1)
    {
        throw std::runtime_error("Invalid random number generation.");
    }
    
    BN_bn2bin(rnd, out.data());
    BN_free(rnd);
    
    return out;
}


TdpInverseImpl::TdpInverseImpl()
{
    int ret;
    
    // initialize the key
    set_rsa_key(RSA_new());
    
    // generate a new random key
    
    unsigned long e = RSA_3;
    BIGNUM *bne = NULL;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if(ret != 1)
    {
        throw std::runtime_error("Invalid BIGNUM initialization.");
    }
    
    ret = RSA_generate_key_ex(get_rsa_key(), RSA_MODULUS_SIZE, bne, NULL);
    if(ret != 1)
    {
        throw std::runtime_error("Invalid RSA key generation.");
    }
    
    BN_free(bne);
}

TdpInverseImpl::TdpInverseImpl(const std::string& sk)
{
    // create a BIO from the std::string
    BIO *mem;
    mem = BIO_new_mem_buf(((void*)sk.data()), (int)sk.length());

    EVP_PKEY* evpkey;
    evpkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);

    if(evpkey == NULL)
    {
        throw std::runtime_error("Error when reading the RSA private key.");
    }

    // read the key from the BIO
    set_rsa_key( EVP_PKEY_get1_RSA(evpkey));

    
    // close and destroy the BIO
    BIO_set_close(mem, BIO_NOCLOSE); // So BIO_free() leaves BUF_MEM alone
    BIO_free(mem);
}

std::string TdpInverseImpl::private_key() const
{
    int ret;
    
    // create an EVP encapsulation
    EVP_PKEY* evpkey = EVP_PKEY_new();
    ret = EVP_PKEY_set1_RSA(evpkey, get_rsa_key());
    if(ret != 1)
    {
        throw std::runtime_error("Invalid EVP initialization.");
    }
    
    // initialize a buffer
    BIO *bio = BIO_new(BIO_s_mem());
    
    // write the key to the buffer
    ret = PEM_write_bio_PKCS8PrivateKey(bio, evpkey, NULL, NULL, 0, NULL, NULL);
    if(ret != 1)
    {
        throw std::runtime_error("Failure when writing private KEY.");
    }
    
    // put the buffer in a std::string
    size_t len = BIO_ctrl_pending(bio);
    void *buf = malloc(len);
    
    int read_bytes = BIO_read(bio, buf, (int)len);
    if(read_bytes == 0)
    {
        throw std::runtime_error("Error when reading BIO.");
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
    unsigned char rsa_out[rsa_size()];

    if(in.size() != rsa_size())
    {
        throw std::runtime_error("Invalid TDP input size. Input size should be kMessageSpaceSize bytes long.");
    }
 
    ret = RSA_private_decrypt((int)in.size(), (unsigned char*)in.data(), rsa_out, get_rsa_key(), RSA_NO_PADDING);
    
    
    out = std::string((char*)rsa_out,ret);
}

std::array<uint8_t, TdpImpl::kMessageSpaceSize> TdpInverseImpl::invert(const std::array<uint8_t, kMessageSpaceSize> &in) const
{
    std::array<uint8_t, TdpImpl::kMessageSpaceSize> out;
    
    RSA_private_decrypt((int)in.size(), (unsigned char*)in.data(), out.data(), get_rsa_key(), RSA_NO_PADDING);
    
    return out;
}


Tdp::Tdp(const std::string& sk) : tdp_imp_(new TdpImpl(sk))
{
}

Tdp::~Tdp()
{
    delete tdp_imp_;
    tdp_imp_ = NULL;
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
    
   
}
}