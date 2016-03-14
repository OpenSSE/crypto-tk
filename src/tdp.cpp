//
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
#include <cassert>
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
	
#define RSA_MODULUS_SIZE 3072
#define PASSPHRASE "sophos"
    
class TdpInverse::TdpInverseImpl
{
public:
    TdpInverseImpl();
    TdpInverseImpl(const std::string& sk);
    
    ~TdpInverseImpl();
    
    std::string private_key() const;
private:
    RSA *rsa_key;

};

TdpInverse::TdpInverseImpl::TdpInverseImpl() : rsa_key(NULL)
{
    int ret;
    
    // initialize the key
    rsa_key = RSA_new();
    
    // generate a new random key
    
    unsigned long e = RSA_3;
    BIGNUM *bne = NULL;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    assert(ret == 1);
    
    ret = RSA_generate_key_ex(rsa_key, RSA_MODULUS_SIZE, bne, NULL);
    assert(ret == 1);
    
    BN_free(bne);
}

TdpInverse::TdpInverseImpl::TdpInverseImpl(const std::string& sk) : rsa_key(NULL)
{
    // create a BIO from the std::string
    BIO *mem;
    mem = BIO_new_mem_buf(((void*)sk.data()), (int)sk.length());

    EVP_PKEY* evpkey;
    evpkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    assert(evpkey != NULL);
    
    // read the key from the BIO
    rsa_key = EVP_PKEY_get1_RSA(evpkey);
    assert(rsa_key != NULL);

    
    // close and destroy the BIO
    BIO_set_close(mem, BIO_NOCLOSE); // So BIO_free() leaves BUF_MEM alone
    BIO_free(mem);
}
    
    
TdpInverse::TdpInverseImpl::~TdpInverseImpl()
{
    RSA_free(rsa_key);
}

std::string TdpInverse::TdpInverseImpl::private_key() const
{
    int ret;
    
    // create an EVP encapsulation
    EVP_PKEY* evpkey = EVP_PKEY_new();
    ret = EVP_PKEY_set1_RSA(evpkey, rsa_key);
    assert(ret == 1);

    // initialize a buffer
    BIO *bio = BIO_new(BIO_s_mem());

    // write the key to the buffer
    ret = PEM_write_bio_PKCS8PrivateKey(bio, evpkey, NULL, NULL, 0, NULL, NULL);
    assert(ret == 1);
    
    // put the buffer in a std::string
    size_t len = BIO_ctrl_pending(bio);
    void *buf = malloc(len);
    
    int read_bytes = BIO_read(bio, buf, (int)len);
    assert(read_bytes >= 0);
    
    return std::string(reinterpret_cast<const char*>(buf), len);
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

std::string TdpInverse::private_key() const
{
    return tdp_inv_imp_->private_key();
}

}
}