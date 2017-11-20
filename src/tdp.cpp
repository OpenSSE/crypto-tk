
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

#include "tdp_impl/tdp_impl.hpp"

#include <cstring>
#include <exception>
#include <iostream>
#include <iomanip>

#define SSE_CRYPTO_TDP_IMPL_MBEDTLS 1

#ifdef WITH_OPENSSL
    #define SSE_CRYPTO_TDP_IMPL_OPENSSL 2
#endif

/*
 * The default TDP implementation used mbedTLS
 * To use OpenSSL, uncomment the following line and
 * replace SSE_CRYPTO_TDP_IMPL_MBEDTLS by SSE_CRYPTO_TDP_IMPL_OPENSSL
 * or pass the option -DSSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL
 * to the compiler
 */
//#define SSE_CRYPTO_TDP_IMPL SSE_CRYPTO_TDP_IMPL_MBEDTLS

#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)

#ifndef WITH_OPENSSL
    #error "OpenSSL is not in use."
#endif

#include "tdp_impl/tdp_impl_openssl.hpp"

#else
#include "tdp_impl/tdp_impl_mbedtls.hpp"


#endif


namespace sse
{

namespace crypto
{
	
#if defined(SSE_CRYPTO_TDP_IMPL) && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)
    
    
    typedef TdpImpl_OpenSSL         TdpImpl_Current;
    typedef TdpInverseImpl_OpenSSL  TdpInverseImpl_Current;
    typedef TdpMultPoolImpl_OpenSSL TdpMultPoolImpl_Current;
#else
    
    typedef TdpImpl_mbedTLS         TdpImpl_Current;
    typedef TdpInverseImpl_mbedTLS  TdpInverseImpl_Current;
    typedef TdpMultPoolImpl_mbedTLS TdpMultPoolImpl_Current;
    
#endif

static_assert(Tdp::kMessageSize == TdpInverse::kMessageSize, "Constants kMessageSize of Tdp and TdpInverse do not match");

Tdp::Tdp(const std::string& sk) : tdp_imp_(new TdpImpl_Current(sk))
{
}

Tdp::Tdp(const Tdp& t) : tdp_imp_(new TdpImpl_Current(*dynamic_cast<const TdpImpl_Current*>(t.tdp_imp_)))
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
        tdp_imp_ = new TdpImpl_Current(*dynamic_cast<const TdpImpl_Current*>(t.tdp_imp_));
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

TdpInverse::TdpInverse() : tdp_inv_imp_(new TdpInverseImpl_Current())
{
}

TdpInverse::TdpInverse(const std::string& sk) : tdp_inv_imp_(new TdpInverseImpl_Current(sk))
{
}

TdpInverse::TdpInverse(const TdpInverse& tdp) : tdp_inv_imp_(new TdpInverseImpl_Current(*dynamic_cast<const TdpInverseImpl_Current*>(tdp.tdp_inv_imp_)))
{
}

TdpInverse& TdpInverse::operator=(const TdpInverse& t)
{
    if (tdp_inv_imp_ != t.tdp_inv_imp_) {
        delete tdp_inv_imp_;
        tdp_inv_imp_ = new TdpInverseImpl_Current(*dynamic_cast<const TdpInverseImpl_Current*>(t.tdp_inv_imp_));
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

TdpMultPool::TdpMultPool(const std::string& pk, const uint8_t size) : tdp_pool_imp_(new TdpMultPoolImpl_Current(pk, size))
{
}
    
TdpMultPool::TdpMultPool(const TdpMultPool& pool) :
    tdp_pool_imp_(new TdpMultPoolImpl_Current(*dynamic_cast<const TdpMultPoolImpl_Current*>(pool.tdp_pool_imp_)))
{
        
}

TdpMultPool& TdpMultPool::operator=(const TdpMultPool& t)
{
    if (tdp_pool_imp_ != t.tdp_pool_imp_) {
        delete tdp_pool_imp_;
        tdp_pool_imp_ = new TdpMultPoolImpl_Current(*dynamic_cast<const TdpMultPoolImpl_Current*>(t.tdp_pool_imp_));
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
    tdp_pool_imp_->eval_pool(in, out, order);
}

std::string TdpMultPool::eval(const std::string &in, uint8_t order) const
{
    std::string out;
    tdp_pool_imp_->eval_pool(in, out, order);
    
    return out;
}

std::array<uint8_t, Tdp::kMessageSize> TdpMultPool::eval(const std::array<uint8_t, kMessageSize> &in, uint8_t order) const
{
    return tdp_pool_imp_->eval_pool(in, order);
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
