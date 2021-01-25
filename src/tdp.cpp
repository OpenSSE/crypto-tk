
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

#include "tdp.hpp"

#include "prf.hpp"
#include "random.hpp"
#include "tdp_impl/tdp_impl.hpp"
#include "utils.hpp"

#include <cstring>

#include <exception>
#include <iomanip>
#include <iostream>

#define SSE_CRYPTO_TDP_IMPL_MBEDTLS 1
#define SSE_CRYPTO_TDP_IMPL_OPENSSL 2

/*
 * The default TDP implementation used mbedTLS
 * To use OpenSSL, uncomment the following line and
 * replace SSE_CRYPTO_TDP_IMPL_MBEDTLS by SSE_CRYPTO_TDP_IMPL_OPENSSL
 * or pass the option -DSSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL
 * to the compiler
 */
#if !defined(SSE_CRYPTO_TDP_IMPL)
#define SSE_CRYPTO_TDP_IMPL SSE_CRYPTO_TDP_IMPL_MBEDTLS
#endif

#if defined(SSE_CRYPTO_TDP_IMPL)                                               \
    && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)

#ifndef WITH_OPENSSL
#error "OpenSSL is not in use."
#endif

#include "tdp_impl/tdp_impl_openssl.hpp"

#elif defined(SSE_CRYPTO_TDP_IMPL)                                             \
    && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_MBEDTLS)
#include "tdp_impl/tdp_impl_mbedtls.hpp"

#else

#error("No valid TDP implementation defined")

#endif


namespace sse {
namespace crypto {

#if defined(SSE_CRYPTO_TDP_IMPL)                                               \
    && (SSE_CRYPTO_TDP_IMPL == SSE_CRYPTO_TDP_IMPL_OPENSSL)

using TdpImpl_Current         = TdpImpl_OpenSSL;
using TdpInverseImpl_Current  = TdpInverseImpl_OpenSSL;
using TdpMultPoolImpl_Current = TdpMultPoolImpl_OpenSSL;

#else

using TdpImpl_Current         = TdpImpl_mbedTLS;
using TdpInverseImpl_Current  = TdpInverseImpl_mbedTLS;
using TdpMultPoolImpl_Current = TdpMultPoolImpl_mbedTLS;

#endif

static_assert(Tdp::kMessageSize == TdpInverse::kMessageSize,
              "Constants kMessageSize of Tdp and TdpInverse do not match");

Tdp::Tdp(const std::string& pk) : tdp_imp_(new TdpImpl_Current(pk))
{
}

Tdp::Tdp(const Tdp& t) : tdp_imp_(t.tdp_imp_->duplicate())
{
}

// NOLINTNEXTLINE(modernize-use-equals-default)
Tdp::~Tdp()
{
}

Tdp& Tdp::operator=(const Tdp& t)
{
    if ((this != &t) && (tdp_imp_ != t.tdp_imp_)) {
        tdp_imp_ = t.tdp_imp_->duplicate();
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

std::string Tdp::generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                          const std::string&                     seed) const
{
    return tdp_imp_->generate(std::move(key), seed);
}
std::array<uint8_t, Tdp::kMessageSize> Tdp::generate_array(
    Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
    const std::string&                     seed) const
{
    return tdp_imp_->generate_array(std::move(key), seed);
}

std::string Tdp::generate(const Prf<Tdp::kRSAPrfSize>& prf,
                          const std::string&           seed) const
{
    return tdp_imp_->generate(prf, seed);
}
std::array<uint8_t, Tdp::kMessageSize> Tdp::generate_array(
    const Prf<Tdp::kRSAPrfSize>& prf,
    const std::string&           seed) const
{
    return tdp_imp_->generate_array(prf, seed);
}

void Tdp::eval(const std::string& in, std::string& out) const
{
    tdp_imp_->eval(in, out);
}

std::string Tdp::eval(const std::string& in) const
{
    std::string out;
    tdp_imp_->eval(in, out);

    return out;
}

std::array<uint8_t, Tdp::kMessageSize> Tdp::eval(
    const std::array<uint8_t, kMessageSize>& in) const
{
    return tdp_imp_->eval(in);
}

TdpInverse::TdpInverse() : tdp_inv_imp_(new TdpInverseImpl_Current())
{
}

TdpInverse::TdpInverse(const std::string& sk)
    : tdp_inv_imp_(new TdpInverseImpl_Current(sk))
{
}

// NOLINTNEXTLINE(modernize-use-equals-default)
TdpInverse::~TdpInverse()
{
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

std::string TdpInverse::generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                                 const std::string& seed) const
{
    return tdp_inv_imp_->generate(std::move(key), seed);
}
std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::generate_array(
    Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
    const std::string&                     seed) const
{
    return tdp_inv_imp_->generate_array(std::move(key), seed);
}

std::string TdpInverse::generate(const Prf<Tdp::kRSAPrfSize>& prf,
                                 const std::string&           seed) const
{
    return tdp_inv_imp_->generate(prf, seed);
}
std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::generate_array(
    const Prf<Tdp::kRSAPrfSize>& prf,
    const std::string&           seed) const
{
    return tdp_inv_imp_->generate_array(prf, seed);
}

void TdpInverse::eval(const std::string& in, std::string& out) const
{
    tdp_inv_imp_->eval(in, out);
}

std::string TdpInverse::eval(const std::string& in) const
{
    std::string out;
    tdp_inv_imp_->eval(in, out);

    return out;
}

std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::eval(
    const std::array<uint8_t, kMessageSize>& in) const
{
    return tdp_inv_imp_->eval(in);
}

void TdpInverse::invert(const std::string& in, std::string& out) const
{
    tdp_inv_imp_->invert(in, out);
}

std::string TdpInverse::invert(const std::string& in) const
{
    std::string out;
    tdp_inv_imp_->invert(in, out);

    return out;
}

std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::invert(
    const std::array<uint8_t, kMessageSize>& in) const
{
    return tdp_inv_imp_->invert(in);
}

void TdpInverse::invert_mult(const std::string& in,
                             std::string&       out,
                             uint32_t           order) const
{
    tdp_inv_imp_->invert_mult(in, out, order);
}

std::string TdpInverse::invert_mult(const std::string& in, uint32_t order) const
{
    std::string out;
    tdp_inv_imp_->invert_mult(in, out, order);

    return out;
}

std::array<uint8_t, TdpInverse::kMessageSize> TdpInverse::invert_mult(
    const std::array<uint8_t, kMessageSize>& in,
    uint32_t                                 order) const
{
    return tdp_inv_imp_->invert_mult(in, order);
}


void TdpInverse::serialize(uint8_t* out) const
{
    std::string sk = private_key();
    // NOLINTNEXTLINE(bugprone-not-null-terminated-result)
    memcpy(out, sk.data(), sk.size());
}


TdpInverse TdpInverse::deserialize(uint8_t*     in,
                                   const size_t in_size,
                                   size_t&      n_bytes_read)
{
    // search for "-----END RSA PRIVATE KEY-----"
    static constexpr size_t kKeySuffixSize = 29;
    // NOLINTNEXTLINE(modernize-avoid-c-arrays)
    static constexpr uint8_t kKeySuffix[kKeySuffixSize + 1]
        = "-----END RSA PRIVATE KEY-----"; // we have to account for the
                                           // '\0' character ...

    const uint8_t* suffix_start
        = strstrn_uint8(in, in_size, kKeySuffix, kKeySuffixSize);

    if (suffix_start <= in) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("TdpInverse::deserialize: invalid "
                                 "buffer. The buffer does not "
                                 "contain the RSA private key suffix");
        /* LCOV_EXCL_STOP */
    }
    n_bytes_read = kKeySuffixSize + static_cast<size_t>(suffix_start - in);
    std::string sk(
        reinterpret_cast<const char*>(in),
        reinterpret_cast<const char*>(suffix_start + kKeySuffixSize));
    TdpInverse result(sk);

    if ((n_bytes_read < in_size) && (in[n_bytes_read] == '\n')) {
        n_bytes_read++; // there might be a trailing \n character at the
                        // end
    }

    return result;
}


TdpMultPool::TdpMultPool(const std::string& pk, const uint8_t size)
    : tdp_pool_imp_(new TdpMultPoolImpl_Current(pk, size))
{
}

TdpMultPool::TdpMultPool(const TdpMultPool& pool)
    : tdp_pool_imp_(pool.tdp_pool_imp_->duplicate_pool())
{
}

TdpMultPool& TdpMultPool::operator=(const TdpMultPool& t)
{
    if ((this != &t) && (tdp_pool_imp_ != t.tdp_pool_imp_)) {
        tdp_pool_imp_ = t.tdp_pool_imp_->duplicate_pool();
    }
    return *this;
}

// NOLINTNEXTLINE(modernize-use-equals-default)
TdpMultPool::~TdpMultPool()
{
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

std::string TdpMultPool::generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                                  const std::string& seed) const
{
    return tdp_pool_imp_->generate(std::move(key), seed);
}
std::array<uint8_t, TdpMultPool::kMessageSize> TdpMultPool::generate_array(
    Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
    const std::string&                     seed) const
{
    return tdp_pool_imp_->generate_array(std::move(key), seed);
}

std::string TdpMultPool::generate(const Prf<Tdp::kRSAPrfSize>& prf,
                                  const std::string&           seed) const
{
    return tdp_pool_imp_->generate(prf, seed);
}
std::array<uint8_t, TdpMultPool::kMessageSize> TdpMultPool::generate_array(
    const Prf<Tdp::kRSAPrfSize>& prf,
    const std::string&           seed) const
{
    return tdp_pool_imp_->generate_array(prf, seed);
}

void TdpMultPool::eval(const std::string& in,
                       std::string&       out,
                       uint8_t            order) const
{
    tdp_pool_imp_->eval_pool(in, out, order);
}

std::string TdpMultPool::eval(const std::string& in, uint8_t order) const
{
    std::string out;
    tdp_pool_imp_->eval_pool(in, out, order);

    return out;
}

std::array<uint8_t, Tdp::kMessageSize> TdpMultPool::eval(
    const std::array<uint8_t, kMessageSize>& in,
    uint8_t                                  order) const
{
    return tdp_pool_imp_->eval_pool(in, order);
}

void TdpMultPool::eval(const std::string& in, std::string& out) const
{
    static_cast<TdpImpl*>(tdp_pool_imp_.get())->eval(in, out);
}

std::string TdpMultPool::eval(const std::string& in) const
{
    std::string out;
    static_cast<TdpImpl*>(tdp_pool_imp_.get())->eval(in, out);

    return out;
}

std::array<uint8_t, Tdp::kMessageSize> TdpMultPool::eval(
    const std::array<uint8_t, kMessageSize>& in) const
{
    return static_cast<TdpImpl*>(tdp_pool_imp_.get())->eval(in);
}

uint8_t TdpMultPool::maximum_order() const
{
    return tdp_pool_imp_->maximum_order();
}

} // namespace crypto
} // namespace sse
