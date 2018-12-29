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


#pragma once

#ifdef WITH_OPENSSL

#include "tdp_impl.hpp"

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>

#include <cstdint>

#include <array>
#include <string>

#include <openssl/rsa.h>

namespace sse {
namespace crypto {
class TdpImpl_OpenSSL : virtual public TdpImpl
{
public:
    explicit TdpImpl_OpenSSL(const std::string& pk);
    TdpImpl_OpenSSL(const TdpImpl_OpenSSL& tdp);

    TdpImpl_OpenSSL& operator=(const TdpImpl_OpenSSL& t);

    ~TdpImpl_OpenSSL() override;

    RSA* get_rsa_key() const;
    void set_rsa_key(RSA* k);

    size_t rsa_size() const override;

    std::string public_key() const override;

    void eval(const std::string& in, std::string& out) const override;
    std::array<uint8_t, kMessageSpaceSize> eval(
        const std::array<uint8_t, kMessageSpaceSize>& in) const override;

    std::string                            sample() const override;
    std::array<uint8_t, kMessageSpaceSize> sample_array() const override;

    std::string generate(const Prf<Tdp::kRSAPrfSize>& prg,
                         const std::string&           seed) const override;
    std::array<uint8_t, kMessageSpaceSize> generate_array(
        const Prf<Tdp::kRSAPrfSize>& prg,
        const std::string&           seed) const override;
    std::string generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                         const std::string& seed) const override;
    std::array<uint8_t, kMessageSpaceSize> generate_array(
        Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
        const std::string&                     seed) const override;

    std::unique_ptr<TdpImpl> duplicate() const override;

protected:
    TdpImpl_OpenSSL();

    // cppcheck-suppress constStatement
    RSA* rsa_key_{nullptr};
};

class TdpInverseImpl_OpenSSL : public TdpImpl_OpenSSL,
                               virtual public TdpInverseImpl
{
public:
    TdpInverseImpl_OpenSSL();
    explicit TdpInverseImpl_OpenSSL(const std::string& sk);
    TdpInverseImpl_OpenSSL(const TdpInverseImpl_OpenSSL& tdp) = delete;
    TdpInverseImpl_OpenSSL(TdpInverseImpl_OpenSSL&& tdp)      = delete;
    ~TdpInverseImpl_OpenSSL() override;

    TdpInverseImpl_OpenSSL& operator=(const TdpInverseImpl_OpenSSL& t) = delete;

    std::string private_key() const override;
    void        invert(const std::string& in, std::string& out) const override;
    std::array<uint8_t, kMessageSpaceSize> invert(
        const std::array<uint8_t, kMessageSpaceSize>& in) const override;

    std::array<uint8_t, kMessageSpaceSize> invert_mult(
        const std::array<uint8_t, kMessageSpaceSize>& in,
        uint32_t                                      order) const override;
    void invert_mult(const std::string& in,
                     std::string&       out,
                     uint32_t           order) const override;

private:
    BIGNUM *phi_, *p_1_, *q_1_;
};

class TdpMultPoolImpl_OpenSSL : public TdpImpl_OpenSSL,
                                virtual public TdpMultPoolImpl
{
public:
    TdpMultPoolImpl_OpenSSL(const std::string& sk, const uint8_t size);
    TdpMultPoolImpl_OpenSSL(const TdpMultPoolImpl_OpenSSL& pool_impl);

    TdpMultPoolImpl_OpenSSL& operator=(const TdpMultPoolImpl_OpenSSL& t);

    ~TdpMultPoolImpl_OpenSSL() override;

    std::array<uint8_t, TdpImpl_OpenSSL::kMessageSpaceSize> eval_pool(
        const std::array<uint8_t, kMessageSpaceSize>& in,
        const uint8_t                                 order) const override;
    void eval_pool(const std::string& in,
                   std::string&       out,
                   const uint8_t      order) const override;

    uint8_t maximum_order() const override;

    std::unique_ptr<TdpMultPoolImpl> duplicate_pool() const override;

private:
    RSA** keys_;

    uint8_t keys_count_;
};


} // namespace crypto
} // namespace sse
#endif
