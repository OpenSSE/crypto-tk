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

#include <sse/crypto/key.hpp>
#include <sse/crypto/prf.hpp>
#include <sse/crypto/tdp.hpp>

#include <cstdint>

#include <array>
#include <memory>
#include <string>

namespace sse {
namespace crypto {
class TdpImpl
{
public:
    static constexpr uint kMessageSpaceSize = Tdp::kMessageSize;

    virtual ~TdpImpl() = default;

    virtual size_t rsa_size() const = 0;

    virtual std::string public_key() const = 0;

    virtual void eval(const std::string& in, std::string& out) const = 0;
    virtual std::array<uint8_t, kMessageSpaceSize> eval(
        const std::array<uint8_t, kMessageSpaceSize>& in) const = 0;

    virtual std::string                            sample() const       = 0;
    virtual std::array<uint8_t, kMessageSpaceSize> sample_array() const = 0;

    virtual std::string generate(const Prf<Tdp::kRSAPrfSize>& prg,
                                 const std::string&           seed) const = 0;
    virtual std::array<uint8_t, kMessageSpaceSize> generate_array(
        const Prf<Tdp::kRSAPrfSize>& prg,
        const std::string&           seed) const                          = 0;
    virtual std::string generate(Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
                                 const std::string& seed) const = 0;
    virtual std::array<uint8_t, kMessageSpaceSize> generate_array(
        Key<Prf<Tdp::kRSAPrfSize>::kKeySize>&& key,
        const std::string&                     seed) const = 0;

    virtual std::unique_ptr<TdpImpl> duplicate() const = 0;
};

class TdpInverseImpl : virtual public TdpImpl
{
public:
    ~TdpInverseImpl() override = default;

    virtual std::string private_key() const                            = 0;
    virtual void invert(const std::string& in, std::string& out) const = 0;
    virtual std::array<uint8_t, kMessageSpaceSize> invert(
        const std::array<uint8_t, kMessageSpaceSize>& in) const = 0;

    virtual std::array<uint8_t, kMessageSpaceSize> invert_mult(
        const std::array<uint8_t, kMessageSpaceSize>& in,
        uint32_t                                      order) const                      = 0;
    virtual void invert_mult(const std::string& in,
                             std::string&       out,
                             uint32_t           order) const = 0;
};

class TdpMultPoolImpl : virtual public TdpImpl
{
public:
    ~TdpMultPoolImpl() override = default;

    virtual std::array<uint8_t, TdpImpl::kMessageSpaceSize> eval_pool(
        const std::array<uint8_t, kMessageSpaceSize>& in,
        const uint8_t                                 order) const                    = 0;
    virtual void eval_pool(const std::string& in,
                           std::string&       out,
                           const uint8_t      order) const = 0;

    virtual uint8_t maximum_order() const = 0;

    virtual std::unique_ptr<TdpMultPoolImpl> duplicate_pool() const = 0;
};


} // namespace crypto
} // namespace sse
