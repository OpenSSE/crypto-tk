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

#include "set_hash.hpp"

#include "hash.hpp"

#include <cstring>

#include <exception>
#include <iomanip>
#include <iostream>

#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/utils.h>

namespace sse {

namespace crypto {


static_assert(crypto_core_ed25519_BYTES == SetHash::kSetHashSize,
              "crypto_core_ed25519_BYTES != kSetHashSize");

constexpr std::array<uint8_t, SetHash::kSetHashSize> SetHash::kECInfinitePoint;

SetHash::SetHash(const std::array<uint8_t, kSetHashSize>& bytes)
    : set_hash_state_(bytes)
{
    if ((crypto_core_ed25519_is_valid_point(set_hash_state_.data()) != 1)
        && (sodium_memcmp(bytes.data(),
                          kECInfinitePoint.data(),
                          crypto_core_ed25519_BYTES)
            != 0)) {
        throw std::invalid_argument("SetHash: Invalid curve point");
    }
}


SetHash::SetHash(const std::vector<std::string>& in_set)
{
    std::array<uint8_t, crypto_core_ed25519_BYTES> p;

    for (const auto& s : in_set) {
        SetHash::gen_curve_point(
            p, reinterpret_cast<const uint8_t*>(s.data()), s.size());

        crypto_core_ed25519_add(
            set_hash_state_.data(), set_hash_state_.data(), p.data());
    }
}

const std::array<uint8_t, SetHash::kSetHashSize>& SetHash::data() const
{
    return set_hash_state_;
}


/* LCOV_EXCL_START */
std::ostream& operator<<(std::ostream& os, const SetHash& h)
{
    // Save the format of the stream
    std::ios_base::fmtflags saved_flags(os.flags());

    for (uint8_t b : h.set_hash_state_) {
        os << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<uint>(b);
    }

    // Reset the flags
    os.flags(saved_flags);

    return os;
}
/* LCOV_EXCL_STOP */

bool SetHash::operator==(const SetHash& h) const
{
    return sodium_memcmp(
               set_hash_state_.data(), h.set_hash_state_.data(), kSetHashSize)
           == 0;
}

bool SetHash::operator!=(const SetHash& h) const
{
    return !(*this == h);
}

void SetHash::gen_curve_point(std::array<uint8_t, crypto_core_ed25519_BYTES>& p,
                              const uint8_t* buf,
                              const size_t   len)
{
    std::array<uint8_t, crypto_core_ed25519_UNIFORMBYTES> h;
    sse::crypto::Hash::hash(
        buf, len, crypto_core_ed25519_UNIFORMBYTES, h.data());

    crypto_core_ed25519_from_uniform(p.data(), h.data());
}

void SetHash::add_element(const std::string& in)
{
    std::array<uint8_t, crypto_core_ed25519_BYTES> p;
    SetHash::gen_curve_point(
        p, reinterpret_cast<const uint8_t*>(in.data()), in.size());

    crypto_core_ed25519_add(
        set_hash_state_.data(), set_hash_state_.data(), p.data());
}

void SetHash::add_set(const SetHash& h)
{
    crypto_core_ed25519_add(set_hash_state_.data(),
                            set_hash_state_.data(),
                            h.set_hash_state_.data());
}

void SetHash::remove_element(const std::string& in)
{
    std::array<uint8_t, crypto_core_ed25519_BYTES> p;
    SetHash::gen_curve_point(
        p, reinterpret_cast<const uint8_t*>(in.data()), in.size());

    crypto_core_ed25519_sub(
        set_hash_state_.data(), set_hash_state_.data(), p.data());
}

void SetHash::remove_set(const SetHash& h)
{
    crypto_core_ed25519_sub(set_hash_state_.data(),
                            set_hash_state_.data(),
                            h.set_hash_state_.data());
}

} // namespace crypto
} // namespace sse
