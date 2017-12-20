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

#include <exception>
#include <iomanip>
#include <iostream>

#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/utils.h>

#include <cstring>

#include "hash.hpp"

namespace sse {

namespace crypto {

constexpr uint8_t ec_inf_point__[crypto_core_ed25519_BYTES]
    = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

class SetHash::SetHashImpl
{
    friend SetHash;

public:
    SetHashImpl();
    explicit SetHashImpl(const SetHashImpl& s);
    explicit SetHashImpl(const std::array<uint8_t, kSetHashSize>& bytes);
    explicit SetHashImpl(const std::vector<std::string>& in_set);

    SetHashImpl& operator=(const SetHashImpl& h);

    void add_element(const std::string& in);
    void add_set(const SetHashImpl* in);
    void remove_element(const std::string& in);
    void remove_set(const SetHashImpl* in);

    std::array<uint8_t, kSetHashSize> data() const;

    bool operator==(const SetHashImpl& h) const;

private:
    static void gen_curve_point(
        std::array<uint8_t, crypto_core_ed25519_BYTES>& p,
        const uint8_t*                                  buf,
        const size_t                                    len);

    uint8_t
        ellig_state_[crypto_core_ed25519_BYTES]; // keep it that way for now,
                                                 // might be replaced with
                                                 // dynamic memory allocation
    static constexpr std::array<uint8_t, crypto_scalarmult_ed25519_SCALARBYTES>
        seed__{{0x00}};

    static_assert(crypto_core_ed25519_BYTES == kSetHashSize,
                  "crypto_core_ed25519_BYTES != kSetHashSize");
};

constexpr std::array<uint8_t, crypto_scalarmult_ed25519_SCALARBYTES>
    SetHash::SetHashImpl::seed__;

SetHash::SetHash() : set_hash_imp_(new SetHashImpl())
{
}

SetHash::SetHash(const std::array<uint8_t, kSetHashSize>& bytes)
    : set_hash_imp_(new SetHashImpl(bytes))
{
}

SetHash::SetHash(const SetHash& o)
    : set_hash_imp_(new SetHashImpl(*o.set_hash_imp_))
{
}

SetHash::SetHash(SetHash&& o) noexcept : set_hash_imp_(o.set_hash_imp_)
{
    o.set_hash_imp_ = NULL;
}

SetHash::SetHash(const std::vector<std::string>& in_set)
    : set_hash_imp_(new SetHashImpl(in_set))
{
}

SetHash::~SetHash()
{
    if (set_hash_imp_ != nullptr) {
        delete set_hash_imp_;
    }
}

void SetHash::add_element(const std::string& in)
{
    set_hash_imp_->add_element(in);
}

void SetHash::add_set(const SetHash& h)
{
    set_hash_imp_->add_set(h.set_hash_imp_);
}

void SetHash::remove_element(const std::string& in)
{
    set_hash_imp_->remove_element(in);
}

void SetHash::remove_set(const SetHash& h)
{
    set_hash_imp_->remove_set(h.set_hash_imp_);
}

std::array<uint8_t, SetHash::kSetHashSize> SetHash::data() const
{
    return set_hash_imp_->data();
}


/* LCOV_EXCL_START */
std::ostream& operator<<(std::ostream& os, const SetHash& h)
{
    auto d = h.set_hash_imp_->data();
    for (uint8_t b : d) {
        os << std::hex << std::setw(2) << std::setfill('0') << (uint)b;
    }
    os << std::dec;
    return os;
}
/* LCOV_EXCL_STOP */

SetHash& SetHash::operator=(const SetHash& h)
{
    if (this != &h) {
        *set_hash_imp_ = *h.set_hash_imp_;
    }
    return *this;
}

bool SetHash::operator==(const SetHash& h) const
{
    return (*set_hash_imp_ == *h.set_hash_imp_);
}

bool SetHash::operator!=(const SetHash& h) const
{
    return !(*this == h);
}

//
//
// SetHashImpl
//
//

void SetHash::SetHashImpl::gen_curve_point(
    std::array<uint8_t, crypto_core_ed25519_BYTES>& p,
    const uint8_t*                                  buf,
    const size_t                                    len)
{
    std::array<uint8_t, crypto_core_ed25519_UNIFORMBYTES> h;
    sse::crypto::Hash::hash(
        buf, len, crypto_core_ed25519_UNIFORMBYTES, h.data());

    crypto_core_ed25519_from_uniform(p.data(), h.data());
}

SetHash::SetHashImpl::SetHashImpl()
{
    // the initial state is the infinite point
    // we directly copy ec_inf_point__: calling
    // crypto_scalarmult_ed25519_base(ellig_state_, scalar_zero__)
    // will generate a differenter byte string as the one obtained by computing
    // crypto_core_ed25519_sub(_,b,b) (computing b-b). Indeed,
    // crypto_core_ed25519_sub(x,b,b) sets x to ec_inf_point__.
    memcpy(ellig_state_, ec_inf_point__, crypto_core_ed25519_BYTES);
}

SetHash::SetHashImpl::SetHashImpl(const SetHash::SetHashImpl& s)
{
    memcpy(ellig_state_, s.ellig_state_, sizeof(ellig_state_));
}

SetHash::SetHashImpl::SetHashImpl(
    const std::array<uint8_t, kSetHashSize>& bytes)
{
    memcpy(ellig_state_, bytes.data(), crypto_core_ed25519_BYTES);

    if ((crypto_core_ed25519_is_valid_point(ellig_state_) != 1)
        && (sodium_memcmp(
                bytes.data(), ec_inf_point__, crypto_core_ed25519_BYTES)
            != 0)) {
        throw std::invalid_argument("SetHash: Invalid curve point");
    }
}

SetHash::SetHashImpl::SetHashImpl(const std::vector<std::string>& in_set)
{
    memcpy(ellig_state_, ec_inf_point__, crypto_core_ed25519_BYTES);
    std::array<uint8_t, crypto_core_ed25519_BYTES> p;

    for (auto& s : in_set) {
        SetHash::SetHashImpl::gen_curve_point(
            p, reinterpret_cast<const uint8_t*>(s.data()), s.size());

        crypto_core_ed25519_add(ellig_state_, ellig_state_, p.data());
    }
}

SetHash::SetHashImpl& SetHash::SetHashImpl::operator=(const SetHashImpl& h)
{
    memcpy(ellig_state_, h.ellig_state_, sizeof(ellig_state_));

    return *this;
}

void SetHash::SetHashImpl::add_element(const std::string& in)
{
    std::array<uint8_t, crypto_core_ed25519_BYTES> p;
    SetHash::SetHashImpl::gen_curve_point(
        p, reinterpret_cast<const uint8_t*>(in.data()), in.size());

    crypto_core_ed25519_add(ellig_state_, ellig_state_, p.data());
}

void SetHash::SetHashImpl::add_set(const SetHash::SetHashImpl* in)
{
    crypto_core_ed25519_add(ellig_state_, ellig_state_, in->ellig_state_);
}

void SetHash::SetHashImpl::remove_element(const std::string& in)
{
    std::array<uint8_t, crypto_core_ed25519_BYTES> p;
    SetHash::SetHashImpl::gen_curve_point(
        p, reinterpret_cast<const uint8_t*>(in.data()), in.size());

    crypto_core_ed25519_sub(ellig_state_, ellig_state_, p.data());
}

void SetHash::SetHashImpl::remove_set(const SetHash::SetHashImpl* in)
{
    crypto_core_ed25519_sub(ellig_state_, ellig_state_, in->ellig_state_);
}

std::array<uint8_t, SetHash::kSetHashSize> SetHash::SetHashImpl::data() const
{
    std::array<uint8_t, kSetHashSize> bytes;
    memcpy(bytes.data(), ellig_state_, kSetHashSize);

    return bytes;
}

bool SetHash::SetHashImpl::operator==(const SetHash::SetHashImpl& h) const
{
    return sodium_memcmp(
               ellig_state_, h.ellig_state_, crypto_core_ed25519_BYTES)
           == 0;
}

} // namespace crypto
} // namespace sse
