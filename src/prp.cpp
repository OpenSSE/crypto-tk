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

#include "prp.hpp"

#include "random.hpp"

#if __AES__ || __ARM_FEATURE_CRYPTO
#include "aez/aez.h"
#endif

#include <climits>
#include <cstring>

#include <array>
#include <exception>
#include <iomanip>

#include <sodium/runtime.h>

namespace sse {

namespace crypto {

bool Prp::is_available__ = false;

#if !(__AES__ || __ARM_FEATURE_CRYPTO)

#error("PRP is not available without CPU support for AES instructions")

#endif /* !(__AES__ || __ARM_FEATURE_CRYPTO) */

void Prp::compute_is_available() noexcept
{
#if __AES__ || __ARM_FEATURE_CRYPTO
    is_available__
        = (sodium_runtime_has_aesni() == 1) || (sodium_runtime_has_neon() == 1);
#else
    is_available__ = false;
#endif
}


Key<sizeof(aez_ctx_t)> Prp::init_random_aez_ctx()
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }
    auto callback = [](uint8_t* key_content) {
        Key<Prp::kKeySize> r_key;
        aez_setup(
            r_key.unlock_get(), 48, reinterpret_cast<aez_ctx_t*>(key_content));
    };

    return Key<Prp::kContextSize>(callback);
}

Prp::Prp() : aez_ctx_(init_random_aez_ctx())
{
    static_assert(kContextSize == sizeof(aez_ctx_t),
                  "Prp: kContextSize and the aez_ctx_t size do not match");
}

Key<sizeof(aez_ctx_t)> Prp::init_aez_ctx(Key<kKeySize>&& k)
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }
    auto callback = [&k](uint8_t* key_content) {
        aez_setup(
            k.unlock_get(), 48, reinterpret_cast<aez_ctx_t*>(key_content));
    };

    auto key = Key<Prp::kContextSize>(callback);
    k.erase();

    return key;
}

Prp::Prp(Key<kKeySize>&& k) : aez_ctx_(init_aez_ctx(std::move(k)))
{
}

Prp::Prp(Key<kContextSize>&& context) : aez_ctx_(std::move(context))
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP are unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }
}

std::string Prp::encrypt(const std::string& in)
{
    std::string out;
    encrypt(in, out);
    return out;
}

uint32_t Prp::encrypt(const uint32_t in)
{
    uint32_t out;
    encrypt(reinterpret_cast<const unsigned char*>(&in),
            sizeof(uint32_t),
            reinterpret_cast<unsigned char*>(&out));
    return out;
}

uint64_t Prp::encrypt_64(const uint64_t in)
{
    uint64_t out;
    encrypt(reinterpret_cast<const unsigned char*>(&in),
            sizeof(uint64_t),
            reinterpret_cast<unsigned char*>(&out));
    return out;
}


std::string Prp::decrypt(const std::string& in)
{
    std::string out;
    decrypt(in, out);
    return out;
}

uint32_t Prp::decrypt(const uint32_t in)
{
    uint32_t out;
    decrypt(reinterpret_cast<const unsigned char*>(&in),
            sizeof(uint32_t),
            reinterpret_cast<unsigned char*>(&out));
    return out;
}

uint64_t Prp::decrypt_64(const uint64_t in)
{
    uint64_t out;
    decrypt(reinterpret_cast<const unsigned char*>(&in),
            sizeof(uint64_t),
            reinterpret_cast<unsigned char*>(&out));
    return out;
}

void Prp::encrypt(const uint8_t* in, const unsigned int len, uint8_t* out)
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }
    std::array<char, 16> iv = {0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00};
    aez_encrypt(reinterpret_cast<const aez_ctx_t*>(aez_ctx_.unlock_get()),
                iv.data(),
                iv.size(),
                0,
                reinterpret_cast<const char*>(in),
                len,
                reinterpret_cast<char*>(out));
}

void Prp::encrypt(const std::string& in, std::string& out)
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }

    size_t len = in.size();

    if (len > UINT_MAX) {
        /* LCOV_EXCL_START */
        throw std::runtime_error(
            "The maximum input length of Format Preserving Encryption is "
            "UINT_MAX");
        /* LCOV_EXCL_STOP */
    }

    unsigned char* data = new unsigned char[len];

    encrypt(reinterpret_cast<const unsigned char*>(in.data()),
            static_cast<unsigned int>(len),
            data);
    out = std::string(reinterpret_cast<char*>(data), len);
    delete[] data;
}

void Prp::decrypt(const uint8_t* in, const unsigned int len, uint8_t* out)
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }

    std::array<char, 16> iv = {0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00,
                               0x00};
    aez_decrypt(reinterpret_cast<const aez_ctx_t*>(aez_ctx_.unlock_get()),
                iv.data(),
                iv.size(),
                0,
                reinterpret_cast<const char*>(in),
                len,
                reinterpret_cast<char*>(out));

    aez_ctx_.lock();
}

void Prp::decrypt(const std::string& in, std::string& out)
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }

    size_t len = in.size();

    if (len > UINT_MAX) {
        /* LCOV_EXCL_START */
        throw std::runtime_error(
            "The maximum input length of Format Preserving Encryption is "
            "UINT_MAX");
        /* LCOV_EXCL_STOP */
    }

    unsigned char* data = new unsigned char[len];

    decrypt(reinterpret_cast<const unsigned char*>(in.data()),
            static_cast<unsigned int>(len),
            data);

    out = std::string(reinterpret_cast<const char*>(data), len);
    delete[] data;
}

void Prp::serialize(uint8_t* out) const
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }
    aez_ctx_.unlock();
    aez_ctx_.serialize(out);
    aez_ctx_.lock();
}

Prp Prp::deserialize(uint8_t* in, const size_t in_size, size_t& n_bytes_read)
{
    if (!Prp::is_available()) {
        /* LCOV_EXCL_START */
        throw std::runtime_error("PRP is unavailable: AES hardware "
                                 "acceleration not supported by the CPU");
        /* LCOV_EXCL_STOP */
    }
    if (in_size < kContextSize) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Prp::deserialize: the deserialization "
                                    "buffer size should be Prp::kContextSize.");
        /* LCOV_EXCL_STOP */
    }
    n_bytes_read = kContextSize;

    return Prp(Key<kContextSize>(in));
}


} // namespace crypto
} // namespace sse
