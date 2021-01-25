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

#include "hash.hpp"

#include "hash/blake2b.hpp"
#include "hash/sha512.hpp"

#include <cstring>

#include <array>
#include <stdexcept>

namespace sse {

namespace crypto {

using hash_function = hash::blake2b;

void Hash::hash(const unsigned char* in, const size_t len, unsigned char* out)
{
    if (in == nullptr) {
        throw std::invalid_argument("in is NULL");
    }

    if (out == nullptr) {
        throw std::invalid_argument("out is NULL");
    }

    static_assert(
        kDigestSize == hash_function::kDigestSize,
        "Declared digest size and hash_function digest size do not match");
    static_assert(
        kBlockSize == hash_function::kBlockSize,
        "Declared block size and hash_function block size do not match");
    hash_function::hash(in, len, out);
}

void Hash::hash(const unsigned char* in,
                const size_t         len,
                const size_t         out_len,
                unsigned char*       out)
{
    if (out_len > kDigestSize) {
        throw std::invalid_argument(
            "Invalid output length: out_len > kDigestSize");
    }

    if (in == nullptr) {
        throw std::invalid_argument("in is NULL");
    }

    if (out == nullptr) {
        throw std::invalid_argument("out is NULL");
    }


    std::array<unsigned char, kDigestSize> digest;

    hash(in, len, digest.data());
    memcpy(out, digest.data(), out_len);
}

void Hash::hash(const std::string& in, std::string& out)
{
    std::array<uint8_t, kDigestSize> tmp_out;
    hash(reinterpret_cast<const unsigned char*>(in.data()),
         in.length(),
         tmp_out.data());

    out = std::string(reinterpret_cast<char*>(tmp_out.data()), kDigestSize);
}

void Hash::hash(const std::string& in, const size_t out_len, std::string& out)
{
    if (out_len > kDigestSize) {
        throw std::invalid_argument(
            "Invalid output length: out_len > kDigestSize");
    }

    std::array<uint8_t, kDigestSize> tmp_out;

    hash(reinterpret_cast<const unsigned char*>(in.data()),
         in.length(),
         tmp_out.data());

    out = std::string(reinterpret_cast<char*>(tmp_out.data()), out_len);
}

std::string Hash::hash(const std::string& in)
{
    std::string out;
    hash(in, out);
    return out;
}

std::string Hash::hash(const std::string& in, const size_t out_len)
{
    std::string out;
    hash(in, out_len, out);
    return out;
}

} // namespace crypto
} // namespace sse
