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

/// @file random.hpp
///
/// @brief Randomness generation
///
///

#pragma once

#include <array>
#include <string>

namespace sse {

namespace crypto {

/// @brief Generate random bytes
///
/// Fills a buffer with random bytes
///
/// @param byte_count   Number of bytes to generate
///
/// @param out          Buffer to be filled
///
void random_bytes(const size_t byte_count, unsigned char* out) noexcept;

/// @brief Fill an array with random bytes
///
/// Fills a std::array with random bytes
///
/// @param out          Array to be filled
///
template<typename T, size_t N>
inline void random_bytes(std::array<T, N>& out) noexcept
{
    random_bytes(out.size() * sizeof(T),
                 reinterpret_cast<unsigned char*>(out.data()));
}

/// @brief Generate a random array
///
/// Creates and returns an array filled with random bytes
///
/// @return A newly initialized array of type T and length N filled with
/// randomness
///
template<typename T, size_t N>
inline std::array<T, N> random_bytes() noexcept
{
    std::array<T, N> out;
    random_bytes(out.size() * sizeof(T),
                 reinterpret_cast<unsigned char*>(out.data()));
    return out;
}

/// @brief Generate a random string
///
/// Creates and returns an std::string filled with random bytes
///
/// @param length  Length of the constructed string
///
/// @return A newly initialized string filled with randomness
///
inline std::string random_string(const size_t length)
{
    uint8_t* tmp = new uint8_t[length];
    random_bytes(length, tmp);

    std::string out(reinterpret_cast<char*>(tmp), length);
    delete[] tmp;

    return out;
}

/// @brief RNG wrapper for mbedTLS
///
/// Wraps the call to random_bytes for mbedTLS.
/// You shoudl never call this function. Use random_bytes instead.
///
/// @param arg      Unused argument
/// @param out      Buffer to be filled
/// @param len      Length of the buffer
///
/// @return     Always return 0
inline int mbedTLS_rng_wrap(__attribute__((unused)) void* arg,
                            unsigned char*                out,
                            size_t                        len) noexcept
{
    random_bytes(len, out);
    return 0;
}

} // namespace crypto
} // namespace sse
