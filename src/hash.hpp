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

#include <cstddef>

#include <string>


namespace sse {

namespace crypto {

/// @class Hash
/// @brief Cryptographic hashing
///
/// Hash is an opaque class for cryptographic hashing.
/// The hash function used is Blake2b.
/// Digests are 512 bits (64 bytes) large, which ensures a 2^256 bits security
/// against collisions (and more against pre-image and second pre-image
/// attacks).
///

class Hash
{
public:
    /// @brief Digest size (in bytes)
    constexpr static size_t kDigestSize = 64;
    /// @brief Size of the blocks in the hash function (in bytes)
    constexpr static size_t kBlockSize = 128;

    ///
    /// @brief Hash a buffer
    ///
    /// Computes the hash of the input buffer and places it in the output
    /// buffer.
    ///
    /// @param in   The input buffer. Must be non NULL.
    /// @param len  The size of the input buffer in bytes.
    /// @param out  The output buffer. Must be non NULL, and larger than
    ///             kDigestSize bytes.
    ///
    /// @exception std::invalid_argument       One of in or out is NULL
    ///
    static void hash(const unsigned char* in,
                     const size_t         len,
                     unsigned char*       out);

    ///
    /// @brief Hash a buffer
    ///
    /// Computes the hash of the input buffer, truncates it and places it in the
    /// output buffer.
    ///
    /// @param in       The input buffer. Must be non NULL.
    /// @param len      The size of the input buffer in bytes.
    /// @param out_len  The size of the output buffer in bytes. Must be smaller
    ///                 than kDigestSize.
    /// @param out      The output buffer. Must be non NULL, and larger than
    /// out_len bytes.
    ///
    /// @exception std::invalid_argument       One of in or out is NULL
    /// @exception std::invalid_argument       out_len is larger than
    /// kDigestSize
    ///
    static void hash(const unsigned char* in,
                     const size_t         len,
                     const size_t         out_len,
                     unsigned char*       out);
    ///
    /// @brief Hash a string
    ///
    /// Computes the hash of the input string andplaces it in the
    /// output string.
    ///
    /// @param in       The input string.
    /// @param out      The output string.
    ///
    ///
    static void hash(const std::string& in, std::string& out);

    ///
    /// @brief Hash a string
    ///
    /// Computes the hash of the input string, truncates it and places it in the
    /// output string.
    ///
    /// @param in       The input string.
    /// @param out_len  The size of the output buffer in bytes. Must be smaller
    ///                 than kDigestSize.
    /// @param out      The output string. Will be an out_len bytes string after
    ///                 return of the function
    ///
    /// @exception std::invalid_argument       out_len is larger than
    /// kDigestSize
    ///
    static void hash(const std::string& in,
                     const size_t       out_len,
                     std::string&       out);

    ///
    /// @brief Hash a string and return the digest
    ///
    /// Computes the hash of the input string and and returns it.
    ///
    /// @param in       The input string.
    ///
    /// @return The hash of in, truncated to its first out_len bytes.
    ///
    static std::string hash(const std::string& in);

    ///
    /// @brief Hash a string and return the digest
    ///
    /// Computes the hash of the input string, truncates it and returns it.
    ///
    /// @param in       The input string.
    /// @param out_len  The size of the output buffer in bytes. Must be smaller
    ///                 than kDigestSize.
    ///
    /// @return The hash of in, truncated to its first out_len bytes.
    ///
    /// @exception std::invalid_argument       out_len is larger than
    /// kDigestSize
    ///
    static std::string hash(const std::string& in, const size_t out_len);
};

} // namespace crypto
} // namespace sse
