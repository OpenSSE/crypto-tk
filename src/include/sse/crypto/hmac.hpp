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
#include <sse/crypto/random.hpp>

#include <cassert>
#include <cstdint>
#include <cstring>

#include <array>
#include <iomanip>
#include <iostream>
#include <string>

#include <sodium/utils.h>


namespace sse {

namespace crypto {

// forward declare the Prf class so we can use is as a friend
template<uint16_t NBYTES>
class Prf;


/// @class HMac
/// @brief Hash-based message authentication code.
///
/// The HMac class implements the hash-based message authentication code as
/// defined by Bellare, Canetti, and Krawczyk (cf. RFC 2104). The class can is
/// templated with the underlying hash function, and the key size.
///
/// @tparam H   Hash function used to compute HMAC
/// @tparam N   Key size (in bytes)
///

template<class H, uint16_t N>
class HMac
{
    template<uint16_t NBYTES>
    friend class Prf;

public:
    /// @brief Maximum key size (in bytes) of the H-HMac instantiation
    static constexpr uint16_t kHMACKeySize = H::kBlockSize;
    /// @brief The key size (in bytes) of the template instantiation (N)
    static constexpr uint16_t kKeySize = N;
    /// @brief Minimum key size: 16 bytes to offer at least 128 bits of security
    static constexpr uint16_t kMinKeySize
        = 16; // minimum key size to ensure security

    static_assert(kHMACKeySize >= kMinKeySize,
                  "The hash block size is less than 16 bytes. "
                  "This is insecure. Chose an other hash function");

    static_assert(N >= kMinKeySize,
                  "The HMAC key is less than 16 bytes. "
                  "This is insecure. Chose an other hash function");

    /// @brief Digest (out) size (in bytes) of the H-HMac instantiation
    static constexpr uint8_t kDigestSize = H::kDigestSize;

    ///
    /// @brief Constructor
    ///
    /// Creates a HMac object with a new randomly generated key.
    ///
    HMac() : key_()
    {
    }

    HMac(const HMac<H, N>& hmac) = delete;

    ///
    /// @brief Constructor
    ///
    /// Creates a HMac object from a kKeySize (= N) bytes key.
    /// After a call to the constructor, the input key is
    /// held by the HMac object, and cannot be re-used.
    ///
    /// @param key  The key used to initialize HMAC.
    ///             Upon return, k is empty
    ///
    explicit HMac(Key<kKeySize>&& key) : key_(std::move(key))
    {
        if (key_.is_empty()) {
            throw std::invalid_argument("Invalid key: key is empty");
        }
    }

    // deleted copy assignement operator
    HMac(HMac<H, N>&& hmac) noexcept = default;

    /// @brief Move assignment operator
    HMac<H, N>& operator=(HMac<H, N>&& hmac) noexcept = default;

    ///
    /// @brief Evaluate HMac
    ///
    /// Evaluates HMac on the input buffer and places the result in the
    /// output buffer (and truncates the result it if necessary).
    ///
    ///
    /// @param in       The input buffer. Must be non NULL.
    /// @param length   The size of the input buffer in bytes.
    /// @param out      The output buffer. Must be non NULL, and larger
    /// than
    ///                 out_len bytes.
    /// @param out_len  The size of the output buffer in bytes. Must be
    /// smaller
    ///                 than kDigestSize.
    ///
    /// @exception std::invalid_argument       One of in or out is NULL
    /// @exception std::invalid_argument       out_len is larger than
    /// kDigestSize
    ///
    void hmac(const unsigned char* in,
              const size_t         length,
              unsigned char*       out,
              const size_t         out_len = kDigestSize) const;

    ///
    /// @brief Evaluate HMac
    ///
    /// Evaluates HMac on the input buffer and returns the digest in an array.
    ///
    ///
    /// @param in       The input buffer. Must be non NULL.
    /// @param length   The size of the input buffer in bytes.
    ///
    /// @return         An std::array of kDigestSize bytes containing the digest
    ///
    /// @exception std::invalid_argument       in or out is NULL
    ///
    std::array<uint8_t, H::kDigestSize> hmac(const unsigned char* in,
                                             const size_t         length) const;

    ///
    /// @brief Evaluate HMac
    ///
    /// Evaluates HMac on the input string and returns the digest in an array.
    ///
    ///
    /// @param s        The input string.
    ///
    /// @return         An std::array of kDigestSize bytes containing the digest
    ///
    ///
    std::array<uint8_t, H::kDigestSize> hmac(const std::string& s) const;

private:
    Key<kKeySize> key_;
};


// HMac instantiation
template<class H, uint16_t N>
void HMac<H, N>::hmac(const unsigned char* in,
                      const size_t         length,
                      unsigned char*       out,
                      const size_t         out_len) const
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

    uint8_t*         buffer;
    size_t           i_len      = kHMACKeySize + length;
    constexpr size_t tmp_len    = kHMACKeySize + kDigestSize;
    size_t           buffer_len = (i_len > kDigestSize) ? i_len : (kDigestSize);

    buffer = new uint8_t[buffer_len];
    uint8_t tmp[tmp_len];

    key_.unlock();

    // copy the key to the buffer
    memcpy(buffer, key_.data(), kKeySize);

    // set the other bytes to 0x00
    if (kKeySize < kHMACKeySize) {
        memset(buffer + kKeySize, 0x00, kHMACKeySize - kKeySize);
    }

    // xor the magic number for input
    for (uint16_t i = 0; i < kHMACKeySize; ++i) {
        buffer[i] ^= 0x36;
    }

    memcpy(buffer + kHMACKeySize, in, length);

    H::hash(buffer, i_len, buffer);

    // prepend the key
    memcpy(tmp, key_.data(), kKeySize);
    // set the other bytes to 0x00
    if (kKeySize < kHMACKeySize) {
        memset(tmp + kKeySize, 0x00, kHMACKeySize - kKeySize);
    }

    // xor the magic number for output
    for (uint16_t i = 0; i < kHMACKeySize; ++i) {
        tmp[i] ^= 0x5c;
    }

    memcpy(tmp + kHMACKeySize, buffer, kDigestSize);

    H::hash(tmp, kHMACKeySize + kDigestSize, buffer);


    memcpy(out, buffer, out_len);

    sodium_memzero(buffer, buffer_len);
    delete[] buffer;

    sodium_memzero(tmp, tmp_len);

    key_.lock();
}

template<class H, uint16_t N>
std::array<uint8_t, H::kDigestSize> HMac<H, N>::hmac(const unsigned char* in,
                                                     const size_t length) const
{
    std::array<uint8_t, kDigestSize> result;

    hmac(in, length, result.data(), kDigestSize);
    return result;
}

// Convienience function to run HMac over a C++ string
template<class H, uint16_t N>
std::array<uint8_t, H::kDigestSize> HMac<H, N>::hmac(const std::string& s) const
{
    return hmac(reinterpret_cast<const unsigned char*>(s.data()), s.length());
}

} // namespace crypto
} // namespace sse

// Explicitely instantiate some templates for the code coverage
#ifdef CHECK_TEMPLATE_INSTANTIATION
#include "hash/sha512.hpp"
namespace sse {
namespace crypto {
extern template class HMac<hash::sha512, 25>;
}
} // namespace sse
#endif
