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

#include <cstdint>

#include <array>
#include <memory>
#include <string>
#include <vector>

#include <sodium/utils.h>

namespace sse {
namespace crypto {

// forward declare a template
template<uint16_t NBYTES>
class ConstrainedRCPrfInnerElement;

/// @class Prg
/// @brief Pseudorandom generator.
///
/// The Prg templates realizes a pseudorandom generator (PRG) using the Chacha20
/// stream cipher. It can be used to derive keys from a master key.
///
class Prg
{
    template<uint16_t NBYTES>
    friend class ConstrainedRCPrfInnerElement;
    template<uint16_t NBYTES>
    friend class RCPrf;

    friend class Wrapper;

public:
    /// @brief Size (in bytes) of a PRG key
    static constexpr uint8_t kKeySize = 32;

    /// @brief  Size (in bytes) of the public context (used to wrap a Prg
    ///         object).
    static constexpr size_t kPublicContextSize = 0;

    /// @brief The public context of a Prg object. It is an empty array.
    static constexpr std::array<uint8_t, kPublicContextSize> public_context()
    {
        // GCC (4.8) does not support using {} instead of
        // std::array<uint8_t, kPublicContextSize>()
        // NOLINTNEXTLINE(modernize-return-braced-init-list)
        return std::array<uint8_t, kPublicContextSize>();
    }

    Prg() = delete;
    ///
    /// @brief Constructor
    ///
    /// Creates a Prg object from a kKeySize (32) bytes key.
    /// After a call to the constructor, the input key is
    /// held by the Prg object, and cannot be re-used.
    ///
    /// @param k    The key used to initialize the PRG.
    ///             Upon return, k is empty
    ///
    explicit Prg(Key<kKeySize>&& k) : key_(std::move(k))
    {
    }

    ///
    /// @brief Move constructor
    ///
    /// @param c The moved PRG
    ///
    Prg(Prg&& c) noexcept = default;

    // we should not be able to duplicate Prg objects
    Prg(const Prg& c) = delete;

    // Avoid any assignement of Prg objects
    Prg& operator=(const Prg& h) = delete;
    Prg& operator=(Prg& h) = delete;

    ///
    /// @brief Generate a pseudorandom string
    ///
    /// Fills the out string with len pseudorandom bytes.
    ///
    ///
    /// @param len      The number of pseudo-random bytes to generate.
    /// @param out      The output string.
    ///
    inline void derive(const size_t len, std::string& out) const
    {
        derive(0, len, out);
    }

    ///
    /// @brief Generate and return a pseudorandom string
    ///
    /// Returns a string with len pseudorandom bytes.
    ///
    ///
    /// @param len      The number of pseudo-random bytes to generate.
    /// @return         A len-bytes string filled with random bytes.
    ///
    inline std::string derive(const size_t len) const
    {
        return derive(0, len);
    }

    ///
    /// @brief Generate a pseudorandom string
    ///
    /// Fills the out string with len pseudorandom bytes, skipping the offset of
    /// the pseudo-random generation.
    ///
    ///
    /// @param offset   The number of bytes to skip in the pseudo-random
    ///                 sequence.
    /// @param len      The number of pseudo-random bytes to generate.
    /// @param out      The output string.
    ///
    void derive(const size_t offset, const size_t len, std::string& out) const;
    ///
    /// @brief Generate and return a pseudorandom string
    ///
    /// Returns a string with len pseudorandom bytes, skipping the first
    /// offset bytes of the pseudo-random generation.
    ///
    ///
    /// @param offset   The number of bytes to skip in the pseudo-random
    ///                 sequence.
    /// @param len      The number of pseudo-random bytes to generate.
    /// @return         A len-bytes string filled with random bytes.
    ///
    std::string derive(const size_t offset, const size_t len) const;

    ///
    /// @brief Fills buffer with pseudorandom bytes
    ///
    /// Fills the out buffer with len pseudorandom bytes, skipping the first
    /// offset bytes of the pseudo-random generation.
    ///
    ///
    /// @param offset   The number of bytes to skip in the pseudo-random
    ///                 sequence.
    /// @param len      The number of pseudo-random bytes to generate.
    /// @param out      The output buffer. Must not be NULL
    ///
    /// @exception std::invalid_argument       out is NULL
    ///
    void derive(const size_t   offset,
                const size_t   len,
                unsigned char* out) const;

    ///
    /// @brief Generate a pseudorandom string from the input seed
    ///
    /// Fills the out string with len pseudorandom bytes using k as a seed.
    ///
    ///
    /// @param k        The seed of the pseudo-random generation. After the call
    ///                 completes, k is empty
    /// @param len      The number of pseudo-random bytes to generate.
    /// @param out      The output string.
    ///
    static void derive(Key<kKeySize>&& k, const size_t len, std::string& out);

    ///
    /// @brief Generate a pseudorandom string from the input seed
    ///
    /// Fills the out string with len pseudorandom bytes, skipping the first
    /// offset bytes of the pseudo-random generation, using k as a seed.
    ///
    ///
    /// @param k        The seed of the pseudo-random generation. After the call
    ///                 completes, k is empty
    /// @param offset   The number of bytes to skip in the pseudo-random
    ///                 sequence.
    /// @param len      The number of pseudo-random bytes to generate.
    /// @param out      The output string.
    ///
    static void derive(Key<kKeySize>&& k,
                       const size_t    offset,
                       const size_t    len,
                       std::string&    out);

    ///
    /// @brief Fills a buffer with pseudorandom bytes from the input seed
    ///
    /// Fills the out buffer with len pseudorandom bytes, skipping the first
    /// offset bytes of the pseudo-random generation, using k as a seed.
    ///
    ///
    /// @param k        The seed of the pseudo-random generation. After the call
    ///                 completes, k is empty
    /// @param offset   The number of bytes to skip in the pseudo-random
    ///                 sequence.
    /// @param len      The number of pseudo-random bytes to generate.
    /// @param out      The output buffer. Must not be NULL.
    ///
    /// @exception std::invalid_argument       out is NULL
    ///
    static void derive(Key<kKeySize>&& k,
                       const size_t    offset,
                       const size_t    len,
                       unsigned char*  out);

    ///
    /// @brief Generate and return a pseudorandom string from the input seed
    ///
    /// Returns a string with len pseudorandom bytes, using k as a seed.
    ///
    ///
    /// @param k        The seed of the pseudo-random generation. After the call
    ///                 completes, k is empty
    /// @param len      The number of pseudo-random bytes to generate.
    /// @return         A len-bytes string filled with random bytes.
    ///
    static inline std::string derive(Key<kKeySize>&& k, const size_t len)
    {
        return derive(std::move(k), 0, len);
    }

    ///
    /// @brief Generate and return a pseudorandom string from the input seed
    ///
    /// Returns a string with len pseudorandom bytes, skipping the first
    /// offset bytes of the pseudo-random generation, using k as a seed.
    ///
    ///
    /// @param k        The seed of the pseudo-random generation. After the call
    ///                 completes, k is empty
    /// @param offset   The number of bytes to skip in the pseudo-random
    ///                 sequence.
    /// @param len      The number of pseudo-random bytes to generate.
    /// @return         A len-bytes string filled with random bytes.
    ///
    static std::string derive(Key<kKeySize>&& k,
                              const size_t    offset,
                              const size_t    len);

    ///
    /// @brief Derive a key
    ///
    /// Returns a pseudo-randomly generated key. The pseudo-random stream is cut
    /// in blocks of K bytes and the key_offset-th block is used to initialize
    /// the key (starting from block 0).
    ///
    /// @tparam K           The size of the generated key.
    ///
    /// @param key_offset   The number of the block used to initialize the key.
    ///
    /// @return             A new pseudo-randomly generated key.
    ///
    template<size_t K>
    Key<K> derive_key(const uint16_t key_offset) const;

    ///
    /// @brief Derive multiple keys
    ///
    /// Returns a vector of pseudo-randomly generated keys.
    /// The pseudo-random stream is cut in blocks of K bytes and the blocks
    /// number key_offset to key_offset+n_keys are used to initialize the keys.
    ///
    /// @tparam K           The size of the generated keys.
    ///
    /// @param n_keys       The number of keys to generate.
    /// @param key_offset   The number of the block used to initialize the key.
    ///
    /// @return             A vectore of pseudo-randomly generated keys.
    ///
    template<size_t K>
    std::vector<Key<K>> derive_keys(const uint16_t n_keys,
                                    const uint16_t key_offset = 0);


    ///
    /// @brief Derive a key from a seed
    ///
    /// Returns a key pseudo-randomly generated using a seed. The pseudo-random
    /// stream is cut in blocks of K bytes and the key_offset-th block is used
    /// to initialize the key (starting from block 0).
    ///
    /// @tparam K           The size of the generated key.
    ///
    /// @param k            The seed of the pseudo-random generation. After the
    ///                     call completes, k is empty.
    /// @param key_offset   The number of the block used to initialize the key.
    ///
    /// @return             A new pseudo-randomly generated key.
    ///
    template<size_t K>
    static Key<K> derive_key(Key<kKeySize>&& k, const uint16_t key_offset);

    ///
    /// @brief Derive multiple keys from a seed
    ///
    /// Returns a vector of pseudo-randomly generated keys, given an input seed.
    /// The pseudo-random stream is cut in blocks of K bytes and the blocks
    /// number key_offset to key_offset+n_keys are used to initialize the keys.
    ///
    /// @tparam K           The size of the generated keys.
    ///
    /// @param k            The seed of the pseudo-random generation. After the
    ///                     call completes, k is empty.
    /// @param n_keys       The number of keys to generate.
    /// @param key_offset   The number of the block used to initialize the key.
    ///
    /// @return             A vectore of pseudo-randomly generated keys.
    ///
    template<size_t K>
    static std::vector<Key<K>> derive_keys(Key<kKeySize>&& k,
                                           const uint16_t  n_keys,
                                           const uint16_t  key_offset = 0);

    ///
    /// @brief Fills an array with pseudorandom bytes from the input seed
    ///
    /// Fills the out array with N pseudorandom bytes, skipping the first
    /// offset bytes of the pseudo-random generation, using k as a seed.
    ///
    /// @tparam N       The number of pseudo-random bytes to generate.
    ///
    /// @param k        The seed of the pseudo-random generation. After the call
    ///                 completes, k is empty
    /// @param offset   The number of bytes to skip in the pseudo-random
    ///                 sequence.
    /// @param out      The output array.
    ///
    ///
    template<size_t N>
    static inline void derive(Key<kKeySize>&&         k,
                              const size_t            offset,
                              std::array<uint8_t, N>& out)
    {
        derive(std::move(k), offset, N, out.data());
    }

private:
    Prg duplicate() const;

    /// @brief  Returns the size (in bytes) of the serialized representation of
    ///         the object
    ///
    /// @return The size in bytes of the buffer needed to serialize the object.
    ///
    size_t serialized_size() const noexcept
    {
        return kKeySize;
    }

    /// @brief Serialize the object in the given buffer
    ///
    /// @param[out] out The serialization buffer. It must be
    ///                 at least kSerializedSize bytes large.
    void serialize(uint8_t* out) const;

    /// @brief Deserialize a buffer into a Prg object
    ///
    /// This static function constructs a new Prg object out of the binary
    /// representation of the input buffer in. The in buffer must be at least
    /// kSerializedSize bytes large.
    ///
    /// @param  in      The byte buffer containing the binary representation of
    ///                 the Prg object.
    /// @param  in_size The size of the in buffer.
    /// @param  n_bytes_read    The number of bytes from in read during the
    ///                         deserialization
    ///
    /// @exception  std::invalid_argument   The size of the in buffer (in_size)
    ///                                     is smaller than kKeySize
    static Prg deserialize(uint8_t*     in,
                           const size_t in_size,
                           size_t&      n_bytes_read);

    Key<kKeySize> key_;
};

template<size_t K>
Key<K> Prg::derive_key(const uint16_t key_offset) const
{
    static_assert(K < SIZE_MAX, "K is too large: K < SIZE_MAX");

    if (key_offset > static_cast<size_t>(0U)
        && K >= static_cast<size_t>(SIZE_MAX) / key_offset) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Key offset too large."
                                    " key_offset*K >= SIZE_MAX.");
        /* LCOV_EXCL_STOP */
    }

    auto fill_callback = [this, key_offset](uint8_t* key_content) {
        this->derive(key_offset * K, K, key_content);
    };

    return Key<K>(fill_callback);
}

template<size_t K>
Key<K> Prg::derive_key(Key<kKeySize>&& k, const uint16_t key_offset)
{
    static_assert(K < SIZE_MAX, "K is too large: K < SIZE_MAX");

    if (key_offset > static_cast<size_t>(0U)
        && K >= static_cast<size_t>(SIZE_MAX) / key_offset) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Key offset too large."
                                    " key_offset*K >= SIZE_MAX.");
        /* LCOV_EXCL_STOP */
    }

    auto fill_callback = [&k, key_offset](uint8_t* key_content) {
        derive(std::move(k), key_offset * K, K, key_content);
    };

    return Key<K>(fill_callback);
}

template<size_t K>
std::vector<Key<K>> Prg::derive_keys(const uint16_t n_keys,
                                     const uint16_t key_offset)
{
    if (n_keys > static_cast<size_t>(0U)
        && K >= static_cast<size_t>(SIZE_MAX) / n_keys) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Too many keys to derive. "
                                    "n_keys*K >= SIZE_MAX.");
        /* LCOV_EXCL_STOP */
    }
    if (key_offset > static_cast<size_t>(0U)
        && K >= static_cast<size_t>(SIZE_MAX) / key_offset) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Key offset too large."
                                    " key_offset*K >= SIZE_MAX.");
        /* LCOV_EXCL_STOP */
    }

    if (n_keys == 0) {
        return std::vector<Key<K>>(); // return empty vector
    }

    uint8_t* key_buffer
        = reinterpret_cast<uint8_t*>(sodium_allocarray(n_keys, K));

    this->derive(key_offset * K, n_keys * K, key_buffer);

    std::vector<Key<K>> derived_keys;

    for (uint16_t i = 0; i < n_keys; i++) {
        derived_keys.push_back(Key<K>(key_buffer + i * K));
    }

    sodium_free(key_buffer);

    return derived_keys;
}


template<size_t K>
std::vector<Key<K>> Prg::derive_keys(Key<kKeySize>&& k,
                                     const uint16_t  n_keys,
                                     const uint16_t  key_offset)
{
    if (k.is_empty()) {
        throw std::invalid_argument("PRG input key is empty");
    }
    if (n_keys == 0) {
        return std::vector<Key<K>>(); // return empty vector
    }
    if (n_keys > static_cast<size_t>(0U)
        && K >= static_cast<size_t>(SIZE_MAX) / n_keys) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Too many keys to derive. "
                                    "n_keys*K >= SIZE_MAX.");
        /* LCOV_EXCL_STOP */
    }
    if (key_offset > static_cast<size_t>(0U)
        && K >= static_cast<size_t>(SIZE_MAX) / key_offset) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Key offset too large."
                                    " key_offset*K >= SIZE_MAX.");
        /* LCOV_EXCL_STOP */
    }


    uint8_t* key_buffer
        = reinterpret_cast<uint8_t*>(sodium_allocarray(n_keys, K));

    derive(std::move(k), key_offset * K, n_keys * K, key_buffer);

    std::vector<Key<K>> derived_keys;

    for (uint16_t i = 0; i < n_keys; i++) {
        derived_keys.push_back(Key<K>(key_buffer + i * K));
    }

    sodium_free(key_buffer);

    return derived_keys;
}

} // namespace crypto
} // namespace sse

/* Instantiation declaration of some of the templates */

#define INSTANTIATE_PRG_TEMPLATE_EXTERN(N)                                     \
    namespace sse {                                                            \
    namespace crypto {                                                         \
    extern template std::vector<Key<(N)>> Prg::derive_keys(                    \
        const uint16_t n_keys,                                                 \
        const uint16_t key_offset);                                            \
    extern template Key<N> Prg::derive_key(const uint16_t key_offset) const;   \
    extern template Key<N> Prg::derive_key(Key<kKeySize>&& k,                  \
                                           const uint16_t  key_offset);         \
    extern template std::vector<Key<(N)>> Prg::derive_keys(                    \
        Key<kKeySize>&& k,                                                     \
        const uint16_t  n_keys,                                                \
        const uint16_t  key_offset = 0);                                        \
    }                                                                          \
    }

#define INSTANTIATE_PRG_TEMPLATE(N)                                            \
    namespace sse {                                                            \
    namespace crypto {                                                         \
    template std::vector<Key<(N)>> Prg::derive_keys(                           \
        const uint16_t n_keys,                                                 \
        const uint16_t key_offset);                                            \
    template Key<N> Prg::derive_key(const uint16_t key_offset) const;          \
    template Key<N> Prg::derive_key(Key<kKeySize>&& k,                         \
                                    const uint16_t  key_offset);                \
    template std::vector<Key<(N)>> Prg::derive_keys(Key<kKeySize>&& k,         \
                                                    const uint16_t  n_keys,    \
                                                    const uint16_t  key_offset \
                                                    = 0);                      \
    }                                                                          \
    }


INSTANTIATE_PRG_TEMPLATE_EXTERN(16)
INSTANTIATE_PRG_TEMPLATE_EXTERN(32)
