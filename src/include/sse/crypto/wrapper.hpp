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
#include <sse/crypto/random.hpp>

#include <algorithm>
#include <array>

#include <sodium/crypto_stream_chacha20.h>
#include <sodium/utils.h>

namespace sse {
namespace crypto {

/// @class Wrapper
/// @brief Secure wrapping of cryptographic objects.
///
/// Wrapper is a class used to wrap (and unwrap) OpenSSE cryptographic objects.
/// It can be used to securely serialize and transmit such objects.
/// To do so, it implements nonce-misuse resistant authenticated encryption (a
/// variant of SIV with an additional random nonce).
///
class Wrapper
{
public:
    /// @brief Wrapper key size (in bytes)
    static constexpr size_t kKeySize = 32;

    /// @brief Size (in bytes) of the tag (which is also the synthetic IV)
    static constexpr uint16_t kTagSize = 12U;

    /// @brief Size (in bytes) of the random IV to be generated.
    static constexpr size_t kRandomIVSize = 16U;

    /// @brief Number of additional bytes in a ciphertext generated by a Wrapper
    static constexpr size_t kCiphertextExpansion = kTagSize + kRandomIVSize;

    Wrapper() = delete;


    ///
    /// @brief Constructor
    ///
    /// Creates a Wrapper object from a 32 bytes (256 bits) key.
    /// After a call to the constructor, the input key is
    /// held by the Wrapper object, and cannot be re-used.
    ///
    /// @param k    The key used to initialize the wrapper.
    ///             Upon return, k is empty
    ///
    Wrapper(Key<kKeySize>&& key);

    // deleted copy constructor and operator
    Wrapper(const Wrapper& w) = delete;
    Wrapper& operator=(const Wrapper& w) = delete;


    /// @brief Move constructor
    Wrapper(Wrapper&& w) = default;

    /// @brief Move assignment operator
    Wrapper& operator=(Wrapper&& w) = default;

    ///
    /// @brief Wrap a cryptographic object
    ///
    /// Wraps a cryptographic object by serializing it and encrypting its binary
    /// representation. Authenticated encryption is used to ensure
    /// confidentiality and integrity of the wrapped object.
    ///
    /// @tparam CryptoClass     The class of the object to be wrapped. The class
    ///                         must declare the kSerializedSize, and
    ///                         kPublicContextSize static
    ///                         variables and implement the void
    ///                         serialize(uint8_t*) const member function and
    ///                         std::array<uint8_t,
    ///                         kPublicContextSize>public_context() static
    ///                         function.
    ///                         The Wrapper::get_type_byte() static function
    ///                         must be specialized for CryptoClass.

    ///
    /// @param c    The object to be wrapped.
    ///
    /// @return A buffer containing the encrypted representation of the wrapped
    ///         object
    template<class CryptoClass>
    std::array<uint8_t, kCiphertextExpansion + CryptoClass::kSerializedSize>
    wrap(const CryptoClass& c) const;


    ///
    /// @brief Unwrap a cryptographic object
    ///
    /// Unwraps a cryptographic object by decrypting it and deserialize the
    /// result. Authenticated encryption is used to ensure confidentiality and
    /// integrity of the wrapped object, and the function throws if the
    /// ciphertext is invalid.
    ///
    /// @tparam CryptoClass     The class of the object to be wrapped. The class
    ///                         must declare the kSerializedSize, and
    ///                         kPublicContextSize static
    ///                         variables and implement the CryptoClass
    ///                         deserialize(uint8_t*) static function and
    ///                         std::array<uint8_t,
    ///                         kPublicContextSize>public_context() static
    ///                         function.
    ///                         The Wrapper::get_type_byte() static function
    ///                         must be specialized for CryptoClass.
    ///
    /// @param c    The buffer containing the encrypted representation of the
    ///             object.
    ///
    /// @return     The object represented by the encrypted buffer.
    ///
    /// @exception std::runtime_error   The decryption failed:
    ///                                 invalid tag
    ///
    template<class CryptoClass>
    CryptoClass unwrap(
        std::array<uint8_t,
                   kCiphertextExpansion + CryptoClass::kSerializedSize>& c_rep)
        const;


    template<class CryptoClass>
    static constexpr uint8_t get_type_byte();

private:
    static constexpr uint16_t kEncryptionKeySize = 32U;

    Prf<kTagSize>           tag_generator_;
    Key<kEncryptionKeySize> encryption_key_;
};

template<class CryptoClass>
std::array<uint8_t,
           Wrapper::kCiphertextExpansion + CryptoClass::kSerializedSize>
Wrapper::wrap(const CryptoClass& c) const
{
    constexpr size_t buffer_size = kRandomIVSize + CryptoClass::kSerializedSize
                                   + CryptoClass::kPublicContextSize
                                   + 1; // the +1 is for the mandatory type byte
    uint8_t* buffer = static_cast<uint8_t*>(sodium_malloc(buffer_size));
    // std::array<uint8_t, buffer_size> buffer;

    // put the random IV at the beggining
    random_bytes(kRandomIVSize, buffer);
    // put the type byte after the IV
    buffer[kRandomIVSize] = Wrapper::get_type_byte<CryptoClass>();
    // copy the AD

    if (CryptoClass::kPublicContextSize > 0) {
        std::array<uint8_t, CryptoClass::kPublicContextSize> public_context
            = CryptoClass::public_context();
        memcpy(buffer + kRandomIVSize + 1,
               public_context.data(),
               CryptoClass::kPublicContextSize);
    }
    // Serialize the object in the buffer
    constexpr size_t serialization_offset
        = +kRandomIVSize + 1 + CryptoClass::kPublicContextSize;
    c.serialize(buffer + serialization_offset);

    std::array<uint8_t, kCiphertextExpansion + CryptoClass::kSerializedSize>
        out;

    // copy the IV at the beggining of the output
    memcpy(out.data(), buffer, kRandomIVSize);

    // compute the tag and put it at the end of the ciphertext
    std::array<uint8_t, kTagSize> tag = tag_generator_.prf(buffer, buffer_size);
    std::copy_n(tag.begin(), kTagSize, out.end() - kTagSize);

    // encrypt the secret part of the buffer
    crypto_stream_chacha20_ietf_xor(out.data() + kRandomIVSize,
                                    buffer + serialization_offset,
                                    CryptoClass::kSerializedSize,
                                    tag.data(),
                                    encryption_key_.unlock_get());
    encryption_key_.lock();

    sodium_free(buffer);

    return out;
}

template<class CryptoClass>
CryptoClass Wrapper::unwrap(
    std::array<uint8_t,
               Wrapper::kCiphertextExpansion + CryptoClass::kSerializedSize>&
        c_rep) const
{
    constexpr size_t buffer_size = kRandomIVSize + CryptoClass::kSerializedSize
                                   + CryptoClass::kPublicContextSize
                                   + 1; // the +1 is for the mandatory type byte
    uint8_t* buffer = static_cast<uint8_t*>(sodium_malloc(buffer_size));
    // std::array<uint8_t, buffer_size> buffer;

    // copy the IV at the beggining of the buffer
    memcpy(buffer, c_rep.data(), kRandomIVSize);
    // std::copy_n(c_rep.begin(), kRandomIVSize, buffer.begin());

    // put the type byte after the IV
    buffer[kRandomIVSize] = Wrapper::get_type_byte<CryptoClass>();

    // copy the AD
    if (CryptoClass::kPublicContextSize > 0) {
        std::array<uint8_t, CryptoClass::kPublicContextSize> public_context
            = CryptoClass::public_context();
        memcpy(buffer + kRandomIVSize + 1,
               public_context.data(),
               CryptoClass::kPublicContextSize);
    }
    // put the expected tag in a dedicated array
    std::array<uint8_t, kTagSize> expected_tag;
    std::copy_n(c_rep.end() - kTagSize, kTagSize, expected_tag.begin());

    // decrypt the representation
    constexpr size_t serialization_offset
        = +kRandomIVSize + 1 + CryptoClass::kPublicContextSize;

    crypto_stream_chacha20_ietf_xor(buffer + serialization_offset,
                                    c_rep.data() + kRandomIVSize,
                                    CryptoClass::kSerializedSize,
                                    expected_tag.data(),
                                    encryption_key_.unlock_get());
    encryption_key_.lock();


    // re-compute the tag
    std::array<uint8_t, kTagSize> computed_tag
        = tag_generator_.prf(buffer, buffer_size);

    // check that the computed tag and the expected tag are the same
    if (sodium_memcmp(expected_tag.data(), computed_tag.data(), kTagSize)
        != 0) {
        throw std::runtime_error("Wrapper: decryption failed, invalid tag!");
    }

    // Deserialize the buffer
    CryptoClass c = CryptoClass::deserialize(buffer + kRandomIVSize + 1
                                             + CryptoClass::kPublicContextSize);


    // free the buffer and zero the entry
    sodium_free(buffer);
    sodium_memzero(c_rep.data(), c_rep.size());

    return c;
}

// template<size_t N>
// std::array<uint8_t, Wrapper::kCiphertextExpansion + N> Wrapper::encrypt_data(
//     const uint8_t* data,
//     const uint8_t* additional_data,
//     const size_t   ad_length)
// {
//     const size_t buffer_size = kRandomIVSize + N + ad_length;
//     uint8_t*     buffer = static_cast<uint8_t*>(sodium_malloc(buffer_size));

//     // put the random IV at the beggining
//     random_bytes(kRandomIVSize, buffer);
//     // copy the AD ...
//     memcpy(buffer + kRandomIVSize, additional_data, ad_length);
//     // ... and the message
//     memcpy(buffer + kRandomIVSize + ad_length, data, N);

//     std::array<uint8_t, kCiphertextExpansion + N> out;

//     // copy the tag at the beggining of the output
//     memcpy(out.data(), buffer, kRandomIVSize);
//     // compute the tag and put it at the end of the ciphertext
//     std::array<uint8_t, kTagSize> tag = tag_generator_.prf(buffer,
//     buffer_size); std::copy(tag.begin(), tag.end(), out.end() - kTagSize);

//     // encrypt the secret part of the buffer
//     crypto_stream_chacha20_ietf_xor(out.data() + kRandomIVSize,
//                                     buffer + kRandomIVSize,
//                                     N,
//                                     tag.data(),
//                                     encryption_key_.unlock_get());
//     encryption_key_.lock();

//     sodium_free(buffer);

//     return out;
// }

// Implementation of the get_type_byte() template

class Prg;
template<>
constexpr uint8_t Wrapper::get_type_byte<Prg>()
{
    return 0x01;
}


} // namespace crypto
} // namespace sse