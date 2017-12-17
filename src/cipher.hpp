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

#include "key.hpp"

#include <cstdint>

#include <array>
#include <string>

namespace sse {

namespace crypto {

/// @class Cipher
/// @brief Encryption and decryption.
///
/// Cipher is an opaque class for symmetric encryption and decryption.
/// It implements a Chacha20+Poly1305 with a nonce-derived key.
/// This allows for larger nonces (128 bits) than the original
/// Chacha20+Poly1305 construction (96 bits). As a consequence,
/// nonces can be randomly generated, and the Cipher object does not
/// need to keep a state to be secure.
///

class Cipher
{
public:
    /// @brief Cipher key size (in bytes)
    static constexpr uint8_t kKeySize = 32;

    Cipher() = delete;

    // we should not be able to duplicate Cipher objects
    Cipher(const Cipher& c)  = delete;
    Cipher(Cipher& c)        = delete;
    Cipher(const Cipher&& c) = delete;
    Cipher(Cipher&& c)       = delete;

    // Again, avoid any assignement of Cipher objects
    Cipher& operator=(const Cipher& h) = delete;
    Cipher& operator=(Cipher& h) = delete;

    ///
    /// @brief Constructor
    ///
    /// Creates a cipher from a 32 bytes (256 bits) key.
    /// After a call to the constructor, the input key is
    /// held by the Cipher object, and cannot be re-used.
    ///
    /// @param k    The key used to initialize the cipher.
    ///             Upon return, k is empty
    ///
    explicit Cipher(Key<kKeySize>&& k);

    ///
    /// @brief Destructor
    ///
    /// Destructs the Cipher object and erase its key.
    ///
    ///
    ~Cipher();

    ///
    /// @brief Encrypt a plaintext
    ///
    /// Computes the encryption of the input plaintext.
    ///
    /// @param in    The plaintext to be encrypted. in must be of size 1 at
    /// least (i.e. non-empty).
    /// @param out   The computed ciphertext.
    ///
    /// @exception std::invalid_argument The size of in is 0.
    ///
    void encrypt(const std::string& in, std::string& out);

    ///
    /// @brief Decrypt a ciphertext
    ///
    /// Computes the plaintext corresponding to the input ciphertext.
    ///
    /// @param in    The ciphertext to be decrypted. in must be of size 1 at
    /// least (i.e. non-empty).
    /// @param out   The computed plaintext.
    ///
    /// @exception std::invalid_argument in is smaller than the size of the
    /// nonce
    /// + the size of the tag.
    /// @exception std::runtime_error       The decryption failed: invalid tag
    ///
    void decrypt(const std::string& in, std::string& out);

    ///
    /// @brief Compute the length of a ciphertext
    ///
    /// Computes the size of the ciphertext returned by encrypt
    /// given the plaintext length.
    ///
    /// @param plaintext_len    Length of the plaintext to be encrypted.
    ///
    /// @return Length of the ciphertext, that is the length of the plaintext +
    /// the length of the nonce + the length of the tag
    ///
    static size_t ciphertext_length(const size_t plaintext_len) noexcept;

    ///
    /// @brief Compute the length of a plaintext
    ///
    /// Computes the size of the plaintext returned by decrypt
    /// given the ciphertext length when the decryption suceeds.
    ///
    /// @param c_len    Length of the ciphertext to be decrypted.
    ///
    /// @return Length of the plaintext, that is the length of the ciphertext -
    /// the length of the nonce - the length of the tag (or 0 if this quantity
    /// is negative)
    ///
    static size_t plaintext_length(const size_t c_len) noexcept;

private:
    /// @class CipherImpl
    /// @brief Hidden Cipher implementation
    class CipherImpl;
    CipherImpl* cipher_imp_; // opaque pointer
};

} // namespace crypto
} // namespace sse
