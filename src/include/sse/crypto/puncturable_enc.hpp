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

#include <array>
#include <memory>
#include <string>
#include <vector>

namespace sse {

namespace crypto {
/// @file puncturable_enc.hpp
///
/// Construct and define puncturable encryption

/// @defgroup punct Puncturable Encryption
///
/// Define and construct puncturable encryption
///
/// @{
///

/*****
 * Ppke class
 *
 * Opaque class for Puncturable Public Key Encryption.
 *
 * PPKE is implemented using Green-Miers scheme.
 ******/

namespace punct {
/// @brief Size of the puncturable encryption tags (in bytes)
constexpr static size_t kTagSize = 16;
/// @brief Type of a tag for puncturable encryption
using tag_type = std::array<uint8_t, kTagSize>;

/// @brief Size of a puncturable encryption key share (in bytes)
constexpr static size_t kKeyShareSize = 211;
/// @brief Type of a punctured key share for puncturable encryption
using key_share_type = std::array<uint8_t, kKeyShareSize>;
/// @brief Type of a punctured key for puncturable encryption
using punctured_key_type = std::vector<key_share_type>;

/// @brief Size of a puncturable encryption master key (in bytes)
const static size_t kMasterKeySize = 32;
/// @brief Type of a master key for puncturable encryption
using master_key_type = Key<kMasterKeySize>;

/// @relatesalso PuncturableEncryption
const static size_t kCiphertextSize = 90;
/// @brief Type of a ciphertext created using puncturable encryption
// cppcheck-suppress constStatement
using ciphertext_type = std::array<uint8_t, kCiphertextSize>;


/// @brief Extracts the tag associated to a key share
/// @relatesalso PuncturableEncryption
inline tag_type extract_tag(const key_share_type& keyshare)
{
    tag_type tag;
    std::copy(keyshare.end() - kTagSize, keyshare.end(), tag.begin());
    return tag;
}

/// @brief Extracts the tag associated to a ciphertext
/// @relatesalso PuncturableEncryption
inline tag_type extract_tag(const ciphertext_type& ciphertext)
{
    tag_type tag;
    std::copy(ciphertext.end() - kTagSize, ciphertext.end(), tag.begin());
    return tag;
}

} // namespace punct


/// @class PuncturableEncryption
/// @brief Puncturable encryption.
///
/// PuncturableEncryption is an opaque class implementing a puncturable
/// encryption scheme. It is based on the puncturable encryption scheme by Green
/// and Miers (see https://isi.jhu.edu/~mgreen/forward_sec.pdf for
/// more details). The actual encryption scheme implemented here is fully
/// described in the paper "Forward and Backward Private Searchable Encryption
/// from Constrained Cryptographic Primitives" by Bost, Minaud and Ohrimenko
/// (cf. https://eprint.iacr.org/2017/805.pdf)
///
class PuncturableEncryption
{
public:
    ///
    /// @brief Constructor
    ///
    /// Creates a PuncturableEncryption object from a kMasterKeySize (32) bytes
    /// key. After a call to the constructor, the input key is held by the
    /// PuncturableEncryption object, and cannot be re-used.
    ///
    /// @param key  The key used to initialize the PuncturableEncryption.
    ///             Upon return, key is empty
    ///
    explicit PuncturableEncryption(punct::master_key_type&& key);

    PuncturableEncryption(const PuncturableEncryption&) = delete;

    ///
    /// @brief Destructor
    ///
    ~PuncturableEncryption();

    // Avoid any assignment of decryption objects
    PuncturableEncryption& operator=(const PuncturableEncryption& h) = delete;

    ///
    /// @brief Encrypt a message
    ///
    /// Encrypts a 64 bits message using the input tag.
    /// The message can be decrypted with a punctured key whose associated tag
    /// set does not contain the tage used during the encryption
    ///
    /// @param m    The message to encrypt
    /// @param tag  The tag associated with the message
    ///
    /// @return     A ciphertext encrypting m and encoding tag
    ///
    punct::ciphertext_type encrypt(const uint64_t         m,
                                   const punct::tag_type& tag);

    ///
    /// @brief Generate the first keyshare of a punctured decryption key
    ///
    /// Generates (pseudo-randomly) the initial keyshare of a punctured key with
    /// d punctures.
    ///
    /// @param d    The number of punctures of the final punctured key
    ///
    /// @return     The initial keyshare (keyshare number 0) in any punctured
    ///             decryption key for the current PuncturableEncryption object
    ///             with d punctures
    ///
    punct::key_share_type initial_keyshare(const size_t d);


    ///
    /// @brief  Incrementally generates a new keyshare of a punctured decryption
    ///         key
    ///
    /// Generates (pseudo-randomly) the d-th keyshare of a punctured key.
    ///
    /// @param d    The number of punctures of the final punctured key
    /// @param tag  The tag associated to the new keyshare. The tag MUST be
    ///             different from the NULL tag {{0x00, 0x01, 0x02, 0x03, 0x04,
    ///             0x05, 0x06, 0x07, 0x08, 0x10, 0x11, 0x12, 0x13, 0x14,
    ///             0x15}}.
    ///
    /// @return     The d-th keyshare of a punctured decryption key for the
    ///             current PuncturableEncryption object with d punctures
    ///
    /// @exception  std::invalid_argument   The input tag is the NULL tag.
    ///
    ///
    ///
    punct::key_share_type inc_puncture(const size_t           d,
                                       const punct::tag_type& tag);

private:
    /// @class PEncImpl
    /// @brief Hidden puncturable encryption implementation
    class PEncImpl;

    std::unique_ptr<PEncImpl> penc_imp_; // opaque pointer
};

/// @class PuncturableDecryption
/// @brief Decryption of ciphertexts generated using puncturable encryption.
///
/// PuncturableDecryption is an opaque class implementing the decryption
/// algorithm of the puncturable encryption implemented by
/// PuncturableEncryption.
///
///
class PuncturableDecryption
{
public:
    ///
    /// @brief Constructor
    ///
    /// Creates a PuncturableDecryption object from a punctured_key, i.e. from
    /// a list of keyshares (cf. the description of punct::punctured_key_type).
    ///
    /// @param punctured_key    The list of keyshare used to initialize the
    ///                         PuncturableDecryption object.
    ///
    explicit PuncturableDecryption(
        const punct::punctured_key_type& punctured_key);

    PuncturableDecryption(const PuncturableDecryption&) = delete;

    // Avoid any assignment of decryption objects
    PuncturableDecryption& operator=(const PuncturableDecryption& h) = delete;


    ///
    /// @brief Destructor
    ///
    ~PuncturableDecryption();

    ///
    /// @brief Encrypt a message
    ///
    /// Encrypts a 64 bits message using the input tag.
    /// The message can be decrypted with a punctured key whose associated tag
    /// set does not contain the tage used during the encryption
    ///
    /// @param ct   The ciphertext to decrypt
    /// @param m    The result of the decryption
    ///
    /// @return     true if the decryption succeeded, false if the tag with
    ///             which the message was encrypted was punctured.
    ///
    bool decrypt(const punct::ciphertext_type& ct, uint64_t& m);

private:
    /// @class PDecImpl
    /// @brief Hidden puncturable decryption implementation
    class PDecImpl;

    std::unique_ptr<PDecImpl> pdec_imp_; // opaque pointer
};

///
/// @} // end of group punct
///

} // namespace crypto
} // namespace sse
