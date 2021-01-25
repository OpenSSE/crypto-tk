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

#include "cipher.hpp"

#include "random.hpp"

#include <exception>
#include <vector>

#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/utils.h>

namespace sse {

namespace crypto {

#define NONCE_SIZE crypto_generichash_blake2b_SALTBYTES

// NOLINTNEXTLINE(modernize-avoid-c-arrays)
static constexpr uint8_t
    g_hash_personal_[crypto_generichash_blake2b_PERSONALBYTES]
    = "encryption_key";

static_assert(crypto_generichash_blake2b_KEYBYTES == Cipher::kKeySize,
              "Invalid Cipher key size");

static_assert(NONCE_SIZE + crypto_aead_chacha20poly1305_IETF_ABYTES
                  == Cipher::kCiphertextExpansion,
              "Invalid Cipher expansion constant");


Cipher::Cipher(Key<kKeySize>&& k) : key_(std::move(k))
{
}

// Compute maximum number of blocks that can be encrypted with the same key
// This number comes from the security reduction of CTR mode (2^48 blocks at
// most to retain 32 bits of security) and from the IV length (not more than
// 2^(8*kIVSize) different IVs)


void Cipher::encrypt(const unsigned char* in,
                     const size_t&        len,
                     unsigned char*       out) const
{
    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> chacha_key;
    unsigned long long c_len = 0; // NOLINT

    // generate a random nonce, and place it at the beginning of the output
    random_bytes(NONCE_SIZE, out);

    // unlock the master key
    key_.unlock();

    // start by deriving a subkey from the master and the nonce
    crypto_generichash_blake2b_salt_personal(chacha_key.data(),
                                             chacha_key.size(),
                                             nullptr,
                                             0,
                                             key_.data(),
                                             kKeySize,
                                             out,
                                             g_hash_personal_);

    // re-lock the master key
    key_.lock();

    // go for encryption with the derived key
    crypto_aead_chacha20poly1305_ietf_encrypt(out + NONCE_SIZE,
                                              &c_len,
                                              in,
                                              len,
                                              nullptr,
                                              0,
                                              nullptr,
                                              out,
                                              chacha_key.data());

    // delete the derived key
    sodium_memzero(chacha_key.data(), crypto_aead_chacha20poly1305_KEYBYTES);
}

void Cipher::encrypt(const std::string& in, std::string& out)
{
    if (in.empty()) {
        throw std::invalid_argument(
            "The minimum number of bytes to encrypt is 1.");
    }

    size_t         len   = in.size();
    size_t         c_len = ciphertext_length(len);
    unsigned char* data  = new unsigned char[c_len];

    encrypt(reinterpret_cast<const unsigned char*>(in.data()), len, data);
    out = std::string(reinterpret_cast<char*>(data), c_len);

    // erase the buffer
    sodium_memzero(data, c_len);

    delete[] data;
}

void Cipher::decrypt(const unsigned char* in,
                     const size_t&        len,
                     unsigned char*       out) const
{
    if (len < ciphertext_length(0)) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("The minimum number of bytes to decrypt is "
                                    + std::to_string(ciphertext_length(0)));
        /* LCOV_EXCL_STOP */
    }

    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> chacha_key;
    unsigned long long m_len = 0; // NOLINT

    // unlock the master key
    key_.unlock();

    // start by deriving a subkey from the master and the nonce
    crypto_generichash_blake2b_salt_personal(chacha_key.data(),
                                             chacha_key.size(),
                                             nullptr,
                                             0,
                                             key_.data(),
                                             kKeySize,
                                             in,
                                             g_hash_personal_);

    // re-lock the master key
    key_.lock();

    // go for decryption with the derived key
    int ret = crypto_aead_chacha20poly1305_ietf_decrypt(out,
                                                        &m_len,
                                                        nullptr,
                                                        in + NONCE_SIZE,
                                                        len - NONCE_SIZE,
                                                        nullptr,
                                                        0,
                                                        in,
                                                        chacha_key.data());

    // delete the derived key
    sodium_memzero(chacha_key.data(), crypto_aead_chacha20poly1305_KEYBYTES);

    if (ret == -1) { // invalid decryption
        // erase the decrypted plaintext
        sodium_memzero(out, m_len);

        throw std::runtime_error("Failed decryption. Invalid ciphertext");
    }
}

void Cipher::decrypt(const std::string& in, std::string& out)
{
    size_t len = in.size();

    if (len <= NONCE_SIZE + crypto_aead_chacha20poly1305_IETF_ABYTES) {
        throw std::invalid_argument("The minimum number of bytes to decrypt is "
                                    "1. The minimum length for a "
                                    "decryption input is kIVSize+1");
    }

    size_t p_len = plaintext_length(len);

    std::vector<uint8_t> data(p_len);
    decrypt(
        reinterpret_cast<const unsigned char*>(in.data()), len, data.data());

    out = std::string(reinterpret_cast<const char*>(data.data()), p_len);
}

void Cipher::serialize(uint8_t* out) const
{
    key_.unlock();
    key_.serialize(out);
    key_.lock();
}

Cipher Cipher::deserialize(uint8_t*     in,
                           const size_t in_size,
                           size_t&      n_bytes_read)
{
    if (in_size < kKeySize) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Cipher::deserialize: the deserialization "
                                    "buffer size should be Cipher::kKeySize.");
        /* LCOV_EXCL_STOP */
    }
    n_bytes_read += kKeySize;
    return Cipher(Key<kKeySize>(in));
}

} // namespace crypto
} // namespace sse
