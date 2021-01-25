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


#include "prg.hpp"

#include <cassert>
#include <cstring>

#include <sodium/crypto_stream_chacha20.h>


// ChaCha is not really a all-in-one stream cipher (like RC4/Trivium/Grain)
// It is just a block cipher in counter mode
// To improve the performance and be able to jump to the right offset,
// we have to use the block size (64 bytes)
#define CHACHA20_BLOCK_SIZE 64

// static nonce
static const std::array<uint8_t, 8> chacha_nonce
    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

namespace sse {

namespace crypto {

static void prg_derivation(const unsigned char* key,
                           const size_t         offset,
                           const size_t         len,
                           unsigned char*       out)
{
    if (out == nullptr) {
        throw std::invalid_argument("out is NULL");
    }

    if (len == 0) {
        return; /* LCOV_EXCL_LINE */
    }

    const size_t mod_offset      = (offset % CHACHA20_BLOCK_SIZE);
    const size_t block_offset    = offset / CHACHA20_BLOCK_SIZE;
    const size_t max_block_index = (len + offset - 1) / CHACHA20_BLOCK_SIZE + 1;

    const size_t block_len = max_block_index - block_offset;

    memset(out, 0, len);

    if (offset % CHACHA20_BLOCK_SIZE == 0) {
        // things are aligned, good !
        crypto_stream_chacha20_xor_ic(
            out, out, len, chacha_nonce.data(), block_offset, key);
    } else {
        std::array<unsigned char, CHACHA20_BLOCK_SIZE> buffer;
        memset(buffer.data(), 0, CHACHA20_BLOCK_SIZE);

        size_t prefix_len = CHACHA20_BLOCK_SIZE - mod_offset;
        // start by generating the inner blocks
        if (block_len > 1) {
            const size_t tmp_len = len - prefix_len;
            crypto_stream_chacha20_xor_ic(out + prefix_len,
                                          out + prefix_len,
                                          tmp_len,
                                          chacha_nonce.data(),
                                          block_offset + 1,
                                          key);
        } else {
            // The output is just the prefix
            // We must cut the output before the end of the block
            prefix_len = len;
        }
        // Now, we have to generate the first bytes of out
        // These are the last out_offset bytes of the block index block_offset

        crypto_stream_chacha20_xor_ic(buffer.data(),
                                      buffer.data(),
                                      CHACHA20_BLOCK_SIZE,
                                      chacha_nonce.data(),
                                      block_offset,
                                      key);

        // copy these last bytes
        memcpy(out, buffer.data() + mod_offset, prefix_len);

        // zeroize the buffer
        sodium_memzero(buffer.data(), CHACHA20_BLOCK_SIZE);
    }
}


void Prg::derive(const size_t offset, const size_t len, std::string& out) const
{
    unsigned char* data = new unsigned char[len];

    derive(offset, len, data);
    out = std::string(reinterpret_cast<char*>(data), len);

    // erase the buffer
    sodium_memzero(data, len);

    delete[] data;
}

std::string Prg::derive(const size_t offset, const size_t len) const
{
    std::string out;

    derive(offset, len, out);

    return out;
}

void Prg::derive(const size_t   offset,
                 const size_t   len,
                 unsigned char* out) const
{
    if (len == 0) {
        return;
    }

    prg_derivation(key_.unlock_get(), offset, len, out);
    key_.lock();
}

void Prg::derive(Key<kKeySize>&& k, const size_t len, std::string& out)
{
    std::vector<uint8_t> data(len);

    derive(std::move(k), 0, len, data.data());
    out = std::string(reinterpret_cast<const char*>(data.data()), len);

    // erase the buffer
    sodium_memzero(data.data(), len);
}

void Prg::derive(Key<kKeySize>&& k,
                 const size_t    offset,
                 const size_t    len,
                 unsigned char*  out)
{
    if (k.is_empty()) {
        throw std::invalid_argument("PRG input key is empty");
    }

    Key<kKeySize> local_key(
        std::move(k)); // make sure the input key cannot be reused

    prg_derivation(local_key.unlock_get(), offset, len, out);

    local_key.lock();
}

void Prg::derive(Key<kKeySize>&& k,
                 const size_t    offset,
                 const size_t    len,
                 std::string&    out)
{
    unsigned char* data = new unsigned char[len];

    derive(std::move(k), offset, len, data);
    out = std::string(reinterpret_cast<char*>(data), len);

    // erase the buffer
    sodium_memzero(data, len);

    delete[] data;
}

std::string Prg::derive(Key<kKeySize>&& k,
                        const size_t    offset,
                        const size_t    len)
{
    unsigned char* data = new unsigned char[len];

    derive(std::move(k), offset, len, data);
    std::string out = std::string(reinterpret_cast<char*>(data), len);

    // erase the buffer
    sodium_memzero(data, len);

    delete[] data;
    return out;
}

Prg Prg::duplicate() const
{
    std::array<uint8_t, kKeySize> buffer;

    memcpy(buffer.data(), key_.unlock_get(), kKeySize);
    key_.lock();

    return Prg(Key<kKeySize>(buffer.data()));
}

void Prg::serialize(uint8_t* out) const
{
    key_.unlock();
    key_.serialize(out);
    key_.lock();
}

Prg Prg::deserialize(uint8_t* in, const size_t in_size, size_t& n_bytes_read)
{
    if (in_size < kKeySize) {
        /* LCOV_EXCL_START */
        throw std::invalid_argument("Prg::deserialize: the deserialization "
                                    "buffer size should be Prg::kKeySize.");
        /* LCOV_EXCL_STOP */
    }
    n_bytes_read = kKeySize;
    return Prg(Key<kKeySize>(in));
}

} // namespace crypto

} // namespace sse

/* Instantiate some of the useful template sizes */

INSTANTIATE_PRG_TEMPLATE(16)
INSTANTIATE_PRG_TEMPLATE(32)

#ifdef CHECK_TEMPLATE_INSTANTIATION
#pragma message "Instantiate templates for unit tests and code coverage"
/* To avoid file duplication in code coverage report */

INSTANTIATE_PRG_TEMPLATE(10)
INSTANTIATE_PRG_TEMPLATE(18)
#endif
