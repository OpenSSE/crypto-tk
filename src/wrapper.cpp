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

#include "wrapper.hpp"

#include <sodium/crypto_stream_chacha20.h>

namespace sse {
namespace crypto {

Wrapper::Wrapper(Key<kKeySize>&& key)
{
    static_assert(kKeySize == Prf<kTagSize>::kKeySize,
                  "Wrapper: incompatible key size");
    static_assert(kEncryptionKeySize == crypto_stream_chacha20_ietf_KEYBYTES,
                  "Wrapper: Invalid encryption key size");

    static_assert(
        kEncryptionKeySize == Prf<kTagSize>::kKeySize,
        "Wrapper: Incompatible encryption key size and tag-derivation "
        "PRF key size");

    static_assert(kTagSize == crypto_stream_chacha20_IETF_NONCEBYTES,
                  "Wrapper: Invalid tag size. The size of the tag size should "
                  "be the size of a Chacha20 nonce");

    Prf<kEncryptionKeySize> kdf(std::move(key));

    std::array<uint8_t, 1> derivation_input{{0x01}};

    tag_generator_ = Prf<kTagSize>(kdf.derive_key(derivation_input));

    derivation_input[0] = 0x02;
    encryption_key_     = kdf.derive_key(derivation_input);
}
} // namespace crypto
} // namespace sse
