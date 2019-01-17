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
#include <cstdint>

namespace sse {
namespace crypto {
///
/// @brief Initialize the library
///
/// init_crypto_lib needs to be called before using any component of
/// libsse_crypto.
///
void init_crypto_lib();

///
/// @brief Cleanup the library
///
/// Properly cleans up the library.
///
void cleanup_crypto_lib();

const uint8_t* strstrn_uint8(const uint8_t* str1,
                             const size_t   str1_len,
                             const uint8_t* str2,
                             const size_t   str2_len);

} // namespace crypto
} // namespace sse
