//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2016 Raphael Bost
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

#include "../tests/test_block_hash.hpp"
#include "../src/block_hash.hpp"

#include <array>
#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>

#include "boost_test_include.hpp"

#define TEST_COUNT 2

void test_block_hash()
{
    std::array<uint8_t, 16> in_array = {{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}};

    std::array<uint8_t, 16> expected_out = {{0x51, 0x16, 0xc5, 0x56, 0x23, 0x3a, 0xa9, 0xf6, 0x41, 0xa3, 0xb4, 0xe2, 0x57, 0xf5, 0xf8, 0xbd}};

    std::string in(in_array.begin(), in_array.end());
    
    std::string  out = sse::crypto::BlockHash::hash(in);
    

    BOOST_CHECK(out == std::string(expected_out.begin(), expected_out.end()));

}
