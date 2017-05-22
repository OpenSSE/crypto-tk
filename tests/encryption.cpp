//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2106 Raphael Bost
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


/*******
 *  encryption.cpp
 *
 *  Check that encryption is correctly inverted by decryption.
 *
 ********/

#include "../tests/encryption.hpp"

#include "../src/cipher.hpp"


#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

#include "gtest/gtest.h"


TEST(encryption, correctness)
{
	string in_enc = "This is a test input.";
	string out_enc, out_dec;
	
	array<uint8_t,sse::crypto::Cipher::kKeySize> k;
	k.fill(0x00);
	
	sse::crypto::Cipher cipher(k);
	cipher.encrypt(in_enc, out_enc);
	
	string in_dec = string(out_enc);
	
	cipher.decrypt(in_dec, out_dec);
	
    ASSERT_EQ(in_enc, out_dec);
}
