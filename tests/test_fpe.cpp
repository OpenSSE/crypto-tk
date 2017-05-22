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

#include "../src/fpe.hpp"


#include <iostream>
#include <iomanip>
#include <string>

#include "gtest/gtest.h"

using namespace std;


TEST(fpe, correctness) {
	string in_enc = "This is a test input.";
	string out_enc, out_dec;
	
	array<uint8_t,sse::crypto::Fpe::kKeySize> k;
	k.fill(0x00);
	
	sse::crypto::Fpe fpe(k);
	fpe.encrypt(in_enc, out_enc);
	
	ASSERT_EQ(in_enc.length(), out_enc.length());
	
	string in_dec = string(out_enc);
	
	fpe.decrypt(in_dec, out_dec);
	
    ASSERT_EQ(in_dec.length(), out_dec.length());
	ASSERT_EQ(in_enc, out_dec);
}
