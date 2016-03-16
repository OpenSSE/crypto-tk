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

#pragma once

/*******
*  hashing.cpp
*
*  Implementation of SHA-512's test vector verification.
*  Reference vectors are taken from NIST's test vectors.
********/	

bool sha_512_test_vectors();

bool sha_512_vector_1();
bool sha_512_vector_2();
bool sha_512_vector_3();
bool sha_512_vector_4();
bool sha_512_vector_5();
