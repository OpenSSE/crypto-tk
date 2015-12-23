//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015 Raphael Bost
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

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE CRYPTO

#include <boost/test/unit_test.hpp>

#include "tests/test_ecmh.hpp"
#include "tests/hashing.hpp"
#include "tests/test_hmac.hpp"
#include "tests/encryption.hpp"
#include "tests/test_fpe.hpp"

BOOST_AUTO_TEST_CASE(ecmh_GLS254) {
	test_generic_multiset_hash();
}

BOOST_AUTO_TEST_CASE(sha_512) {
	BOOST_REQUIRE(sha_512_vector_1());
	BOOST_REQUIRE(sha_512_vector_2());
	BOOST_REQUIRE(sha_512_vector_3());
	BOOST_REQUIRE(sha_512_vector_4());
	BOOST_REQUIRE(sha_512_vector_5());
}

BOOST_AUTO_TEST_CASE(hmac_sha_512) {
	BOOST_REQUIRE(hmac_test_case_1());
	BOOST_REQUIRE(hmac_test_case_2());
	BOOST_REQUIRE(hmac_test_case_3());
	BOOST_REQUIRE(hmac_test_case_4());
}

BOOST_AUTO_TEST_CASE(encryption) {
	BOOST_REQUIRE(encryption_decryption_test());
}

BOOST_AUTO_TEST_CASE(fpe) {
	fpe_correctness_test();
}
