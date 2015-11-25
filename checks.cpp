#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE CRYPTO

#include <boost/test/unit_test.hpp>

#include "tests/test_ecmh.hpp"
#include "tests/hashing.hpp"
#include "tests/prf_hmac.hpp"
#include "tests/encryption.hpp"

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
