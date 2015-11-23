#include "src/prf.hpp"

#include "tests/prf_hmac.hpp"
#include "tests/encryption.hpp"
#include "tests/hashing.hpp"

#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

typedef sse::crypto::PrfKey<16> PrfKey_16;
typedef sse::crypto::PrfKey<64> PrfKey_64;

int main( int argc, char* argv[] ) {

	hmac_tests();
	encryption_decryption_test();
	sha_512_256_test_vectors();
	return 0;	
}