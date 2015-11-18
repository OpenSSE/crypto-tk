#include "src/prf.hpp"

#include "tests/prf_hmac.hpp"

#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

typedef sse::crypto::PrfKey<16> PrfKey_16;
typedef sse::crypto::PrfKey<64> PrfKey_64;

int main( int argc, char* argv[] ) {

	hmac_tests();
	
	return 0;	
}