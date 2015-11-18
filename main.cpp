#include "src/prf.hpp"



#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

typedef sse::crypto::PrfKey<16> PrfKey_16;

int main( int argc, char* argv[] ) {

	array<uint8_t,PrfKey_16::kKeySize> k = { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 
								0x0c, 0x0d, 0x0e, 0x0f } };
	
	PrfKey_16 key(k);
	
	string in = "toto";
	array<uint8_t,16> result = sse::crypto::prf<16>(key, in);
	
	for(uint8_t c : result)
	{
		cout << hex << setw(2) << setfill('0') << (uint) c;
	}
	cout << endl;
	return 0;	
}