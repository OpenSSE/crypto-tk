#include "src/prf.hpp"



#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

typedef sse::crypto::PrfKey<16> PrfKey_16;
typedef sse::crypto::PrfKey<64> PrfKey_64;

int main( int argc, char* argv[] ) {

	// array<uint8_t,PrfKey_16::kKeySize> k = { {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
								// 0x0c, 0x0d, 0x0e, 0x0f } };
	
	array<uint8_t,PrfKey_64::kKeySize> k;
	k.fill(0x0b);
	
	
	// PrfKey_16 key(k);
	PrfKey_16 key_16(k.data(),20);
	PrfKey_64 key_64(k.data(),20);	
	
	
	
	
	
	string in = "Hi There";
	
	cout << "Test vectors for PRF with output size 16\n";
	
	array<uint8_t,16> result_16 = sse::crypto::prf<16>(key_16, in);
	
	for(uint8_t c : result_16)
	{
		cout << hex << setw(2) << setfill('0') << (uint) c;
	}
	cout << endl;
	
	cout << "Test vectors for PRF with output size 64\n";
	
	array<uint8_t,64> result_64 = sse::crypto::prf<64>(key_64, in);
	
	for(uint8_t c : result_64)
	{
		cout << hex << setw(2) << setfill('0') << (uint) c;
	}
	cout << endl;
	return 0;	
}