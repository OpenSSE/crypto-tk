#include "prf_hmac.hpp"
#include "../src/cipher.hpp"


#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

bool encryption_decryption_test()
{
	string in_enc = "This is a test input.";
	string out_enc, out_dec;
	
	array<uint8_t,sse::crypto::Cipher::kKeySize> k;
	k.fill(0x00);
	
	sse::crypto::Cipher cipher(k);
	cipher.encrypt(in_enc, out_enc);
	
	string in_dec = string(out_enc);
	
	cipher.decrypt(in_dec, out_dec);
	
	if(in_enc != out_dec){
		cout << "Decryption output does not match original input\n";
		
		cout << "Original input: ( " << dec << in_enc.size() << " bytes) \n";
		for(uint8_t c : in_enc)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Encryption output : ( " << dec << out_enc.size() << " bytes) \n";
		for(uint8_t c : out_enc)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Decryption input : ( " << dec << in_dec.size() << " bytes) \n";
		for(uint8_t c : in_dec)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Decryption Output: ( " << dec << out_dec.size() << " bytes) \n";
		for(uint8_t c : out_dec)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		return false;
	}
	// cout << "Encryption/decryption test succeeded!\n";
	return true;
}