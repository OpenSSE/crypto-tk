#include "hashing.hpp"
#include "../src/hash.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <array>

using namespace std;

bool sha_512_256_test_vectors()
{
	return sha_512_256_vector_1() && sha_512_256_vector_2() && sha_512_256_vector_3()&& sha_512_256_vector_4() && sha_512_256_vector_5();
}

bool sha_512_256_vector_1()
{
	string in = "abc";
	string out = sse::crypto::Hash::hash(in);
	
	uint8_t reference[] = {
					0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
					0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a
				};
												
	if(out != string((char*)reference, 32))
	{
		cout << "Test case 1 failed!\n";
		cout << "Input (" << dec << in.length() << " bytes):\n";
		cout << in << "\n";
		cout << "Reference: \n";
		for(uint8_t c : reference)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Computed: \n";
		for(uint8_t c : out)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
	
		return false;
	}
	
	cout << "SHA-512/256 Test case 1 succeeded!\n";
	return true;
}

bool sha_512_256_vector_2()
{
	string in = "";
	string out = sse::crypto::Hash::hash(in);
	
	uint8_t reference[] = {
					0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 
					0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce
				};
												
	if(out != string((char*)reference,32))
	{
		cout << "Test case 2 failed!\n";
		cout << "Input (" << dec << in.length() << " bytes):\n";
		cout << in << "\n";
		cout << "Reference: \n";
		for(uint8_t c : reference)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Computed: \n";
		for(uint8_t c : out)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
	
		return false;
	}
	
	cout << "SHA-512/256 Test case 2 succeeded!\n";
	return true;
}

bool sha_512_256_vector_3()
{
	string in = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	string out = sse::crypto::Hash::hash(in);
	
	uint8_t reference[] = {
					0x20, 0x4a, 0x8f, 0xc6, 0xdd, 0xa8, 0x2f, 0x0a, 0x0c, 0xed, 0x7b, 0xeb, 0x8e, 0x08, 0xa4, 0x16, 
					0x57, 0xc1, 0x6e, 0xf4, 0x68, 0xb2, 0x28, 0xa8, 0x27, 0x9b, 0xe3, 0x31, 0xa7, 0x03, 0xc3, 0x35
				};
												
	if(out != string((char*)reference,32))
	{
		cout << "Test case 3 failed!\n";
		cout << "Input (" << dec << in.length() << " bytes):\n";
		cout << in << "\n";
		cout << "Reference: \n";
		for(uint8_t c : reference)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Computed: \n";
		for(uint8_t c : out)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
	
		return false;
	}
	
	cout << "SHA-512/256 Test case 3 succeeded!\n";
	return true;
}

bool sha_512_256_vector_4()
{
	string in = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	string out = sse::crypto::Hash::hash(in);
	
	uint8_t reference[] = {
					0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc, 0x14, 0x3f, 
					0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18
				};
												
	if(out != string((char*)reference,32))
	{
		cout << "Test case 4 failed!\n";
		cout << "Input (" << dec << in.length() << " bytes):\n";
		cout << in << "\n";
		cout << "Reference: \n";
		for(uint8_t c : reference)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Computed: \n";
		for(uint8_t c : out)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
	
		return false;
	}
	
	cout << "SHA-512/256 Test case 4 succeeded!\n";
	return true;
}

bool sha_512_256_vector_5()
{
	string in(1e6, 'a');
	string out = sse::crypto::Hash::hash(in);
	
	uint8_t reference[] = {
					0xe7, 0x18, 0x48, 0x3d, 0x0c, 0xe7, 0x69, 0x64, 0x4e, 0x2e, 0x42, 0xc7, 0xbc, 0x15, 0xb4, 0x63, 
					0x8e, 0x1f, 0x98, 0xb1, 0x3b, 0x20, 0x44, 0x28, 0x56, 0x32, 0xa8, 0x03, 0xaf, 0xa9, 0x73, 0xeb
				};
												
	if(out != string((char*)reference,32))
	{
		cout << "Test case 5 failed!\n";
		cout << "Input (" << dec << in.length() << " bytes):\n";
		cout << in << "\n";
		cout << "Reference: \n";
		for(uint8_t c : reference)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
		
		cout << "Computed: \n";
		for(uint8_t c : out)
		{
			cout << hex << setw(2) << setfill('0') << (uint) c;
		}
		cout << endl;
	
		return false;
	}
	
	cout << "SHA-512/256 Test case 5 succeeded!\n";
	return true;
}