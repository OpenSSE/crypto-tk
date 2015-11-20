#pragma once

#include <cstdint>

#include <array>
#include <string>

namespace sse
{

namespace crypto
{

/*****
* Cipher class
*
* Opaque class for encryption and decryption.
* 	
* For now, Cipher implements a counter mode.
******/

class Cipher
{
public:
	static constexpr uint8_t kKeySize = 32;

	Cipher();
	
	Cipher(const std::array<uint8_t,kKeySize>& k);
	
	~Cipher();

	void encrypt(const std::string &in, std::string &out);
	void decrypt(const std::string &in, std::string &out);
	
private:	
	class CipherImpl; // not defined in the header
	CipherImpl *cipher_imp_; // opaque pointer
};

}
}