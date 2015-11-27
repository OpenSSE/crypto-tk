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
	
	// we should not be able to duplicate Cipher objects
	Cipher(const Cipher& c) = delete;
	Cipher(Cipher& c) = delete;
	Cipher(const Cipher&& c) = delete;
	Cipher(Cipher&& c) = delete;
	
	
	Cipher(const std::array<uint8_t,kKeySize>& k);
	
	~Cipher();

	void encrypt(const std::string &in, std::string &out);
	void decrypt(const std::string &in, std::string &out);
	
	// Again, avoid any assignement of Cipher objects
	Cipher& operator=(const Cipher& h) = delete;
	Cipher& operator=(Cipher& h) = delete;
	
private:	
	class CipherImpl; // not defined in the header
	CipherImpl *cipher_imp_; // opaque pointer
};

}
}