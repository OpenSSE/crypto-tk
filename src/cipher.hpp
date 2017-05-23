//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2106 Raphael Bost
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

	Cipher() = delete;
	
	// we should not be able to duplicate Cipher objects
	Cipher(const Cipher& c) = delete;
	Cipher(Cipher& c) = delete;
	Cipher(const Cipher&& c) = delete;
	Cipher(Cipher&& c) = delete;
	
	
	Cipher(const std::array<uint8_t,kKeySize>& k);
	Cipher(const uint8_t* k);
	
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
