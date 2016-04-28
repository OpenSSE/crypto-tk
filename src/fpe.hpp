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
* Fpe class
*
* Opaque class for format preserving encryption and decryption.
* 	
* For now, Fpe implements AEZ.
******/

class Fpe{
public:
	static constexpr uint8_t kKeySize = 48;
	
	Fpe();
	// we should not be able to duplicate Fpe objects
	Fpe(const Fpe& c) = delete;
	Fpe(Fpe& c) = delete;
	Fpe(const Fpe&& c) = delete;
	Fpe(Fpe&& c) = delete;
	
	
	Fpe(const std::array<uint8_t,kKeySize>& k);
	
	~Fpe();

	void encrypt(const std::string &in, std::string &out);
	std::string encrypt(const std::string &in);
	uint32_t encrypt(const uint32_t &in);
    uint64_t encrypt_64(const uint64_t &in);

	void decrypt(const std::string &in, std::string &out);
	std::string decrypt(const std::string &in);
	uint32_t decrypt(const uint32_t &in);
    uint64_t decrypt_64(const uint64_t &in);

	// Again, avoid any assignement of Cipher objects
	Fpe& operator=(const Fpe& h) = delete;
	Fpe& operator=(Fpe& h) = delete;
	
private:	
	class FpeImpl; // not defined in the header
	FpeImpl *fpe_imp_; // opaque pointer

};
	

}
}