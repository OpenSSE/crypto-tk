//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2016 Raphael Bost
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
* Tdp class
*
* Opaque class for Trapdoor permutation.
* 	
* Trapdoor permutations are implemented using RSA.
******/
//
//class Tdp{
//public:
//	// static constexpr uint16_t kPKeySize = 384; // only N,
//	static constexpr uint16_t kMessageSpaceSize = 384;
//	
//	Tdp(const std::string& pk);
//	
//	virtual ~Tdp();
//
//	void apply(const std::string &in, std::string &out);
//	std::string apply(const std::string &in);
//	
//private:	
//	class TdpImpl; // not defined in the header
//	TdpImpl *tdp_imp_; // opaque pointer
//
//};
	
class TdpInverse {
public:
	static constexpr uint16_t kMessageSpaceSize = 384;
    
    TdpInverse();
	TdpInverse(const std::string& sk);
	
	~TdpInverse();

    std::string private_key() const;

	void apply(const std::string &in, std::string &out);
	std::string apply(const std::string &in);

	void invert(const std::string &in, std::string &out);
	std::string invert(const std::string &in);
	
private:	
	class TdpInverseImpl; // not defined in the header
	TdpInverseImpl *tdp_inv_imp_; // opaque pointer

};

}
}