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

class TdpImpl; // not defined in the header
class TdpInverseImpl; // not defined in the header

/*****
* Tdp class
*
* Opaque class for Trapdoor permutation.
* 	
* Trapdoor permutations are implemented using RSA.
******/

class Tdp{
public:
	Tdp(const std::string& pk);
	
	virtual ~Tdp();

    std::string public_key() const;

    std::string sample() const;
    
    void eval(const std::string &in, std::string &out) const;
	std::string eval(const std::string &in) const;
	
private:
	TdpImpl *tdp_imp_; // opaque pointer

};
	
class TdpInverse {
public:    
    TdpInverse();
	TdpInverse(const std::string& sk);
	
	~TdpInverse();

    std::string public_key() const;
    std::string private_key() const;

    std::string sample() const;

    void eval(const std::string &in, std::string &out) const;
	std::string eval(const std::string &in) const;

	void invert(const std::string &in, std::string &out) const;
	std::string invert(const std::string &in) const;
	
private:	
	TdpInverseImpl *tdp_inv_imp_; // opaque pointer

};

}
}