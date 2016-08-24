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

#include <string>
#include <vector>

namespace sse
{

namespace crypto
{

/*****
* SetHash class
*
* Opaque class for set hashing.
* 	
* For now, SetHash implements the ECMH function (by Maitin-Shepard, Tibouchi and Aranha)
******/

class SetHash
{
public:

	SetHash();	
	SetHash(const std::string &hex_str);
	SetHash(const SetHash& o);
	SetHash(const SetHash&& o);
	SetHash(const std::vector<std::string> &in_set);
	~SetHash();

	void add_element(const std::string &in);
	void add_set(const SetHash &h);
	void remove_element(const std::string &in);
	void remove_set(const SetHash &h);
	SetHash invert_set();
	
	std::string hex() const;
	
	friend std::ostream& operator<<(std::ostream& os, const SetHash& h);
	SetHash& operator=(const SetHash& h);
	bool operator==(const SetHash& h) const;
	bool operator!=(const SetHash& h) const;
private:	
	class SetHashImpl; // not defined in the header
	SetHashImpl *set_hash_imp_; // opaque pointer
};

}
}