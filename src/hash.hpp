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

#include <cstddef>
#include <string>


namespace sse
{

namespace crypto
{
	/*****
	* Hash class
	*
	* Implementation of a hash function.
	* 	
	* Hash implements Blake2b
	******/
	
	class Hash
	{
	public:
		constexpr static size_t kDigestSize = 64;
		constexpr static size_t kBlockSize = 128;
	
		static void hash(const unsigned char *in, const size_t &len, unsigned char *out);
		static void hash(const unsigned char *in, const size_t &len, const size_t &out_len, unsigned char *out);
		static void hash(const std::string &in, std::string &out);
		static void hash(const std::string &in, const size_t &out_len, std::string &out);
		static std::string hash(const std::string &in);
		static std::string hash(const std::string &in, const size_t &out_len);
	};

}
}
