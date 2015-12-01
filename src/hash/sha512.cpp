//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015 Raphael Bost
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

#include "sha512.hpp"

#include <openssl/sha.h>

namespace sse
{
	
namespace crypto
{

namespace hash
{
	
void sha512::hash(const unsigned char *in, const size_t &len, unsigned char *out)
{
	// memset(out,0x00, kDigestSize);
	SHA512_CTX c;
	SHA512_Init(&c);
	SHA512_Update(&c, in, len);
	SHA512_Final(out, &c);
}

}
}
}