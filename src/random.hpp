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

#include <array>
#include <string>

#include <cstdint>

namespace sse
{

namespace crypto
{

	class Drbg
	{
	public:
		Drbg();
		~Drbg();
		
        Drbg(const Drbg&) = delete;
        Drbg& operator=(const Drbg&) = delete;
        
		void reseed();
		void next(const size_t &byte_count, unsigned char* out);
		
	private:	
		class DrbgImpl; // not defined in the header
		DrbgImpl *drdg_imp_; // opaque pointer
		
	};

#ifdef __MACH__
	static Drbg rng;
#else
	static thread_local Drbg rng;
#endif
	
	inline void random_bytes(const size_t &byte_count, unsigned char* out)
	{
	// #warning thread_local is not supported by Mac OS libc implementation
	   rng.next(byte_count, out);
	}

	template <typename T, size_t N>
	inline void random_bytes(std::array<T,N> &out)
	{
		random_bytes(out.size()*sizeof(T), reinterpret_cast<unsigned char*>(out.data()));
	}

	inline std::string random_string(const size_t &length)
	{
        std::string out(length,0x00);
		random_bytes(length, reinterpret_cast<unsigned char*>(const_cast<char*>(out.data())));
        
        return out;
	}
}
}
