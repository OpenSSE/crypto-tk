#pragma once

#include <array>

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
		random_bytes(out.size()*sizeof(T), (unsigned char*)out.data());
	}

}
}