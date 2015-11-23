#pragma once

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
	* Hash implements SHA-512/256
	******/

	class Hash
	{
	public:
		constexpr static size_t kDigestSize = 32;
		constexpr static size_t kBlockSize = 128;
	
		static void hash(const unsigned char *in, const size_t &len, unsigned char *out);
		static void hash(const std::string &in, std::string &out);
		static std::string hash(const std::string &in);
	};

}
}
