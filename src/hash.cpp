#include "hash.hpp"

#include <cassert>

#include <openssl/sha.h>

namespace sse
{
	
namespace crypto
{
	
void Hash::hash(const unsigned char *in, const size_t &len, unsigned char *out)
{
	SHA512(in, len, out);
}

void Hash::hash(const unsigned char *in, const size_t &len, const size_t &out_len, unsigned char *out)
{
	assert(out_len <= kDigestSize);
	unsigned char digest[kDigestSize];

	hash(in, len, digest);
	memcpy(out, digest, out_len);
}

void Hash::hash(const std::string &in, std::string &out)
{
	out.resize(kDigestSize);
	hash((unsigned char*)in.data(),in.length(),(unsigned char*)out.data());
}

void Hash::hash(const std::string &in, const size_t &out_len, std::string &out)
{
	out.resize(out_len);
	hash((unsigned char*)in.data(), in.length(), out_len, (unsigned char*)out.data());
}

std::string Hash::hash(const std::string &in)
{
	std::string out;
	hash(in,out);
	return out;
}

std::string Hash::hash(const std::string &in, const size_t &out_len)
{
	std::string out;
	hash(in,out_len,out);
	return out;
}

}
}