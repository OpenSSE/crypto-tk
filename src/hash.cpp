#include "hash.hpp"

#include <openssl/sha.h>

namespace sse
{
	
namespace crypto
{
	
void Hash::hash(const unsigned char *in, const size_t &len, unsigned char *out)
{
	unsigned char digest[SHA512_DIGEST_LENGTH];
	
	SHA512(in, len, digest);
	memcpy(out, digest, kDigestSize);
}

void Hash::hash(const std::string &in, std::string &out)
{
	out.resize(kDigestSize);
	hash((unsigned char*)in.data(),in.length(),(unsigned char*)out.data());
}

std::string Hash::hash(const std::string &in)
{
	std::string out;
	hash(in,out);
	return out;
}

}
}