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