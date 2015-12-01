#include <cstddef>

namespace sse
{
	
namespace crypto
{

namespace hash
{

struct sha512
	{
		
		constexpr static size_t kDigestSize = 64;
		constexpr static size_t kBlockSize = 128;
		
		static void hash(const unsigned char *in, const size_t &len, unsigned char *out);

	};	

}
}
}