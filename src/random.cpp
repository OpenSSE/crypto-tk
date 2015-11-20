#include "random.hpp"

#include <fstream>

namespace sse
{

namespace crypto
{
	
void random_bytes(const size_t &byte_count, unsigned char* buffer)
{
	std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary);
	urandom.read((char*) buffer,byte_count);
	urandom.close();
}

}
}