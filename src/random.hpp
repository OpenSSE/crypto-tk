#pragma once

#include <array>

#include <cstdint>

namespace sse
{

namespace crypto
{


	void random_bytes(const size_t &byte_count, unsigned char* buffer);

	template <typename T, size_t N>
	void random_bytes(std::array<T,N> &buffer)
	{
		random_bytes(buffer.size()*sizeof(T), (unsigned char*)buffer.data());
	}

}
}