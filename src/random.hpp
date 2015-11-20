#pragma once

#include <cstdint>

namespace sse
{

namespace crypto
{


void random_bytes(const size_t &byte_count, unsigned char* buffer);
}
}