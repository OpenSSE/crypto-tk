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

#include "fpe.hpp"
#include "aez/aez.h"
#include "random.hpp"

#include <limits.h>

#include <cstring>
#include <exception>
#include <iostream>
#include <iomanip>


namespace sse
{

namespace crypto
{

class Fpe::FpeImpl
{
public:
		

	FpeImpl();
	
	FpeImpl(const std::array<uint8_t,kKeySize>& k);
	
	// ~FpeImpl();

	void encrypt(const unsigned char* in, const unsigned int &len, unsigned char* out);
	void encrypt(const std::string &in, std::string &out);
	void decrypt(const unsigned char* in, const unsigned int &len, unsigned char* out);
	void decrypt(const std::string &in, std::string &out);


private:
	void setup(const unsigned char* k);
		
	aez_ctx_t aez_ctx_;
	
};

Fpe::Fpe() : fpe_imp_(new FpeImpl())
{
	
}
	
Fpe::Fpe(const std::array<uint8_t,kKeySize>& k) : fpe_imp_(new FpeImpl(k))
{	
}

Fpe::~Fpe() 
{ 
	delete fpe_imp_;
}

void Fpe::encrypt(const std::string &in, std::string &out)
{
	fpe_imp_->encrypt(in, out);
}
std::string Fpe::encrypt(const std::string &in)
{
	std::string out;
	fpe_imp_->encrypt(in, out);
	return out;
}

uint32_t Fpe::encrypt(const uint32_t &in)
{
    uint32_t out;
    fpe_imp_->encrypt((const unsigned char*)&in, sizeof(uint32_t), (unsigned char*)&out);
    return out;
}

uint64_t Fpe::encrypt_64(const uint64_t &in)
{
    uint64_t out;
    fpe_imp_->encrypt((const unsigned char*)&in, sizeof(uint64_t), (unsigned char*)&out);
    return out;
}
    

void Fpe::decrypt(const std::string &in, std::string &out)
{
	fpe_imp_->decrypt(in, out);
}

std::string Fpe::decrypt(const std::string &in)
{
	std::string out;
	fpe_imp_->decrypt(in, out);
	return out;
}

uint32_t Fpe::decrypt(const uint32_t &in)
{
	uint32_t out;
	fpe_imp_->decrypt((const unsigned char*)&in, sizeof(uint32_t), (unsigned char*)&out);
	return out;
}

uint64_t Fpe::decrypt_64(const uint64_t &in)
{
    uint64_t out;
    fpe_imp_->decrypt((const unsigned char*)&in, sizeof(uint64_t), (unsigned char*)&out);
    return out;
}

Fpe::FpeImpl::FpeImpl()
    : aez_ctx_{}
{
	unsigned char k[kKeySize];
	random_bytes(kKeySize, k);
	setup((unsigned char*)k);
}

Fpe::FpeImpl::FpeImpl(const std::array<uint8_t,kKeySize>& k)
    : aez_ctx_{}
{
	setup((const unsigned char*)k.data());
}

void Fpe::FpeImpl::setup(const unsigned char* k)
{
	aez_setup(k, 48, &aez_ctx_);
}
	
void Fpe::FpeImpl::encrypt(const unsigned char* in, const unsigned int &len, unsigned char* out)
{
	char iv[16] = {0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00};
	aez_encrypt(&aez_ctx_, iv, 16,
	                 NULL, 0, 0,
	                 (const char *)in, len, (char *)out);
}

void Fpe::FpeImpl::encrypt(const std::string &in, std::string &out)
{
	size_t len = in.size();

    if(len > UINT_MAX)
    {
        throw std::runtime_error("The maximum input length of Format Preserving Encryption is UINT_MAX");
    }

    unsigned char *data = new unsigned char[len];

	encrypt((const unsigned char*)in.data(), (unsigned int)len, data);
	out = std::string((char *)data, len);
    delete [] data;
}

void Fpe::FpeImpl::decrypt(const unsigned char* in, const unsigned int &len,  unsigned char* out)
{
	char iv[16] = {0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00, 
							0x00, 0x00, 0x00, 0x00};
	aez_decrypt(&aez_ctx_, iv, 16,
	                 NULL, 0, 0,
	                 (const char *)in, len, (char *)out);
}

void Fpe::FpeImpl::decrypt(const std::string &in, std::string &out)
{
	size_t len = in.size();

    if(len > UINT_MAX)
    {
        throw std::runtime_error("The maximum input length of Format Preserving Encryption is UINT_MAX");
    }
    
    unsigned char *data = new unsigned char[len];
	
	decrypt((const unsigned char*)in.data(), (unsigned int)len, data);
    
	out = std::string((const char *)data, len);
    delete [] data;
}

	
}
}