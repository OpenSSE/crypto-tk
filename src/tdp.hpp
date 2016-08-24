//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2016 Raphael Bost
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


#pragma once

#include "prf.hpp"

#include <cstdint>

#include <array>
#include <string>

namespace sse
{
namespace crypto
{

class TdpImpl; // not defined in the header
class TdpInverseImpl; // not defined in the header
class TdpMultPoolImpl; // not defined in the header

/*****
* Tdp class
*
* Opaque class for Trapdoor permutation.
* 	
* Trapdoor permutations are implemented using RSA.
******/

class Tdp{
public:
    static constexpr size_t kMessageSize = 256;
    static constexpr unsigned int kStatisticalSecurity = 64;
    static constexpr size_t kRSAPrgSize = kMessageSize + kStatisticalSecurity;

	Tdp(const std::string& pk);

    Tdp(const Tdp &t);
    Tdp& operator=(const Tdp& t);

	virtual ~Tdp();

    std::string public_key() const;

    std::string sample() const;
    std::array<uint8_t, kMessageSize> sample_array() const;
    
    std::string generate(const std::string& key, const std::string& seed) const;
    std::array<uint8_t, kMessageSize> generate_array(const std::string& key, const std::string& seed) const;
    std::string generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;
    std::array<uint8_t, kMessageSize> generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;

    void eval(const std::string &in, std::string &out) const;
	std::string eval(const std::string &in) const;    
    std::array<uint8_t, kMessageSize> eval(const std::array<uint8_t, kMessageSize> &in) const;
    
private:
	TdpImpl *tdp_imp_; // opaque pointer

};
	
class TdpInverse {
public:    
    static constexpr size_t kMessageSize = Tdp::kMessageSize;

    TdpInverse();
    TdpInverse(const std::string& sk);
    TdpInverse(const TdpInverse& tdp);
    
    TdpInverse& operator=(const TdpInverse& t);

    
	~TdpInverse();

    std::string public_key() const;
    std::string private_key() const;

    std::string sample() const;
    std::array<uint8_t, kMessageSize> sample_array() const;

    std::string generate(const std::string& key, const std::string& seed) const;
    std::array<uint8_t, kMessageSize> generate_array(const std::string& key, const std::string& seed) const;
    std::string generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;
    std::array<uint8_t, kMessageSize> generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;

    void eval(const std::string &in, std::string &out) const;
	std::string eval(const std::string &in) const;
    std::array<uint8_t, kMessageSize> eval(const std::array<uint8_t, kMessageSize> &in) const;

    void invert(const std::string &in, std::string &out) const;
    std::string invert(const std::string &in) const;
    std::array<uint8_t, kMessageSize> invert(const std::array<uint8_t, kMessageSize> &in) const;
    
    void invert_mult(const std::string &in, std::string &out, uint32_t order) const;
    std::string invert_mult(const std::string &in, uint32_t order) const;
    std::array<uint8_t, kMessageSize> invert_mult(const std::array<uint8_t, kMessageSize> &in, uint32_t order) const;
    
private:
	TdpInverseImpl *tdp_inv_imp_; // opaque pointer

};

class TdpMultPool{
public:
    static constexpr size_t kMessageSize = Tdp::kMessageSize;
    
    TdpMultPool(const std::string& pk, const uint8_t size);
    TdpMultPool(const TdpMultPool& pool);
    
    TdpMultPool& operator=(const TdpMultPool& t);

    virtual ~TdpMultPool();
    
    std::string public_key() const;
    
    std::string sample() const;
    std::array<uint8_t, kMessageSize> sample_array() const;
    std::string generate(const std::string& key, const std::string& seed) const;
    std::array<uint8_t, kMessageSize> generate_array(const std::string& key, const std::string& seed) const;
    std::string generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;
    std::array<uint8_t, kMessageSize> generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const;

    void eval(const std::string &in, std::string &out) const;
    std::string eval(const std::string &in) const;
    std::array<uint8_t, kMessageSize> eval(const std::array<uint8_t, kMessageSize> &in) const;

    void eval(const std::string &in, std::string &out, uint8_t order) const;
    std::string eval(const std::string &in, uint8_t order) const;
    std::array<uint8_t, kMessageSize> eval(const std::array<uint8_t, kMessageSize> &in, uint8_t order) const;
    
    uint8_t maximum_order() const;
    uint8_t pool_size() const;

private:
    TdpMultPoolImpl *tdp_pool_imp_; // opaque pointer
    
};
    

}
}