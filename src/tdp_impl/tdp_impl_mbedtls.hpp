//
// libsse_crypto - An abstraction layer for high level cryptographic features.
// Copyright (C) 2015-2017 Raphael Bost
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

#include "tdp_impl.hpp"
#include "prf.hpp"
#include "key.hpp"

#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#include <cstdint>

#include <array>
#include <string>

namespace sse
{
namespace crypto
{

    class TdpImpl_mbedTLS : virtual public TdpImpl
    {
    public:
//        static constexpr uint kMessageSpaceSize = Tdp::kMessageSize;
        
        TdpImpl_mbedTLS(const std::string& pk);
        TdpImpl_mbedTLS(const TdpImpl_mbedTLS& tdp);
        
        ~TdpImpl_mbedTLS() override;
        
        TdpImpl_mbedTLS& operator=(const TdpImpl_mbedTLS& t);

        
        size_t rsa_size() const override;
        
        std::string public_key() const override;
        
        void eval(const std::string &in, std::string &out) const override;
        std::array<uint8_t, kMessageSpaceSize> eval(const std::array<uint8_t, kMessageSpaceSize> &in) const override;
        
        std::string sample() const override;
        std::array<uint8_t, kMessageSpaceSize> sample_array() const override;
        
        std::string generate(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const override;
        std::array<uint8_t, kMessageSpaceSize> generate_array(const Prf<Tdp::kRSAPrgSize>& prg, const std::string& seed) const override;
        std::string generate(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const override;
        std::array<uint8_t, kMessageSpaceSize> generate_array(Key<Prf<Tdp::kRSAPrgSize>::kKeySize>&& key, const std::string& seed) const override;
        
    protected:
        TdpImpl_mbedTLS();
        
        mutable mbedtls_rsa_context rsa_key_;
    };

    class TdpInverseImpl_mbedTLS : public TdpImpl_mbedTLS, virtual public TdpInverseImpl
    {
    public:
        TdpInverseImpl_mbedTLS();
        TdpInverseImpl_mbedTLS(const std::string& sk);
        TdpInverseImpl_mbedTLS(const TdpInverseImpl_mbedTLS& tdp) = delete;
        TdpInverseImpl_mbedTLS(TdpInverseImpl_mbedTLS&& tdp) = delete;
        ~TdpInverseImpl_mbedTLS() override;
        
        TdpInverseImpl_mbedTLS& operator=(const TdpInverseImpl_mbedTLS& t) = delete;

        std::string private_key() const override;
        void invert(const std::string &in, std::string &out) const override;
        std::array<uint8_t, kMessageSpaceSize> invert(const std::array<uint8_t, kMessageSpaceSize> &in) const override;
        
        std::array<uint8_t, kMessageSpaceSize> invert_mult(const std::array<uint8_t, kMessageSpaceSize> &in, uint32_t order) const override;
        void invert_mult(const std::string &in, std::string &out, uint32_t order) const override;
        
    private:
        mbedtls_mpi phi_, p_1_, q_1_;
    };
    
    class TdpMultPoolImpl_mbedTLS : public TdpImpl_mbedTLS, virtual public TdpMultPoolImpl
    {
    public:
        TdpMultPoolImpl_mbedTLS(const std::string& sk, const uint8_t size);
        TdpMultPoolImpl_mbedTLS(const TdpMultPoolImpl_mbedTLS& pool_impl);
        
        TdpMultPoolImpl_mbedTLS& operator=(const TdpMultPoolImpl_mbedTLS& t);

        ~TdpMultPoolImpl_mbedTLS() override;
        
        std::array<uint8_t, TdpImpl_mbedTLS::kMessageSpaceSize> eval_pool(const std::array<uint8_t, kMessageSpaceSize> &in, const uint8_t order) const override;
        void eval_pool(const std::string &in, std::string &out, const uint8_t order) const override;
        
        uint8_t maximum_order() const override;
        uint8_t pool_size() const override;
    private:
        mbedtls_rsa_context* keys_;
        
        uint8_t keys_count_;
    };
    


}
}
