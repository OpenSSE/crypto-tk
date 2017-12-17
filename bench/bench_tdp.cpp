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

#include <benchmark/benchmark.h>

#include "tdp_impl/tdp_impl_openssl.hpp"
#include "tdp_impl/tdp_impl_mbedtls.hpp"

using sse::crypto::TdpImpl_mbedTLS;
using sse::crypto::TdpInverseImpl_mbedTLS;
using sse::crypto::TdpImpl_OpenSSL;
using sse::crypto::TdpInverseImpl_OpenSSL;

template <class TDP_INV>
void tdp_key_generation(benchmark::State& state)
{
    for (auto _ : state){
        TDP_INV sk_tdp;
        benchmark::DoNotOptimize(sk_tdp);
    }
}

BENCHMARK_TEMPLATE(tdp_key_generation, TdpInverseImpl_mbedTLS)->Unit(benchmark::kMicrosecond)->Iterations(20);
BENCHMARK_TEMPLATE(tdp_key_generation, TdpInverseImpl_OpenSSL)->Unit(benchmark::kMicrosecond)->Iterations(20);

template<typename TDP_INV>
class Tdp_Benchmark : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state)
    {
        message = tdp_.sample();
    }
    void eval()
    {
        tdp_.eval(message,message);
    }
    
    
    std::string message;
    TDP_INV tdp_;
};

#define EVAL_BENCH(NAME,TDP_INV_IMPL) \
BENCHMARK_TEMPLATE_DEFINE_F(Tdp_Benchmark, NAME##_eval, TDP_INV_IMPL)(benchmark::State& st) { \
    for (auto _ : st) { \
        eval(); \
    } \
} \
BENCHMARK_REGISTER_F(Tdp_Benchmark, NAME##_eval);


EVAL_BENCH(mbedTLS,TdpInverseImpl_mbedTLS);
EVAL_BENCH(OpenSSL,TdpInverseImpl_OpenSSL);


