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

#include "tdp_impl/tdp_impl_mbedtls.hpp"
#include "tdp_impl/tdp_impl_openssl.hpp"

#include <benchmark/benchmark.h>

using sse::crypto::TdpImpl_mbedTLS;
using sse::crypto::TdpInverseImpl_mbedTLS;
using sse::crypto::TdpMultPoolImpl_mbedTLS;

#ifdef WITH_OPENSSL
using sse::crypto::TdpImpl_OpenSSL;
using sse::crypto::TdpInverseImpl_OpenSSL;
using sse::crypto::TdpMultPoolImpl_OpenSSL;
#endif

template<class TDP_INV>
void Tdp_key_generation(benchmark::State& state)
{
    for (auto _ : state) {
        TDP_INV sk_tdp;
        benchmark::DoNotOptimize(sk_tdp);
    }
}

#define MAX_POOL_SIZE 0x7E

BENCHMARK_TEMPLATE(Tdp_key_generation, TdpInverseImpl_mbedTLS)
    ->Unit(benchmark::kMicrosecond)
    ->Iterations(20);

#ifdef WITH_OPENSSL
BENCHMARK_TEMPLATE(Tdp_key_generation, TdpInverseImpl_OpenSSL)
    ->Unit(benchmark::kMicrosecond)
    ->Iterations(20);
#endif

#ifdef WITH_OPENSSL
struct OpenSSL_Impl
{
    typedef TdpImpl_OpenSSL         TdpImpl;
    typedef TdpInverseImpl_OpenSSL  TdpInverseImpl;
    typedef TdpMultPoolImpl_OpenSSL TdpMultPoolImpl;
};
#endif

struct mbedTLS_Impl
{
    typedef TdpImpl_mbedTLS         TdpImpl;
    typedef TdpInverseImpl_mbedTLS  TdpInverseImpl;
    typedef TdpMultPoolImpl_mbedTLS TdpMultPoolImpl;
};

template<typename IMPL>
class Tdp_Benchmark : public benchmark::Fixture
{
public:
    Tdp_Benchmark()
        : tdp_inv_(), tdp_(tdp_inv_.public_key()),
          tdp_mult_(tdp_inv_.public_key(), MAX_POOL_SIZE)
    {
    }
    void SetUp(const ::benchmark::State& /*state*/)
    {
        message = tdp_.sample();
    }

    std::string                    message;
    typename IMPL::TdpInverseImpl  tdp_inv_;
    typename IMPL::TdpImpl         tdp_;
    typename IMPL::TdpMultPoolImpl tdp_mult_;
};

#define EVAL_BENCH_AUX(NAME, IMPL)                                             \
    BENCHMARK_TEMPLATE_DEFINE_F(Tdp_Benchmark, NAME##_eval, IMPL)              \
    (benchmark::State & st)                                                    \
    {                                                                          \
        for (auto _ : st) {                                                    \
            tdp_.eval(message, message);                                       \
        }                                                                      \
        st.SetItemsProcessed(int64_t(st.iterations()));                        \
    }                                                                          \
    BENCHMARK_REGISTER_F(Tdp_Benchmark, NAME##_eval);

#define EVAL_BENCH(LIB) EVAL_BENCH_AUX(LIB, LIB##_Impl)

#define EVAL_MULT_BENCH_AUX(NAME, IMPL)                                        \
    BENCHMARK_TEMPLATE_DEFINE_F(Tdp_Benchmark, NAME##_eval_mult, IMPL)         \
    (benchmark::State & st)                                                    \
    {                                                                          \
        for (auto _ : st) {                                                    \
            tdp_mult_.eval_pool(message, message, st.range(0));                \
        }                                                                      \
        st.SetItemsProcessed(int64_t(st.iterations()));                        \
    }                                                                          \
    BENCHMARK_REGISTER_F(Tdp_Benchmark, NAME##_eval_mult)                      \
        ->RangeMultiplier(2)                                                   \
        ->Range(1, MAX_POOL_SIZE);

#define EVAL_MULT_BENCH(LIB) EVAL_MULT_BENCH_AUX(LIB, LIB##_Impl)


#define INVERT_BENCH_AUX(NAME, IMPL)                                           \
    BENCHMARK_TEMPLATE_DEFINE_F(Tdp_Benchmark, NAME##_invert, IMPL)            \
    (benchmark::State & st)                                                    \
    {                                                                          \
        for (auto _ : st) {                                                    \
            tdp_inv_.invert(message, message);                                 \
        }                                                                      \
        st.SetItemsProcessed(int64_t(st.iterations()));                        \
    }                                                                          \
    BENCHMARK_REGISTER_F(Tdp_Benchmark, NAME##_invert)

#define INVERT_BENCH(LIB) INVERT_BENCH_AUX(LIB, LIB##_Impl)

#define INVERT_MULT_BENCH_AUX(NAME, IMPL)                                      \
    BENCHMARK_TEMPLATE_DEFINE_F(Tdp_Benchmark, NAME##_invert_mult, IMPL)       \
    (benchmark::State & st)                                                    \
    {                                                                          \
        for (auto _ : st) {                                                    \
            tdp_inv_.invert_mult(message, message, st.range(0));               \
        }                                                                      \
        st.SetItemsProcessed(int64_t(st.iterations()));                        \
    }                                                                          \
    BENCHMARK_REGISTER_F(Tdp_Benchmark, NAME##_invert_mult)                    \
        ->RangeMultiplier(2)                                                   \
        ->Range(1, 32);

#define INVERT_MULT_BENCH(LIB) INVERT_MULT_BENCH_AUX(LIB, LIB##_Impl)

EVAL_BENCH(mbedTLS);
#ifdef WITH_OPENSSL
EVAL_BENCH(OpenSSL);
#endif

EVAL_MULT_BENCH(mbedTLS);
#ifdef WITH_OPENSSL
EVAL_MULT_BENCH(OpenSSL);
#endif

INVERT_BENCH(mbedTLS);
#ifdef WITH_OPENSSL
INVERT_BENCH(OpenSSL);
#endif

INVERT_MULT_BENCH(mbedTLS);
#ifdef WITH_OPENSSL
INVERT_MULT_BENCH(OpenSSL);
#endif
