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

#include <sse/crypto/hash.hpp>
#include <sse/crypto/random.hpp>
#include <sse/crypto/set_hash.hpp>

#include <benchmark/benchmark.h>

#include <iostream>
#include <vector>


using sse::crypto::SetHash;

template<typename SH>
static void SetHash_insert(benchmark::State& state)
{
    for (auto _ : state) {
        state.PauseTiming();
        std::vector<std::string> samples(state.range(0));
        for (auto& e : samples) {
            e = sse::crypto::random_string(state.range(1));
        }
        state.ResumeTiming();

        SH a;
        for (auto& e : samples) {
            a.add_element(e);
        }
    }

    state.SetItemsProcessed(int64_t(state.iterations())
                            * int64_t(state.range(0)));

    state.SetComplexityN((int)state.items_processed());
}

static void SetHash_insert_args(benchmark::internal::Benchmark* b)
{
    auto elts_size = {4, 16, 128, 256};
    for (auto es : elts_size)
        for (int j = 1 << 2; j <= 1 << 14; j *= 8)
            b->Args({j, es});
}


BENCHMARK_TEMPLATE(SetHash_insert, SetHash)
    ->Apply(SetHash_insert_args)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_TEMPLATE(SetHash_insert, SetHash)
    ->RangeMultiplier(2)
    ->Ranges({{1 << 4, 1 << 14}, {32, 32}})
    ->Unit(benchmark::kMicrosecond)
    ->Complexity(benchmark::oN);


template<typename SH>
static void SetHash_batch_construct(benchmark::State& state)
{
    for (auto _ : state) {
        state.PauseTiming();
        std::vector<std::string> samples(state.range(0));
        for (auto& e : samples) {
            e = sse::crypto::random_string(state.range(1));
        }
        state.ResumeTiming();

        SH a(samples);
        benchmark::DoNotOptimize(a);
    }

    state.SetItemsProcessed(int64_t(state.iterations())
                            * int64_t(state.range(0)));

    state.SetComplexityN((int)state.items_processed());
}


BENCHMARK_TEMPLATE(SetHash_batch_construct, SetHash)
    ->Apply(SetHash_insert_args)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_TEMPLATE(SetHash_batch_construct, SetHash)
    ->RangeMultiplier(2)
    ->Ranges({{1 << 4, 1 << 14}, {32, 32}})
    ->Unit(benchmark::kMicrosecond)
    ->Complexity(benchmark::oN);
