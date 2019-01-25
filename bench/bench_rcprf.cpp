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

#include <sse/crypto/rcprf.hpp>

#include <benchmark/benchmark.h>

#include <random>

using sse::crypto::Key;
using sse::crypto::RCPrf;
using sse::crypto::RCPrfParams;

static void RCPrf_eval(benchmark::State& state)
{
    uint8_t  depth          = state.range(0);
    uint64_t max_leaf_index = RCPrfParams::max_leaf_index_generic(depth);

    std::random_device                      rnd;
    std::mt19937_64                         rnd_gen(rnd());
    std::uniform_int_distribution<uint64_t> unif_dist(0, max_leaf_index);

    RCPrf<32> rcprf(Key<RCPrfParams::kKeySize>(), depth);

    for (auto _ : state) {
        // randomly generate a starting point
        uint64_t index = unif_dist(rnd_gen);
        rcprf.eval(index);
    }
    state.SetItemsProcessed(state.iterations());
}

static void RCPrf_eval_range(benchmark::State& state)
{
    uint8_t  depth          = state.range(0);
    uint64_t max_leaf_index = RCPrfParams::max_leaf_index_generic(depth);

    std::random_device                      rnd;
    std::mt19937_64                         rnd_gen(rnd());
    std::uniform_int_distribution<uint64_t> unif_dist(
        0, max_leaf_index - state.range(1));

    RCPrf<32> rcprf(Key<RCPrfParams::kKeySize>(), depth);

    auto callback = [](size_t, std::array<uint8_t, 32>) {};

    for (auto _ : state) {
        // randomly generate a starting point
        uint64_t start_index = unif_dist(rnd_gen);

        rcprf.eval_range(start_index, start_index + state.range(1), callback);
    }
    state.SetItemsProcessed(state.iterations() * state.range(1));
}

static void RCPrf_eval_range_constrain(benchmark::State& state)
{
    uint8_t  depth          = state.range(0);
    uint64_t max_leaf_index = RCPrfParams::max_leaf_index_generic(depth);

    std::random_device                      rnd;
    std::mt19937_64                         rnd_gen(rnd());
    std::uniform_int_distribution<uint64_t> unif_dist(
        0, max_leaf_index - state.range(1));

    RCPrf<32> rcprf(Key<RCPrfParams::kKeySize>(), depth);

    auto callback = [](size_t, std::array<uint8_t, 32>) {};

    for (auto _ : state) {
        // randomly generate a starting point
        uint64_t start_index = unif_dist(rnd_gen);

        state.PauseTiming();
        auto constrained
            = rcprf.constrain(start_index, start_index + state.range(1));

        state.ResumeTiming();

        constrained.eval_range(
            start_index, start_index + state.range(1), callback);
    }
    state.SetItemsProcessed(state.iterations() * state.range(1));
}

BENCHMARK(RCPrf_eval)->RangeMultiplier(2)->Range(48, 48);

BENCHMARK(RCPrf_eval_range)->RangeMultiplier(2)->Ranges({{48, 48}, {8, 128}});
// ->Ranges({{16, 32}, {8, 128}});

BENCHMARK(RCPrf_eval_range_constrain)
    ->RangeMultiplier(2)
    ->Ranges({{48, 48}, {8, 128}});
// ->Ranges({{16, 32}, {8, 128}});
