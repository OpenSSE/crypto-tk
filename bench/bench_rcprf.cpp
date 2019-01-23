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

using sse::crypto::Key;
using sse::crypto::RCPrf;
using sse::crypto::RCPrfParams;

static void BM_RCPrf_eval_all_loop(benchmark::State& state)
{
    uint8_t  depth          = state.range(0);
    uint64_t max_leaf_index = RCPrfParams::max_leaf_index_generic(depth);

    RCPrf<32> rcprf(Key<RCPrfParams::kKeySize>(), depth);

    size_t i = 0;
    for (auto _ : state) {
        rcprf.eval(i);

        i = (i + 1) % (max_leaf_index + 1);
    }
    state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_RCPrf_eval_all_loop)
    ->RangeMultiplier(2)
    ->Range(4, 62); // Arg(4)->Arg(8)->Arg(16)->Arg(4)->Arg(4);