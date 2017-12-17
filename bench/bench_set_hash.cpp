#include <benchmark/benchmark.h>


#include "set_hash.hpp"
#include "hash.hpp"
#include "random.hpp"

#include <iostream>
#include <vector>


using sse::crypto::SetHash;

static void SetHash_insert(benchmark::State& state) {
    for (auto _ : state){
        state.PauseTiming();
        std::vector<std::string> samples(state.range(0));
        for (auto &e : samples){
            e = sse::crypto::random_string(state.range(1));
        }
        state.ResumeTiming();

        SetHash a;
        for (auto &e : samples){
            a.add_element(e);
        }
    }
    
    state.SetItemsProcessed(int64_t(state.iterations()) *
                            int64_t(state.range(0)));
    
    state.SetComplexityN((int)state.items_processed());
}

static void SetHash_insert_args(benchmark::internal::Benchmark* b) {
    auto elts_size = { 4, 16, 128, 256};
    for (auto es : elts_size)
        for (int j = 1<<2; j <= 1<<14; j *= 8)
            b->Args({j, es});
}
BENCHMARK(SetHash_insert)->Apply(SetHash_insert_args)
->Unit(benchmark::kMicrosecond);

BENCHMARK(SetHash_insert)->RangeMultiplier(2)
->Ranges({{1<<4, 1<<14},{32,32}})
->Unit(benchmark::kMicrosecond)->Complexity(benchmark::oN);




BENCHMARK_MAIN();
