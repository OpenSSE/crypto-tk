# We need the Google benchmark library for the targets defined in this
# directory, but it is not a requirement.

find_package(benchmark)

if(benchmark_FOUND)
    add_custom_target(bench)
else()
    message(STATUS "Could not found Google Benchmark. Benchmark targets will be unavailable.")
endif()

function(add_bench_target target_name target_source)

    if(benchmark_FOUND)
        add_executable(${target_name} benchmarks.cpp ${target_source} ${ARGN})
        target_link_libraries(
            ${target_name} OpenSSE::crypto benchmark::benchmark
        )
        # The benchmarks might use the internals
        target_include_directories(
            ${target_name}
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src
        )

        add_dependencies(bench ${target_name})
    endif()
endfunction()

add_bench_target(benchmark_set_hash bench_set_hash.cpp)
add_bench_target(benchmark_tdp bench_tdp.cpp)
add_bench_target(benchmark_rcprf bench_rcprf.cpp)
