set(
    FUZZING_FLAGS
    "-fsanitize=fuzzer -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep"
    "-fsanitize=fuzzer"
)
set(FUZZING_STANDALONE_FLAGS "-fsanitize=fuzzer-no-link")

sanitizer_check_compiler_flags("${FUZZING_FLAGS}" "libFuzzer" "libFuzzer")
sanitizer_check_compiler_flags(
    "${FUZZING_STANDALONE_FLAGS}" "libFuzzer (standalone target)"
    "libFuzzer_standalone"
)

add_custom_target(fuzz)

function(add_fuzz_target target_name target_source)

    if(libFuzzer_FLAG_DETECTED)
        add_executable(${target_name} ${target_source} ${ARGN})
        target_link_libraries(${target_name} OpenSSE::crypto)
        add_sanitizers(${target_name})
        sanitizer_add_flags(${target_name} "libFuzzer" "libFuzzer")

        add_dependencies(fuzz ${target_name})
        target_apply_saved_options(${target_name})

        if(libFuzzer_standalone_FLAG_DETECTED)

            add_executable(
                ${target_name}_standalone
                StandaloneFuzzTargetMain.c
                ${target_source}
                ${ARGN}
            )
            target_apply_saved_options(${target_name}_standalone)

            target_link_libraries(${target_name}_standalone OpenSSE::crypto)
            add_sanitizers(${target_name}_standalone)

            sanitizer_add_flags(
                ${target_name}_standalone "libFuzzer (standalone target)"
                "libFuzzer_standalone"
            )
            add_dependencies(fuzz ${target_name}_standalone)
        endif()
    endif()

endfunction()

add_fuzz_target("strstrn_fuzz" targets/strstrn.cpp)
