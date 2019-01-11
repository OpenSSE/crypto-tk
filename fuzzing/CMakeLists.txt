set(FUZZING_FLAGS "-fsanitize=fuzzer")
set(FUZZING_STANDALONE_FLAGS "-fsanitize=fuzzer-no-link")

sanitizer_check_compiler_flags("${FUZZING_FLAGS}" "libFuzzer" "libFuzzer")
sanitizer_check_compiler_flags("${FUZZING_STANDALONE_FLAGS}" "libFuzzer (standalone target)" "libFuzzer_standalone")

add_custom_target(fuzz)

function(add_fuzz_target target_name target_source)

    add_executable(${target_name} ${target_source})
    sanitizer_add_flags(${target_name} "libFuzzer" "libFuzzer")
    sanitizer_add_flags(${target_name}_standalone "libFuzzer (standalone target)" "libFuzzer")

    add_dependencies(fuzz ${target_name} ${target_name}_standalone)

endfunction()
