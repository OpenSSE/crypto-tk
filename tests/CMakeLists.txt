if(${CMAKE_VERSION} VERSION_GREATER "3.10.0") 
    include(GoogleTest)
endif()

add_executable(check checks.cpp encryption.cpp hashing.cpp test_hmac.cpp test_mbedtls.cpp test_ppke.cpp test_prf.cpp test_prg.cpp test_prp.cpp test_set_hash.cpp test_tdp.cpp test_rcprf.cpp)

target_link_libraries(check gtest OpenSSE::crypto)
target_include_directories(check PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)


target_compile_features(check
    PUBLIC
        cxx_auto_type
        cxx_nullptr
        cxx_constexpr
        cxx_defaulted_functions
        cxx_deleted_functions
        cxx_extern_templates
        cxx_noexcept
        cxx_static_assert
        cxx_thread_local
    PRIVATE
        cxx_lambdas
)

if(${CMAKE_VERSION} VERSION_GREATER "3.10.0") 
    gtest_discover_tests(check)
else()
    add_test(check check)
endif()

