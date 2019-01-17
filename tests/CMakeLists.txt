if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
    include(GoogleTest)
endif()

add_executable(
    check
    checks.cpp
    encryption.cpp
    hashing.cpp
    test_hmac.cpp
    test_mbedtls.cpp
    test_ppke.cpp
    test_prf.cpp
    test_prg.cpp
    test_prp.cpp
    test_set_hash.cpp
    test_tdp.cpp
    test_rcprf.cpp
    test_utility.cpp
)

target_link_libraries(check gtest OpenSSE::crypto)
target_include_directories(check PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
    gtest_discover_tests(check)
else()
    add_test(check check)
endif()
