if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
    include(GoogleTest)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/../src/cmake/modules")

find_package(relic REQUIRED)
find_package(LibGmp REQUIRED)

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

target_link_libraries(check gtest OpenSSE::crypto ${LIBGMP_LIBRARIES} ${RLC_LIBRARY})
target_include_directories(
    check
    SYSTEM
    PRIVATE ${LIBGMP_INCLUDE_DIR} ${RLC_INCLUDE_DIR}
)
target_include_directories(check PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)

if(${CMAKE_VERSION} VERSION_GREATER "3.10.0")
    gtest_discover_tests(check)
else()
    add_test(check check)
endif()
