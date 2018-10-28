cmake_minimum_required (VERSION 2.6)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")


INCLUDE(CheckCCompilerFlag)

# Build in Debug mode by default
set(default_build_type "Debug")

option(RSA_IMPL_OPENSSL "Use OpenSSL's implementation of RSA" OFF)


project ("OpenSSE's cryptographic library")
include(CodeCoverage)
include(FindDependencies)

enable_testing()

set(C_WARNING_FLAGS "-Wall -Wextra")

CHECK_C_COMPILER_FLAG("-Wpsabi" WARNING_PSABI)
if(WARNING_PSABI)
    set(C_WARNING_FLAGS "${C_WARNING_FLAGS} -Wno-error=psabi")
endif()

CHECK_C_COMPILER_FLAG("-fsanitize-address-use-after-scope" SANITIZE_USE_AFTER_SCOPE)

set(SANITIZER_FLAGS "-fsanitize=undefined -fsanitize=address -fno-omit-frame-pointer")

if(SANITIZE_USE_AFTER_SCOPE)
    set(SANITIZER_FLAGS "${SANITIZER_FLAGS} -fsanitize-address-use-after-scope")
endif()

if(WARNING_PSABI)
    set(C_WARNING_FLAGS "${C_WARNING_FLAGS} -Wno-error=psabi")
endif()

set(C_COVERAGE_FLAGS "--coverage -fno-inline -fno-inline-small-functions -fno-default-inline -Wno-ignored-optimization-argument")
set(LINK_COVERAGE_FLAGS "--coverage")


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -std=c++11 ${C_WARNING_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native ${C_WARNING_FLAGS}")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g ${SANITIZER_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g ${SANITIZER_FLAGS}")

# Do some code coverage in Debug mode
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    APPEND_COVERAGE_COMPILER_FLAGS()
    set(COVERAGE_EXCLUDES '${CMAKE_CURRENT_SOURCE_DIR}/tests/*' '${CMAKE_CURRENT_SOURCE_DIR}/*.cpp' '${CMAKE_CURRENT_SOURCE_DIR}/bench/*' '${CMAKE_CURRENT_SOURCE_DIR}/gtest/*' '/usr/*' '*v1/*')
endif()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")


include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories("src")


add_subdirectory(gtest)

add_subdirectory(src)
add_subdirectory(tests)

if(OPENSSL_FOUND)
    add_executable(debug_tool main.cpp)
    target_link_libraries(debug_tool sse_crypto ${OPENSSL_CRYPTO_LIBRARY})

    target_include_directories(debug_tool SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()


# add_subdirectory(tests)
# add_subdirectory(bench)
