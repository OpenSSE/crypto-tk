cmake_minimum_required (VERSION 3.1)
project (libsse_crypto VERSION 0.2 
                       DESCRIPTION "OpenSSE's cryptographic library")



list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/externals/CMake-codecov/cmake")



# Build in Debug mode by default
set(default_build_type "Debug")

# Options
option(RSA_IMPL_OPENSSL "Use OpenSSL's implementation of RSA" OFF)

# Load modules

include(CheckCCompilerFlag)

# Find all the dependencies for this project
include(FindDependencies)

# enable code coverage
find_package(codecov)

# We use CMake's integrated testing features
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


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native ${C_WARNING_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native ${C_WARNING_FLAGS}")

# set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${SANITIZER_FLAGS}")
# set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${SANITIZER_FLAGS}")

# Do some code coverage in Debug mode
# if(CMAKE_BUILD_TYPE STREQUAL "Debug")
#     set(COVERAGE_EXCLUDES '${CMAKE_CURRENT_SOURCE_DIR}/tests/*' '${CMAKE_CURRENT_SOURCE_DIR}/*.cpp' '${CMAKE_CURRENT_SOURCE_DIR}/bench/*' '${CMAKE_CURRENT_SOURCE_DIR}/gtest/*' '/usr/*' '*v1/*')
# endif()


list(APPEND LCOV_REMOVE_PATTERNS '${CMAKE_CURRENT_SOURCE_DIR}/tests/*' '${CMAKE_CURRENT_SOURCE_DIR}/*.cpp' '${CMAKE_CURRENT_SOURCE_DIR}/bench/*' '${CMAKE_CURRENT_SOURCE_DIR}/gtest/*')

add_subdirectory(gtest)

add_subdirectory(src)

add_subdirectory(tests)
# add_subdirectory(bench)

if(OPENSSL_FOUND)
    add_executable(debug_tool main.cpp)

    target_include_directories(debug_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    target_link_libraries(debug_tool sse_crypto ${OPENSSL_CRYPTO_LIBRARY})

    target_include_directories(debug_tool SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()

coverage_evaluate()