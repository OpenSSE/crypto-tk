cmake_minimum_required(VERSION 3.1)

project(
    libsse_crypto
    VERSION 0.3
    DESCRIPTION "OpenSSE's cryptographic library"
)

# Needed on Mac OS for the fuzzing targets
if(APPLE)
    cmake_policy(SET CMP0025 OLD)
endif()
# Indeed, we need a modern Clang (more modern than AppleClang) with support of
# libFuzzer. Unfortunately, Clang is not superbly well supported by CMake on Mac
# OS. I even opened an issue on CMake's tracker about that (and ridiculed
# myself): https://gitlab.kitware.com/cmake/cmake/issues/18785

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_SOURCE_DIR}/externals/CMake-codecov/cmake"
)
list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_SOURCE_DIR}/externals/sanitizers-cmake/cmake"
)
list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_SOURCE_DIR}/externals/cmake-flag-manager/cmake"
)
# Build in Debug mode by default
set(default_build_type "Debug")

# Options
option(opensse_ENABLE_WALL "Enable all warnings" ON)
option(opensse_ENABLE_WEXTRA "Enable extra warnings" ON)
option(opensse_ENABLE_WSHADOW "Enable shadow warning" OFF)
option(opensse_ENABLE_PEDANTIC "Enable pedantic warning" ON)
option(opensse_ENABLE_WERROR "Make all warnings into errors" ON)
option(opensse_ENABLE_BASIC_WARNINGS "Enable basic additional warnings" ON)
option(opensse_ENABLE_ADVANCED_WARNINGS "Enable advanced additional warnings"
       ON
)
option(
    opensse_OPTIMIZE_FOR_NATIVE_ARCH
    "Enable compiler optimizations for the native processor architecture (if available)"
    ON
)

# Load modules

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

include(FlagManager)

# enable code coverage
find_package(codecov)

# Find Sanitizers
find_package(Sanitizers)

# We use CMake's integrated testing features
enable_testing()

if(opensse_ENABLE_WALL)
    save_compile_option(-Wall)
endif()

if(opensse_ENABLE_WEXTRA)
    save_compile_option(-Wextra)
endif()

if(opensse_ENABLE_WSHADOW)
    save_compile_option(-Wshadow)
endif()

if(opensse_ENABLE_PEDANTIC)
    save_compile_option(-pedantic)
endif()

if(opensse_ENABLE_WERROR)
    save_compile_option(
        -Wno-error=unknown-pragmas -Wno-error=unused-function
        -Wno-error=useless-cast -Werror
    )
endif()

if(opensse_OPTIMIZE_FOR_NATIVE_ARCH)
    save_compile_option(-march=native)
endif()

if(opensse_ENABLE_BASIC_WARNINGS)

    save_compile_option(
        -Wmissing-include-dirs
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Woverloaded-virtual
        -Wctor-dtor-privacy
        -Wunsafe-loop-optimizations
        -Wuseless-cast
        -Wformat=2
        -Wcast-qual
        -Wcast-align
    )
    save_compile_option(
        -fno-rtti
        # -fstack-protector -Wstack-protector
    )
endif()

if(opensse_ENABLE_ADVANCED_WARNINGS)
    save_compile_option(
        LIST_NAME
        "Lib_Warnings"
        # -Weffc++ # Weffc++ is too annoying on gcc
        -Wextra-semi # Extra, unnecessary semicolumns
        # -Wsign-conversion # To be enabled -Wconversion # Extremely strict on
        # gcc
        -Wno-c++98-compat # No need to be C++98 compatible: we require C++11
        -Wno-c++98-compat-pedantic
        -Wno-error=padded
        -Wno-error=source-uses-openmp
        -Wno-unused-macros
        -Wno-padded
        # New to MacOs
        -Wno-poison-system-directories
    )

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

        save_compile_option(
            LIST_NAME
            "Clang_Lib_Warnings"
            -Weverything # All Clang warnings
            -Wno-covered-switch-default
            -Wno-exit-time-destructors
            -Wno-weak-vtables
            -Wno-weak-template-vtables
            -Wno-documentation-unknown-command
        )
    endif()
endif()

# This might be redundant with what is done in the main source CMakeLists.txt
# file: we will look for OpenSSL there too. Yet, sse_crypto's CMakeLists.txt
# file must be standalone, so OpenSSL must be looked for in there, and, at the
# same time, the WITH_OPENSSL is needed in the tests.
find_package(OpenSSL 1.0.0) # Optional

if(OPENSSL_FOUND)
    # add_definitions(-DWITH_OPENSSL)
endif()

list(APPEND LCOV_REMOVE_PATTERNS '${CMAKE_CURRENT_SOURCE_DIR}/tests/*'
     '${CMAKE_CURRENT_SOURCE_DIR}/bench/*'
     '${CMAKE_CURRENT_SOURCE_DIR}/externals/*'
)

# To avoid building GTest twice
if(NOT TARGET gtest)
    set(BUILD_GMOCK
        OFF
        CACHE BOOL "Disable GMock" FORCE
    )
    add_subdirectory(externals/googletest)
    # Not adding the sanitizers might cause ASan false positives. See https://gi
    # thub.com/google/sanitizers/wiki/AddressSanitizerContainerOverflow
    add_sanitizers(gtest)
endif()

add_subdirectory(src)
target_apply_saved_options(sse_crypto)
target_apply_saved_options(LIST_NAME "Lib_Warnings" sse_crypto)
target_apply_saved_options(LIST_NAME "Clang_Lib_Warnings" sse_crypto)
add_sanitizers(sse_crypto)
add_coverage(sse_crypto)

# Tests

add_subdirectory(tests)
target_apply_saved_options(check)
add_sanitizers(check)
add_coverage(check)

# Fuzzing

add_subdirectory(fuzzing)

# Benchmarks

add_subdirectory(bench)

if(OPENSSL_FOUND)
    add_executable(debug_tool EXCLUDE_FROM_ALL main.cpp)

    set_property(TARGET debug_tool PROPERTY CXX_STANDARD 11)

    target_include_directories(
        debug_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_link_libraries(debug_tool sse_crypto ${OPENSSL_CRYPTO_LIBRARY})

    target_include_directories(debug_tool SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()

coverage_evaluate()
