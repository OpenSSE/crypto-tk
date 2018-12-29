cmake_minimum_required (VERSION 3.1)



list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/externals/CMake-codecov/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/externals/sanitizers-cmake/cmake")



# Build in Debug mode by default
set(default_build_type "Debug")

# Options
option(opensse_ENABLE_WALL "Enable all warnings" ON)
option(opensse_ENABLE_WEXTRA "Enable extra warnings" ON)
option(opensse_ENABLE_WERROR "Make all warnings into errors" ON)
option(opensse_OPTIMIZE_FOR_NATIVE_ARCH "Enable compiler optimizations for the native processor architecture (if available)" ON)

# Load modules

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

# enable code coverage
find_package(codecov)

# Find Sanitizers
find_package(Sanitizers)

# We use CMake's integrated testing features
enable_testing()

if (opensse_ENABLE_WALL)
  CHECK_CXX_COMPILER_FLAG("-Wall" COMPILER_OPT_WALL_SUPPORTED)
  if (COMPILER_OPT_WALL_SUPPORTED)
    add_compile_options(-Wall)
  endif()
endif()

if (opensse_ENABLE_WEXTRA)
  CHECK_CXX_COMPILER_FLAG("-Wextra" COMPILER_OPT_WEXTRA_SUPPORTED)
  if (COMPILER_OPT_WEXTRA_SUPPORTED)
    add_compile_options(-Wextra)
  endif()
endif()

if (opensse_ENABLE_WERROR)
  CHECK_CXX_COMPILER_FLAG("-Werror" COMPILER_OPT_WERROR_SUPPORTED)
  if (COMPILER_OPT_WERROR_SUPPORTED)
      add_compile_options(-Werror -Wno-error=unknown-pragmas)
  endif()
endif()

if (opensse_OPTIMIZE_FOR_NATIVE_ARCH)
  CHECK_CXX_COMPILER_FLAG("-march=native" COMPILER_OPT_ARCH_NATIVE_SUPPORTED)
  if (COMPILER_OPT_ARCH_NATIVE_SUPPORTED)
      add_compile_options(-march=native)
  endif()
endif()



CHECK_C_COMPILER_FLAG("-Wpsabi" WARNING_PSABI)
if(WARNING_PSABI)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=psabi")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=psabi")
endif()


# This might be redundant with what is done in the main source
# CMakeLists.txt file: we will look for OpenSSL there too.
# Yet, sse_crypto's CMakeLists.txt file must be standalone, so
# OpenSSL must be looked for in there, and, at the same time,
# the WITH_OPENSSL is needed in the tests.
find_package(OpenSSL 1.0.0) # Optional

if (OPENSSL_FOUND)
    add_definitions(-DWITH_OPENSSL)
endif()


list(APPEND LCOV_REMOVE_PATTERNS '${CMAKE_CURRENT_SOURCE_DIR}/tests/*' '${CMAKE_CURRENT_SOURCE_DIR}/*.cpp' '${CMAKE_CURRENT_SOURCE_DIR}/bench/*' '${CMAKE_CURRENT_SOURCE_DIR}/externals/*')


# To avoid building GTest twice
if (NOT TARGET gtest)
  set(BUILD_GMOCK OFF CACHE BOOL "Disable GMock" FORCE)
  add_subdirectory(externals/googletest)
endif()

add_subdirectory(src)
add_sanitizers(sse_crypto)
add_coverage(sse_crypto)

add_subdirectory(tests)
add_sanitizers(check)
add_coverage(check)

# add_subdirectory(bench)

if(OPENSSL_FOUND)
    add_executable(debug_tool EXCLUDE_FROM_ALL main.cpp)

    set_property(TARGET debug_tool PROPERTY CXX_STANDARD 11)

    target_include_directories(debug_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    target_link_libraries(debug_tool sse_crypto ${OPENSSL_CRYPTO_LIBRARY})

    target_include_directories(debug_tool SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()

coverage_evaluate()