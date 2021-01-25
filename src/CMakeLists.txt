cmake_minimum_required(VERSION 3.1)

# Duplicate the project declaration: this should be a standalone file
project(libsse_crypto VERSION 0.3 DESCRIPTION "OpenSSE's cryptographic library")

option(RSA_IMPL_OPENSSL "Use OpenSSL's implementation of RSA" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/modules")

find_package(Sodium REQUIRED)
find_package(OpenSSL 1.0.0) # Optional
find_package(relic REQUIRED)
find_package(LibGmp REQUIRED)

if(OPENSSL_FOUND)
    message(STATUS "OpenSSL Include directories:" ${OPENSSL_INCLUDE_DIR})

    # add_definitions(-DWITH_OPENSSL)
else()
    if(RSA_IMPL_OPENSSL)
        message(
            FATAL_ERROR
                "OpenSSL's implementation of RSA was chosen and the OpenSSL library was not found."
        )
    endif()
endif()

# Add an option to choose, if the memory locking mechanisms shoudl be enabled.
option(ENABLE_MEMORY_LOCK "Enable the memory locking mechanisms." ON)

add_library(
    sse_crypto
    SHARED
    cipher.cpp
    key.cpp
    prg.cpp
    tdp.cpp
    prp.cpp
    hmac.cpp
    prf.cpp
    puncturable_enc.cpp
    random.cpp
    utils.cpp
    set_hash.cpp
    rcprf.cpp
    wrapper.cpp
    hash.cpp
    hash/blake2b.cpp
    hash/sha512.cpp
    ppke/GMPpke.cpp
    ppke/util.cpp
    ppke/relic_wrapper/relic_api.cpp
    tdp_impl/tdp_impl_mbedtls.cpp
    tdp_impl/tdp_impl_openssl.cpp
    aez/aez.c
    mbedtls/asn1write.c
    mbedtls/bignum.c
    mbedtls/pk.c
    mbedtls/pkparse.c
    mbedtls/rsa_io.c
    mbedtls/asn1parse.c
    mbedtls/base64.c
    mbedtls/pem.c
    mbedtls/pk_wrap.c
    mbedtls/rsa.c
)


# Generate PIC for the library
set_target_properties(sse_crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Use the appropriate compiler features

set_property(TARGET sse_crypto PROPERTY CXX_STANDARD 11)

target_compile_features(
    sse_crypto
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

target_compile_features(
    sse_crypto
    PRIVATE
    c_std_99
)

target_include_directories(
    sse_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/sse/crypto
)

target_include_directories(
    sse_crypto
    SYSTEM
    PRIVATE ${LIBGMP_INCLUDE_DIR} ${RLC_INCLUDE_DIR}
)

target_link_libraries(sse_crypto sodium ${LIBGMP_LIBRARIES} ${RLC_LIBRARY})

if(OPENSSL_FOUND)
    target_link_libraries(sse_crypto OpenSSL::Crypto)
    if(RSA_IMPL_OPENSSL)
	    #add_compile_definitions(SSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL)
	    add_definitions(-DSSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL)
    endif()
endif()

if(ENABLE_MEMORY_LOCK)
    message(STATUS "Enable memory locks")
    target_compile_definitions(sse_crypto PUBLIC ENABLE_MEMORY_LOCK)
else()
    message(STATUS "Memory locks disabled")
endif(ENABLE_MEMORY_LOCK)

# Installation

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(
    TARGETS sse_crypto
    EXPORT OpenSSECryptoTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# CMake magic

install(
    EXPORT OpenSSECryptoTargets
    FILE OpenSSECryptoTargets.cmake
    NAMESPACE OpenSSE::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/sse"
)
export(TARGETS sse_crypto NAMESPACE OpenSSE:: FILE OpenSSECryptoTargets.cmake)

configure_package_config_file(
    cmake/OpenSSECryptConfig.cmake.in
    OpenSSECryptoConfig.cmake
    INSTALL_DESTINATION
    "${CMAKE_INSTALL_LIBDIR}/cmake/sse"
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/OpenSSECryptoConfigVersion.cmake
    VERSION ${libsse_crypto_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/OpenSSECryptoConfigVersion.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/OpenSSECryptoConfig.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sse
)

install(DIRECTORY cmake/modules DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sse)

# Add an alias
add_library(OpenSSE::crypto ALIAS sse_crypto)

# Documentation

# From https://vicrucann.github.io/tutorials/quick-cmake-doxygen/ and
# https://nazavode.github.io/blog/cmake-doxygen-improved/

# check if Doxygen is installed
find_package(Doxygen)
if(DOXYGEN_FOUND)
    # set input and output files
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/doc/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    message("Doxygen build started")

    set(doxy_extra_files ${CMAKE_CURRENT_SOURCE_DIR}/../README.md)
    set(doxy_html_index_file ${CMAKE_CURRENT_BINARY_DIR}/html/index.html)

    add_custom_command(
        OUTPUT ${doxy_html_index_file}
        COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
        MAIN_DEPENDENCY ${doxyfile}
        ${doxyfile_in}
        DEPENDS sse_crypto ${doxy_extra_files}
        COMMENT "Generating HTML documentation with Doxygen"
    )

    add_custom_target(doc DEPENDS ${doxy_html_index_file})

else(DOXYGEN_FOUND)
    message(
        "Doxygen need to be installed to generate the doxygen documentation"
    )
endif(DOXYGEN_FOUND)
