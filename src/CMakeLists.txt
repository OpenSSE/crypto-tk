cmake_minimum_required (VERSION 3.1)

option(RSA_IMPL_OPENSSL "Use OpenSSL's implementation of RSA" OFF)


find_library(LIB_SODIUM NAMES sodium)

find_library(LIB_RELIC NAMES relic librelic_s.a)

include(FindOpenSSL)

if (OPENSSL_FOUND)
    message (STATUS "OpenSSL Include directories:" ${OPENSSL_INCLUDE_DIR})

    add_definitions(-DWITH_OPENSSL)
else() 
    if(RSA_IMPL_OPENSSL)
        message(FATAL_ERROR "OpenSSL's implementation of RSA was chosen and the OpenSSL library was not found.")
    endif()
endif()

add_library(sse_crypto SHARED 
                cipher.cpp key.cpp prg.cpp tdp.cpp prp.cpp hmac.cpp prf.cpp
                puncturable_enc.cpp random.cpp utils.cpp set_hash.cpp
                hash.cpp hash/blake2b.cpp hash/sha512.cpp
                ppke/GMPpke.cpp ppke/util.cpp ppke/relic_wrapper/relic_api.cpp
                tdp_impl/tdp_impl_mbedtls.cpp tdp_impl/tdp_impl_openssl.cpp
                aez/aez.c
                mbedtls/asn1write.c mbedtls/bignum.c 
                mbedtls/pk.c mbedtls/pkparse.c mbedtls/rsa_io.c
                mbedtls/asn1parse.c mbedtls/base64.c mbedtls/pem.c 
                mbedtls/pk_wrap.c mbedtls/rsa.c           
            )

# Generate PIC for the library
set_target_properties(sse_crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Use the appropriate compiler features

target_compile_features(sse_crypto
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

target_include_directories(sse_crypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/sse/crypto)

target_link_libraries(sse_crypto ${LIB_SODIUM} ${LIB_RELIC})

if(OPENSSL_FOUND)
    target_include_directories(sse_crypto SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(sse_crypto ${OPENSSL_CRYPTO_LIBRARY})
if(RSA_IMPL_OPENSSL)
    add_compile_definitions(SSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL)
endif()
endif()