set(CMAKE_MACOSX_RPATH 1)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")


add_subdirectory(mbedtls)

add_library(sse_crypto SHARED 
                cipher.cpp key.cpp prg.cpp tdp.cpp prp.cpp hmac.cpp prf.cpp
                puncturable_enc.cpp random.cpp utils.cpp set_hash.cpp
                hash.cpp hash/blake2b.cpp hash/sha512.cpp
                ppke/GMPpke.cpp ppke/util.cpp ppke/relic_wrapper/relic_api.cpp
                tdp_impl/tdp_impl_mbedtls.cpp tdp_impl/tdp_impl_openssl.cpp
                aez/aez.c           
                $<TARGET_OBJECTS:mbedTLS_lite> 
            )

target_link_libraries(sse_crypto ${LIB_SODIUM} ${LIB_RELIC})


if(OPENSSL_FOUND)
    target_include_directories(sse_crypto SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(sse_crypto ${OPENSSL_CRYPTO_LIBRARY})
if(RSA_IMPL_OPENSSL)
    add_compile_definitions(SSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL)
endif()
endif()