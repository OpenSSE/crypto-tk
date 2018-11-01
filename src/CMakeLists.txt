
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
set(sse_crypto_build_include_dirs
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}")
message(STATUS "${CMAKE_SOURCE_DIR}/include")
message(STATUS "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(sse_crypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} 
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/opensse/crypto)

# target_include_directories(sse_crypto  PUBLIC
#     "$<BUILD_INTERFACE:${sse_crypto_build_include_dirs}>"
#     "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>")

target_link_libraries(sse_crypto ${LIB_SODIUM} ${LIB_RELIC})

if(OPENSSL_FOUND)
    target_include_directories(sse_crypto SYSTEM PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(sse_crypto ${OPENSSL_CRYPTO_LIBRARY})
if(RSA_IMPL_OPENSSL)
    add_compile_definitions(SSE_CRYPTO_TDP_IMPL=SSE_CRYPTO_TDP_IMPL_OPENSSL)
endif()
endif()

# Generate PIC for the library
set_target_properties(sse_crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)
