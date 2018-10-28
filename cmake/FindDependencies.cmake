find_library(LIB_SODIUM NAMES sodium)

find_library(LIB_RELIC NAMES relic librelic_s.a)

include(FindOpenSSL)

if (OPENSSL_FOUND)
    message (STATUS "OpenSSL Include directories:" ${OPENSSL_INCLUDE_DIR})

    add_compile_definitions(WITH_OPENSSL)
else() 
    if(RSA_IMPL_OPENSSL)
        message(FATAL_ERROR "OpenSSL's implementation of RSA was chosen and theb OpenSSL library was not found.")
    endif()
endif()
