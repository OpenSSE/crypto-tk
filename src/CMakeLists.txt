set(CMAKE_MACOSX_RPATH 1)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

find_library(LIB_SODIUM
         NAMES sodium)
find_library(LIB_RELIC
         NAMES relic librelic_s.a)

add_library(libsse_crypto SHARED 
                cipher.cpp key.cpp prg.cpp tdp.cpp prp.cpp hmac.cpp prf.cpp
                puncturable_enc.cpp random.cpp utils.cpp set_hash.cpp
                hash.cpp hash/blake2b.cpp hash/sha512.cpp
                ppke/GMPpke.cpp ppke/util.cpp ppke/relic_wrapper/relic_api.cpp
                tdp_impl/tdp_impl_mbedtls.cpp tdp_impl/tdp_impl_openssl.cpp
                aez/aez.c           
                mbedtls/asn1write.c mbedtls/bignum.c mbedtls/pk.c mbedtls/pkparse.c mbedtls/rsa_io.c mbedtls/asn1parse.c mbedtls/base64.c mbedtls/pem.c mbedtls/pk_wrap.c mbedtls/rsa.c
            )

target_link_libraries(libsse_crypto ${LIB_SODIUM} ${LIB_RELIC})