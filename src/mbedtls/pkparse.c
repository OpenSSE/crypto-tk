/*
 *  Public Key layer for parsing key files and structures
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "config.h"

#if defined(MBEDTLS_PK_PARSE_C)

#include "pk.h"
#include "asn1.h"
//#include "oid.h"

#include <string.h>

#if defined(MBEDTLS_RSA_C)
#include "rsa.h"
#endif
#if defined(MBEDTLS_PEM_PARSE_C)
#include "pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif


#if defined(MBEDTLS_RSA_C)
/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_get_rsapubkey( unsigned char **p,
                             const unsigned char *end,
                             mbedtls_rsa_context *rsa )
{
    int ret;
    size_t len;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( ret = mbedtls_asn1_get_mpi( p, end, &rsa->N ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( p, end, &rsa->E ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( ret = mbedtls_rsa_check_pubkey( rsa ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY );

    rsa->len = mbedtls_mpi_size( &rsa->N );

    return( 0 );
}
#endif /* MBEDTLS_RSA_C */

/* Get a PK algorithm identifier
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *       algorithm               OBJECT IDENTIFIER,
 *       parameters              ANY DEFINED BY algorithm OPTIONAL  }
 */
static int pk_get_pk_alg( unsigned char **p,
                          const unsigned char *end,
                          mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params )
{
    int ret;
    mbedtls_asn1_buf alg_oid;

    memset( params, 0, sizeof(mbedtls_asn1_buf) );

    if( ( ret = mbedtls_asn1_get_alg( p, end, &alg_oid, params ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_ALG + ret );

    // WORKAROUND
    // In the original mbedTLS, we have the following lines
    //    if( mbedtls_oid_get_pk_alg( &alg_oid, pk_alg ) != 0 )
    //        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );
    //
    // which we replace by
    
    if( alg_oid.len != 9 || memcmp(alg_oid.p, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", alg_oid.len) != 0 )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );
    *pk_alg = MBEDTLS_PK_RSA;


    /*
     * No parameters with RSA (only for EC)
     */
    if( *pk_alg == MBEDTLS_PK_RSA &&
            ( ( params->tag != MBEDTLS_ASN1_NULL && params->tag != 0 ) ||
                params->len != 0 ) )
    {
        return( MBEDTLS_ERR_PK_INVALID_ALG );
    }

    return( 0 );
}

/*
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING }
 */
int mbedtls_pk_parse_subpubkey( unsigned char **p, const unsigned char *end,
                        mbedtls_pk_context *pk )
{
    int ret;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = *p + len;

    if( ( ret = pk_get_pk_alg( p, end, &pk_alg, &alg_params ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_asn1_get_bitstring_null( p, end, &len ) ) != 0 )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY + ret );

    if( *p + len != end )
        return( MBEDTLS_ERR_PK_INVALID_PUBKEY +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );

    if( ( pk_info = mbedtls_pk_info_from_type( pk_alg ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG ); /* LCOV_EXCL_LINE */ // An algorithm different from RSA would have been detected earlier

    if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret ); /* LCOV_EXCL_LINE */

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA )
    {
        ret = pk_get_rsapubkey( p, end, mbedtls_pk_rsa( *pk ) );
    } else
#endif /* MBEDTLS_RSA_C */
        ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG; /* LCOV_EXCL_LINE */ // An algorithm different from RSA would have been detected earlier

    if( ret == 0 && *p != end )
        ret = MBEDTLS_ERR_PK_INVALID_PUBKEY
              MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;

    if( ret != 0 )
        mbedtls_pk_free( pk );

    return( ret );
}

#if defined(MBEDTLS_RSA_C)
/*
 * Parse a PKCS#1 encoded private RSA key
 */
static int pk_parse_key_pkcs1_der( mbedtls_rsa_context *rsa,
                                   const unsigned char *key,
                                   size_t keylen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;

    // manually ignore const cast warning.
    // fixing this would require a lot of change in the code
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    p = (unsigned char *) key;
    end = p + keylen;
#pragma GCC diagnostic pop

    /*
     * This function parses the RSAPrivateKey (PKCS#1)
     *
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
     *      coefficient       INTEGER,  -- (inverse of q) mod p
     *      otherPrimeInfos   OtherPrimeInfos OPTIONAL
     *  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &rsa->ver ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    if( rsa->ver != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_VERSION );
    }

    if( ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->N  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->E  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->D  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->P  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->Q  ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->DP ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->DQ ) ) != 0 ||
        ( ret = mbedtls_asn1_get_mpi( &p, end, &rsa->QP ) ) != 0 )
    {
        mbedtls_rsa_free( rsa );
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    rsa->len = mbedtls_mpi_size( &rsa->N );

    if( p != end )
    {
        mbedtls_rsa_free( rsa );
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    if( ( ret = mbedtls_rsa_check_privkey( rsa ) ) != 0 )
    {
        mbedtls_rsa_free( rsa );
        return( ret );
    }

    return( 0 );
}
#endif /* MBEDTLS_RSA_C */

/*
 * Parse an unencrypted PKCS#8 encoded private key
 */
static int pk_parse_key_pkcs8_unencrypted_der(
                                    mbedtls_pk_context *pk,
                                    const unsigned char* key,
                                    size_t keylen )
{
    int ret, version;
    size_t len;
    mbedtls_asn1_buf params;
    // manually ignore const cast warning.
    // fixing this would require a lot of change in the code
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = p + keylen;
#pragma GCC diagnostic pop
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    const mbedtls_pk_info_t *pk_info;

    /*
     * This function parses the PrivatKeyInfo object (PKCS#8 v1.2 = RFC 5208)
     *
     *    PrivateKeyInfo ::= SEQUENCE {
     *      version                   Version,
     *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *      privateKey                PrivateKey,
     *      attributes           [0]  IMPLICIT Attributes OPTIONAL }
     *
     *    Version ::= INTEGER
     *    PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *    PrivateKey ::= OCTET STRING
     *
     *  The PrivateKey OCTET STRING is a SEC1 ECPrivateKey
     */

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );
    }

    end = p + len;

    if( ( ret = mbedtls_asn1_get_int( &p, end, &version ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( version != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_VERSION + ret );

    if( ( ret = pk_get_pk_alg( &p, end, &pk_alg, &params ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_OCTET_STRING ) ) != 0 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT + ret );

    if( len < 1 )
        return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_OUT_OF_DATA );

    if( ( pk_info = mbedtls_pk_info_from_type( pk_alg ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info ) ) != 0 )
        return( ret );

#if defined(MBEDTLS_RSA_C)
    if( pk_alg == MBEDTLS_PK_RSA )
    {
        if( ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ), p, len ) ) != 0 )
        {
            mbedtls_pk_free( pk );
            return( ret );
        }
    } else
#endif /* MBEDTLS_RSA_C */
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    return( 0 );
}

/*
 * Parse a private key
 */
int mbedtls_pk_parse_key( mbedtls_pk_context *pk,
                  const unsigned char *key, size_t keylen,
                  const unsigned char *pwd, size_t pwdlen )
{
    int ret;
    const mbedtls_pk_info_t *pk_info;

#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;

    mbedtls_pem_init( &pem );

#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN RSA PRIVATE KEY-----",
                               "-----END RSA PRIVATE KEY-----",
                               key, pwd, pwdlen, &len );

    if( ret == 0 )
    {
        if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == NULL )
            return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

        if( ( ret = mbedtls_pk_setup( pk, pk_info                    ) ) != 0 ||
            ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ),
                                            pem.buf, pem.buflen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH )
        return( MBEDTLS_ERR_PK_PASSWORD_MISMATCH ); /* LCOV_EXCL_LINE */
    else if( ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED )
        return( MBEDTLS_ERR_PK_PASSWORD_REQUIRED ); /* LCOV_EXCL_LINE */
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );
#endif /* MBEDTLS_RSA_C */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN PRIVATE KEY-----",
                               "-----END PRIVATE KEY-----",
                               key, NULL, 0, &len );
    if( ret == 0 )
    {
        if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk,
                                                pem.buf, pem.buflen ) ) != 0 )
        {
            mbedtls_pk_free( pk );
        }

        mbedtls_pem_free( &pem );
        return( ret );
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
        return( ret );

#else
    ((void) ret);
    ((void) pwd);
    ((void) pwdlen);
#endif /* MBEDTLS_PEM_PARSE_C */

    /*
     * At this point we only know it's not a PEM formatted key. Could be any
     * of the known DER encoded private key formats
     *
     * We try the different DER format parsers to see if one passes without
     * error
     */

    if( ( ret = pk_parse_key_pkcs8_unencrypted_der( pk, key, keylen ) ) == 0 )
        return( 0 );

    mbedtls_pk_free( pk );

#if defined(MBEDTLS_RSA_C)
    if( ( pk_info = mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) == NULL )
        return( MBEDTLS_ERR_PK_UNKNOWN_PK_ALG );

    if( ( ret = mbedtls_pk_setup( pk, pk_info                           ) ) != 0 ||
        ( ret = pk_parse_key_pkcs1_der( mbedtls_pk_rsa( *pk ), key, keylen ) ) == 0 )
    {
        return( 0 );
    }

    mbedtls_pk_free( pk );
#endif /* MBEDTLS_RSA_C */

    return( MBEDTLS_ERR_PK_KEY_INVALID_FORMAT );
}

/*
 * Parse a public key
 */
int mbedtls_pk_parse_public_key( mbedtls_pk_context *ctx,
                         const unsigned char *key, size_t keylen )
{
    int ret;
    unsigned char *p;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;

    mbedtls_pem_init( &pem );

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( keylen == 0 || key[keylen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                "-----BEGIN PUBLIC KEY-----",
                "-----END PUBLIC KEY-----",
                key, NULL, 0, &len );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded
         */
        key = pem.buf;
        keylen = pem.buflen;
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        mbedtls_pem_free( &pem ); /* LCOV_EXCL_LINE */
        return( ret ); /* LCOV_EXCL_LINE */
    }
#endif /* MBEDTLS_PEM_PARSE_C */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    p = (unsigned char *) key;
#pragma GCC diagnostic pop

    ret = mbedtls_pk_parse_subpubkey( &p, p + keylen, ctx );

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_free( &pem );
#endif

    return( ret );
}

#endif /* MBEDTLS_PK_PARSE_C */
