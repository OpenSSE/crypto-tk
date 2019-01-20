//
//  rsa_io.c
//  libsse_crypto
//
//  Created by Raphael Bost on 15/11/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#include "rsa_io.h"

#include "pk.h"
#include "asn1write.h"
//#include "oid.h"

#include <string.h>

#if defined(MBEDTLS_RSA_C)
#include "rsa.h"
#endif
#if defined(MBEDTLS_PEM_WRITE_C)
#include "pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#pragma GCC diagnostic push
// mbedTLS does sign conversion everywhere
#pragma GCC diagnostic ignored "-Wsign-conversion"


int mbedtls_rsa_parse_public_key( mbedtls_rsa_context *rsa_ctx,
                                 const unsigned char *key, size_t keylen )
{
    int ret;
    mbedtls_pk_context pk_ctx;
    
    mbedtls_pk_init(&pk_ctx);
    
    ret = mbedtls_pk_parse_public_key( &pk_ctx, key, keylen );
    
    if (ret != 0) {
        goto cleanup;
    }
    
    if( mbedtls_pk_get_type( &pk_ctx ) == MBEDTLS_PK_RSA )
    {
        // copy the key context to rsa_ctx
        mbedtls_rsa_copy(rsa_ctx, mbedtls_pk_rsa(pk_ctx));
    }else{
        ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }
cleanup:
    mbedtls_pk_free(&pk_ctx);
    return ret;
}

/*
 * Parse a private key
 */
int mbedtls_rsa_parse_key( mbedtls_rsa_context *rsa_ctx,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *pwd, size_t pwdlen )
{
    int ret;
    mbedtls_pk_context pk_ctx;

    mbedtls_pk_init(&pk_ctx);

    ret = mbedtls_pk_parse_key( &pk_ctx, key, keylen, pwd, pwdlen );
    
    if (ret != 0) {
        goto cleanup;
    }
    
    if( mbedtls_pk_get_type( &pk_ctx ) == MBEDTLS_PK_RSA )
    {
        // copy the key context to rsa_ctx
        mbedtls_rsa_copy(rsa_ctx, mbedtls_pk_rsa(pk_ctx));
    }else{
        ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }
cleanup:
    mbedtls_pk_free(&pk_ctx);
    return ret;
}


/*
 *  RSAPublicKey ::= SEQUENCE {
 *      modulus           INTEGER,  -- n
 *      publicExponent    INTEGER   -- e
 *  }
 */
static int pk_write_rsa_pubkey( unsigned char **p, unsigned char *start,
                               const mbedtls_rsa_context *rsa )
{
    int ret;
    size_t len = 0;
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( p, start, &rsa->E ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( p, start, &rsa->N ) );
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                      MBEDTLS_ASN1_SEQUENCE ) );
    
    return( (int) len );
}

int mbedtls_rsa_write_pubkey_der( mbedtls_rsa_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c;
    size_t len = 0, par_len = 0;
    
    //#warning WORKAROUND
    // we want to avoid using the oid functions, so the oid is hardcoded here
    size_t oid_len = 9;
    const unsigned char oid[10] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, '\0'};
    
    c = buf + size;
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_rsa_write_pubkey( &c, buf, key ) );
    
    if( c - buf < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );
    
    /*
     *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm            AlgorithmIdentifier,
     *       subjectPublicKey     BIT STRING }
     */
    *--c = 0;
    len += 1;
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_BIT_STRING ) );
    
// Previous implementation used to retrieve the oid
//        if( ( ret = mbedtls_oid_get_oid_by_pk_alg( MBEDTLS_PK_RSA,
//                                           &oid, &oid_len ) ) != 0 )
//        {
//            return( ret );
//        }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( &c, buf, (const char*)oid, oid_len,
                                                                       par_len ) );
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                      MBEDTLS_ASN1_SEQUENCE ) );
    
    return( (int) len );
}

#define MPI_MAX_SIZE_2          MBEDTLS_MPI_MAX_SIZE / 2 + \
MBEDTLS_MPI_MAX_SIZE % 2
#define RSA_PRV_DER_MAX_BYTES   47 + 3 * MBEDTLS_MPI_MAX_SIZE \
+ 5 * MPI_MAX_SIZE_2
#define RSA_PUB_DER_MAX_BYTES   38 + 2 * MBEDTLS_MPI_MAX_SIZE

#define PEM_BEGIN_PUBLIC_KEY    "-----BEGIN PUBLIC KEY-----\n"
#define PEM_END_PUBLIC_KEY      "-----END PUBLIC KEY-----\n"

#define PEM_BEGIN_PRIVATE_KEY_RSA   "-----BEGIN RSA PRIVATE KEY-----\n"
#define PEM_END_PRIVATE_KEY_RSA     "-----END RSA PRIVATE KEY-----\n"

int mbedtls_rsa_write_pubkey_pem( mbedtls_rsa_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char output_buf[RSA_PUB_DER_MAX_BYTES];
    size_t olen = 0;
    
    if( ( ret = mbedtls_rsa_write_pubkey_der( key, output_buf,
                                            sizeof(output_buf) ) ) < 0 )
    {
        return( ret );
    }
    
    if( ( ret = mbedtls_pem_write_buffer( PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
                                         output_buf + sizeof(output_buf) - ret,
                                         ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }
    
    return( 0 );
}

int mbedtls_rsa_write_pubkey( unsigned char **p, unsigned char *start,
                            const mbedtls_rsa_context *key )
{
    int ret;
    size_t len = 0;
    
    MBEDTLS_ASN1_CHK_ADD( len, pk_write_rsa_pubkey( p, start, key ) );

    return( (int) len );
}

int mbedtls_rsa_write_key_der( mbedtls_rsa_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char *c = buf + size;
    size_t len = 0;
    
    mbedtls_rsa_context *rsa = key;
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->QP ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DQ ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->DP ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->Q ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->P ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->D ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->E ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &c, buf, &rsa->N ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_int( &c, buf, 0 ) );
    
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &c, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                      MBEDTLS_ASN1_SEQUENCE ) );
    
    return( (int) len );
}

int mbedtls_rsa_write_key_pem( mbedtls_rsa_context *key, unsigned char *buf, size_t size )
{
    int ret;
    unsigned char output_buf[RSA_PRV_DER_MAX_BYTES];
    const char *begin, *end;
    size_t olen = 0;
    
    if( ( ret = mbedtls_rsa_write_key_der( key, output_buf, sizeof(output_buf) ) ) < 0 )
        return( ret );
    
    begin = PEM_BEGIN_PRIVATE_KEY_RSA;
    end = PEM_END_PRIVATE_KEY_RSA;
    
    if( ( ret = mbedtls_pem_write_buffer( begin, end,
                                         output_buf + sizeof(output_buf) - ret,
                                         ret, buf, size, &olen ) ) != 0 )
    {
        return( ret );
    }
    
    return( 0 );
}

#pragma GCC diagnostic pop
