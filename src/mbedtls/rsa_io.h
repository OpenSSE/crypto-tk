//
//  rsa_io.h
//  libsse_crypto
//
//  Created by Raphael Bost on 15/11/2017.
//  Copyright © 2017 VSSE project. All rights reserved.
//

#ifndef rsa_io_h
#define rsa_io_h

#include "config.h"


#if defined(MBEDTLS_RSA_C)
#include "rsa.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

    
// Read/Parse keys
    
/**
 * \brief           Parse a rsa public key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_rsa_parse_public_key( mbedtls_rsa_context *ctx,
                                const unsigned char *key, size_t keylen );

    
/**
 * \brief           Parse a rsa private key in PEM or DER format
 *
 * \param ctx       key to be initialized
 * \param key       input buffer
 * \param keylen    size of the buffer
 *                  (including the terminating null byte for PEM data)
 * \param pwd       password for decryption (optional)
 * \param pwdlen    size of the password
 *
 * \note            On entry, ctx must be empty, either freshly initialised
 *                  with mbedtls_pk_init() or reset with mbedtls_pk_free(). If you need a
 *                  specific key type, check the result with mbedtls_pk_can_do().
 *
 * \note            The key is also checked for correctness.
 *
 * \return          0 if successful, or a specific PK or PEM error code
 */
int mbedtls_rsa_parse_key( mbedtls_rsa_context *ctx,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *pwd, size_t pwdlen );

    
// Write keys
    
/**
 * \brief           Write a rsa public key to a SubjectPublicKeyInfo DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedtls_rsa_write_pubkey_der( mbedtls_rsa_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a ras public key to a PEM string
 *
 * \param ctx       rsa public key to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int mbedtls_rsa_write_pubkey_pem( mbedtls_rsa_context *ctx, unsigned char *buf, size_t size );

    
/**
 * \brief           Write a subjectPublicKey to ASN.1 data
 *                  Note: function works backwards in data buffer
 *
 * \param p         reference to current position pointer
 * \param start     start of the buffer (for bounds-checking)
 * \param key       public key to write away
 *
 * \return          the length written or a negative error code
 */
int mbedtls_rsa_write_pubkey( unsigned char **p, unsigned char *start,
                            const mbedtls_rsa_context *key );


/**
 * \brief           Write a rsa private key to a PKCS#1 or SEC1 DER structure
 *                  Note: data is written at the end of the buffer! Use the
 *                        return value to determine where you should start
 *                        using the buffer
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          length of data written if successful, or a specific
 *                  error code
 */
int mbedtls_rsa_write_key_der( mbedtls_rsa_context *ctx, unsigned char *buf, size_t size );

/**
 * \brief           Write a rsa private key to a PKCS#1 or SEC1 PEM string
 *
 * \param ctx       private to write away
 * \param buf       buffer to write to
 * \param size      size of the buffer
 *
 * \return          0 if successful, or a specific error code
 */
int mbedtls_rsa_write_key_pem( mbedtls_rsa_context *ctx, unsigned char *buf, size_t size );

#ifdef __cplusplus
}
#endif

#endif /* rsa_io_h */
