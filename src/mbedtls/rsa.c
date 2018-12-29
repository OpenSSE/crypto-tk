/*
 *  The RSA public-key cryptosystem
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
/*
 *  The following sources were referenced in the design of this implementation
 *  of the RSA algorithm:
 *
 *  [1] A method for obtaining digital signatures and public-key cryptosystems
 *      R Rivest, A Shamir, and L Adleman
 *      http://people.csail.mit.edu/rivest/pubs.html#RSA78
 *
 *  [2] Handbook of Applied Cryptography - 1997, Chapter 8
 *      Menezes, van Oorschot and Vanstone
 *
 *  [3] Malware Guard Extension: Using SGX to Conceal Cache Attacks
 *      Michael Schwarz, Samuel Weiser, Daniel Gruss, Clémentine Maurice and
 *      Stefan Mangard
 *      https://arxiv.org/abs/1702.08719v2
 *
 */

#include "config.h"

#if defined(MBEDTLS_RSA_C)

#include "rsa.h"

#include <string.h>

#if defined(MBEDTLS_PKCS1_V15) && !defined(__OpenBSD__)
#include <stdlib.h>
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_calloc calloc
#define mbedtls_free   free
#endif


/*
 * Initialize an RSA context
 */
void mbedtls_rsa_init( mbedtls_rsa_context *ctx,
               int padding,
               int hash_id )
{
    memset( ctx, 0, sizeof( mbedtls_rsa_context ) );

    mbedtls_rsa_set_padding( ctx, padding, hash_id );

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init( &ctx->mutex );
#endif
}

/*
 * Set padding for an existing RSA context
 */
void mbedtls_rsa_set_padding( mbedtls_rsa_context *ctx, int padding, int hash_id )
{
    ctx->padding = padding;
    ctx->hash_id = hash_id;
}

#if defined(MBEDTLS_GENPRIME)

/*
 * Generate an RSA keypair
 */
int mbedtls_rsa_gen_key( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 unsigned int nbits, int exponent )
{
    int ret;
    mbedtls_mpi P1, Q1, H, G;

    if( f_rng == NULL || nbits < 128 || exponent < 3 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    if( nbits % 2 )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 );
    mbedtls_mpi_init( &H ); mbedtls_mpi_init( &G );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_lset( &ctx->E, exponent ) );

    do
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->P, nbits >> 1, 0,
                                f_rng, p_rng ) );

        MBEDTLS_MPI_CHK( mbedtls_mpi_gen_prime( &ctx->Q, nbits >> 1, 0,
                                f_rng, p_rng ) );

        if( mbedtls_mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mbedtls_mpi_bitlen( &ctx->N ) != nbits )
            continue;

        if( mbedtls_mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
                                mbedtls_mpi_swap( &ctx->P, &ctx->Q );

        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P1, &ctx->P, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mbedtls_mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mbedtls_mpi_bitlen( &ctx->N ) + 7 ) >> 3;

cleanup:

    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &H ); mbedtls_mpi_free( &G );

    if( ret != 0 )
    {
        mbedtls_rsa_free( ctx ); /* LCOV_EXCL_LINE */
        return( MBEDTLS_ERR_RSA_KEY_GEN_FAILED + ret ); /* LCOV_EXCL_LINE */
    }

    return( 0 );
}

#endif /* MBEDTLS_GENPRIME */

/*
 * Check a public RSA key
 */
int mbedtls_rsa_check_pubkey( const mbedtls_rsa_context *ctx )
{
    if( !ctx->N.p || !ctx->E.p )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( ( ctx->N.p[0] & 1 ) == 0 ||
        ( ctx->E.p[0] & 1 ) == 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( mbedtls_mpi_bitlen( &ctx->N ) < 128 ||
        mbedtls_mpi_bitlen( &ctx->N ) > MBEDTLS_MPI_MAX_BITS )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    if( mbedtls_mpi_bitlen( &ctx->E ) < 2 ||
        mbedtls_mpi_cmp_mpi( &ctx->E, &ctx->N ) >= 0 )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int mbedtls_rsa_check_privkey( const mbedtls_rsa_context *ctx )
{
    int ret;
    mbedtls_mpi PQ, DE, P1, Q1, H, I, G, G2, L1, L2, DP, DQ, QP;

    if( ( ret = mbedtls_rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    if( !ctx->P.p || !ctx->Q.p || !ctx->D.p )
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );

    mbedtls_mpi_init( &PQ ); mbedtls_mpi_init( &DE ); mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 );
    mbedtls_mpi_init( &H  ); mbedtls_mpi_init( &I  ); mbedtls_mpi_init( &G  ); mbedtls_mpi_init( &G2 );
    mbedtls_mpi_init( &L1 ); mbedtls_mpi_init( &L2 ); mbedtls_mpi_init( &DP ); mbedtls_mpi_init( &DQ );
    mbedtls_mpi_init( &QP );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P1, &ctx->P, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &H, &P1, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G, &ctx->E, &H  ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &G2, &P1, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_div_mpi( &L1, &L2, &H, &G2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &I, &DE, &L1  ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &DP, &ctx->D, &P1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &DQ, &ctx->D, &Q1 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &QP, &ctx->Q, &ctx->P ) );
    /*
     * Check for a valid PKCS1v2 private key
     */
    if( mbedtls_mpi_cmp_mpi( &PQ, &ctx->N ) != 0 ||
        mbedtls_mpi_cmp_mpi( &DP, &ctx->DP ) != 0 ||
        mbedtls_mpi_cmp_mpi( &DQ, &ctx->DQ ) != 0 ||
        mbedtls_mpi_cmp_mpi( &QP, &ctx->QP ) != 0 ||
        mbedtls_mpi_cmp_int( &L2, 0 ) != 0 ||
        mbedtls_mpi_cmp_int( &I, 1 ) != 0 ||
        mbedtls_mpi_cmp_int( &G, 1 ) != 0 )
    {
        ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

cleanup:
    mbedtls_mpi_free( &PQ ); mbedtls_mpi_free( &DE ); mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 );
    mbedtls_mpi_free( &H  ); mbedtls_mpi_free( &I  ); mbedtls_mpi_free( &G  ); mbedtls_mpi_free( &G2 );
    mbedtls_mpi_free( &L1 ); mbedtls_mpi_free( &L2 ); mbedtls_mpi_free( &DP ); mbedtls_mpi_free( &DQ );
    mbedtls_mpi_free( &QP );

    if( ret == MBEDTLS_ERR_RSA_KEY_CHECK_FAILED )
        return( ret );

    if( ret != 0 ) /* LCOV_EXCL_LINE */
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED + ret ); /* LCOV_EXCL_LINE */

    return( 0 );
}

/*
 * Check if contexts holding a public and private key match
 */
int mbedtls_rsa_check_pub_priv( const mbedtls_rsa_context *pub, const mbedtls_rsa_context *prv )
{
    if( mbedtls_rsa_check_pubkey( pub ) != 0 ||
        mbedtls_rsa_check_privkey( prv ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    if( mbedtls_mpi_cmp_mpi( &pub->N, &prv->N ) != 0 ||
        mbedtls_mpi_cmp_mpi( &pub->E, &prv->E ) != 0 )
    {
        return( MBEDTLS_ERR_RSA_KEY_CHECK_FAILED );
    }

    return( 0 );
}

/*
 * Do an RSA public key operation
 */
int mbedtls_rsa_public( mbedtls_rsa_context *ctx,
                const unsigned char *input,
                unsigned char *output )
{
    int ret;
    size_t olen;
    mbedtls_mpi T;

    mbedtls_mpi_init( &T );

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );

    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    mbedtls_mpi_free( &T );

    if( ret != 0 )
        return( MBEDTLS_ERR_RSA_PUBLIC_FAILED + ret );

    return( 0 );
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, count = 0;

    if( ctx->Vf.p != NULL )
    {
        /* We already have blinding values, just update them by squaring */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vi, &ctx->Vi, &ctx->Vi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vi, &ctx->Vi, &ctx->N ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &ctx->Vf, &ctx->Vf, &ctx->Vf ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &ctx->Vf, &ctx->Vf, &ctx->N ) );

        goto cleanup;
    }

    /* Unblinding value: Vf = random number, invertible mod N */
    do {
        if( count++ > 10 )
            return( MBEDTLS_ERR_RSA_RNG_FAILED ); /* LCOV_EXCL_LINE */

        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &ctx->Vf, ctx->len - 1, f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_gcd( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    } while( mbedtls_mpi_cmp_int( &ctx->Vi, 1 ) != 0 );

    /* Blinding value: Vi =  Vf^(-e) mod N */
    MBEDTLS_MPI_CHK( mbedtls_mpi_inv_mod( &ctx->Vi, &ctx->Vf, &ctx->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &ctx->Vi, &ctx->Vi, &ctx->E, &ctx->N, &ctx->RN ) );


cleanup:
    return( ret );
}

/*
 * Exponent blinding supposed to prevent side-channel attacks using multiple
 * traces of measurements to recover the RSA key. The more collisions are there,
 * the more bits of the key can be recovered. See [3].
 *
 * Collecting n collisions with m bit long blinding value requires 2^(m-m/n)
 * observations on avarage.
 *
 * For example with 28 byte blinding to achieve 2 collisions the adversary has
 * to make 2^112 observations on avarage.
 *
 * (With the currently (as of 2017 April) known best algorithms breaking 2048
 * bit RSA requires approximately as much time as trying out 2^112 random keys.
 * Thus in this sense with 28 byte blinding the security is not reduced by
 * side-channel attacks like the one in [3])
 *
 * This countermeasure does not help if the key recovery is possible with a
 * single trace.
 */
#define RSA_EXPONENT_BLINDING 28

/*
 * Do an RSA private key operation
 */
int mbedtls_rsa_private( mbedtls_rsa_context *ctx,
                 int (*f_rng)(void *, unsigned char *, size_t),
                 void *p_rng,
                 const unsigned char *input,
                 unsigned char *output )
{
    int ret;
    size_t olen;
    mbedtls_mpi T, T1, T2;
    mbedtls_mpi P1, Q1, R;
#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi D_blind;
    mbedtls_mpi *D = &ctx->D;
#else
    mbedtls_mpi DP_blind, DQ_blind;
    mbedtls_mpi *DP = &ctx->DP;
    mbedtls_mpi *DQ = &ctx->DQ;
#endif

    /* Make sure we have private key info, prevent possible misuse */
    if( ctx->P.p == NULL || ctx->Q.p == NULL || ctx->D.p == NULL )
        return( MBEDTLS_ERR_RSA_BAD_INPUT_DATA );

    mbedtls_mpi_init( &T ); mbedtls_mpi_init( &T1 ); mbedtls_mpi_init( &T2 );
    mbedtls_mpi_init( &P1 ); mbedtls_mpi_init( &Q1 ); mbedtls_mpi_init( &R );


    if( f_rng != NULL )
    {
#if defined(MBEDTLS_RSA_NO_CRT)
        mbedtls_mpi_init( &D_blind );
#else
        mbedtls_mpi_init( &DP_blind );
        mbedtls_mpi_init( &DQ_blind );
#endif
    }


#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &T, input, ctx->len ) );
    if( mbedtls_mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    if( f_rng != NULL )
    {
        /*
         * Blinding
         * T = T * Vi mod N
         */
        MBEDTLS_MPI_CHK( rsa_prepare_blinding( ctx, f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vi ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );

        /*
         * Exponent blinding
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &P1, &ctx->P, 1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_sub_int( &Q1, &ctx->Q, 1 ) );

#if defined(MBEDTLS_RSA_NO_CRT)
        /*
         * D_blind = ( P - 1 ) * ( Q - 1 ) * R + D
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                         f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &D_blind, &P1, &Q1 ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &D_blind, &D_blind, &R ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &D_blind, &D_blind, &ctx->D ) );

        D = &D_blind;
#else
        /*
         * DP_blind = ( P - 1 ) * R + DP
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                         f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DP_blind, &P1, &R ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &DP_blind, &DP_blind,
                    &ctx->DP ) );

        DP = &DP_blind;

        /*
         * DQ_blind = ( Q - 1 ) * R + DQ
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_fill_random( &R, RSA_EXPONENT_BLINDING,
                         f_rng, p_rng ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &DQ_blind, &Q1, &R ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &DQ_blind, &DQ_blind,
                    &ctx->DQ ) );

        DQ = &DQ_blind;
#endif /* MBEDTLS_RSA_NO_CRT */
    }

#if defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T, &T, D, &ctx->N, &ctx->RN ) );
#else
    /*
     * Faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T1, &T, DP, &ctx->P, &ctx->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_exp_mod( &T2, &T, DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_sub_mpi( &T, &T1, &T2 ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * T = T2 + T * Q
     */
    MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( &T, &T2, &T1 ) );
#endif /* MBEDTLS_RSA_NO_CRT */

    if( f_rng != NULL )
    {
        /*
         * Unblind
         * T = T * Vf mod N
         */
        MBEDTLS_MPI_CHK( mbedtls_mpi_mul_mpi( &T, &T, &ctx->Vf ) );
        MBEDTLS_MPI_CHK( mbedtls_mpi_mod_mpi( &T, &T, &ctx->N ) );
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &T, output, olen ) );

cleanup:
#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    // erase the temporary variable
    mbedtls_mpi_lset(&T, 0);
    mbedtls_mpi_lset(&T1, 0);
    mbedtls_mpi_lset(&T2, 0);
    mbedtls_mpi_lset(&P1, 0);
    mbedtls_mpi_lset(&Q1, 0);
    mbedtls_mpi_lset(&R, 0);

    mbedtls_mpi_free( &T ); mbedtls_mpi_free( &T1 ); mbedtls_mpi_free( &T2 );
    mbedtls_mpi_free( &P1 ); mbedtls_mpi_free( &Q1 ); mbedtls_mpi_free( &R );

    if( f_rng != NULL )
    {
#if defined(MBEDTLS_RSA_NO_CRT)
        mbedtls_mpi_lset(&D_blind, 0);
        
        mbedtls_mpi_free( &D_blind );
#else
        mbedtls_mpi_lset(&DP_blind, 0);
        mbedtls_mpi_lset(&DP_blind, 0);

        mbedtls_mpi_free( &DP_blind );
        mbedtls_mpi_free( &DQ_blind );
#endif
    }

    if( ret != 0 )
        return( MBEDTLS_ERR_RSA_PRIVATE_FAILED + ret );

    return( 0 );
}

/*
 * Copy the components of an RSA key
 */
int mbedtls_rsa_copy( mbedtls_rsa_context *dst, const mbedtls_rsa_context *src )
{
    int ret;

    dst->ver = src->ver;
    dst->len = src->len;

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->N, &src->N ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->E, &src->E ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->D, &src->D ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->P, &src->P ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Q, &src->Q ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DP, &src->DP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->DQ, &src->DQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->QP, &src->QP ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RN, &src->RN ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RP, &src->RP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->RQ, &src->RQ ) );

    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vi, &src->Vi ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_copy( &dst->Vf, &src->Vf ) );

    dst->padding = src->padding;
    dst->hash_id = src->hash_id;

cleanup:
    if( ret != 0 )
        mbedtls_rsa_free( dst ); /* LCOV_EXCL_LINE */

    return( ret );
}

/*
 * Free the components of an RSA key
 */
void mbedtls_rsa_free( mbedtls_rsa_context *ctx )
{
    mbedtls_mpi_free( &ctx->Vi ); mbedtls_mpi_free( &ctx->Vf );
    mbedtls_mpi_free( &ctx->RQ ); mbedtls_mpi_free( &ctx->RP ); mbedtls_mpi_free( &ctx->RN );
    mbedtls_mpi_free( &ctx->QP ); mbedtls_mpi_free( &ctx->DQ ); mbedtls_mpi_free( &ctx->DP );
    mbedtls_mpi_free( &ctx->Q  ); mbedtls_mpi_free( &ctx->P  ); mbedtls_mpi_free( &ctx->D );
    mbedtls_mpi_free( &ctx->E  ); mbedtls_mpi_free( &ctx->N  );

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_free( &ctx->mutex );
#endif
}

#endif /* MBEDTLS_RSA_C */
