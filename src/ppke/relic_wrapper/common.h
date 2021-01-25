#ifndef COMMON_H
#define COMMON_H

#ifdef __cplusplus
// gmp.h uses __cplusplus to decide if it's right to include c++ headers.
// At last on osx  causes error: conflicting types for 'operator<<'.
// including gmpxx.h prevents this issue.
#include <gmpxx.h>
extern "C" {
#endif

#include <relic/relic.h>
#include <relic/relic_conf.h>

#ifdef __cplusplus
}
#endif

#define POINT_COMPRESS 1
#define DECIMAL 10
#define BASE 16
#define MAX_BUF 1024
#define SHA_LEN 32
#define SHA_FUNC md_map_sh256

// clang-tidy considers this file as a C++ source
// We use this trick so it still checks this header while not raising an error.

// NOLINTNEXTLINE(modernize-use-using)
typedef enum _status_t
{
    ELEMENT_OK = 2,
    ELEMENT_INVALID_ARG,
    ELEMENT_INVALID_ARG_LEN,
    ELEMENT_INVALID_TYPES,
    ELEMENT_INVALID_RESULT,
    ELEMENT_PAIRING_INIT_FAILED,
    ELEMENT_UNINITIALIZED,
    ELEMENT_DIV_ZERO,
} status_t;

enum ZR_type
{
    ZR_t     = 0,
    listZR_t = 1
};
enum G1_type
{
    G1_t     = 2,
    listG1_t = 3
};
enum G2_type
{
    G2_t     = 4,
    listG2_t = 5
};
enum GT_type
{
    GT_t     = 6,
    listGT_t = 7
};
enum Other_type
{
    Str_t     = 8,
    listStr_t = 9,
    int_t     = 10,
    listInt_t = 11,
    list_t    = 12,
    None_t    = 13
};

inline void bn_inits(bn_t b)
{
    (void)b;
    {bn_null(b)} {
        bn_new(b)
    }
}

inline void g1_inits(g1_t g)
{
    (void)g;
    {g1_null(g)} {
        g1_new(g)
    }
}
inline void g2_inits(g2_t g)
{
    (void)g;
    {g2_null(g)} {
        g2_new(g)
    }
}
inline void gt_inits(gt_t g)
{
    (void)g;
    {gt_null(g)} {
        gt_new(g)
    }
}

#define FP_STR (((((RLC_FP_BYTES * 2 + 1)))))
#define G1_LEN ((((((RLC_FP_BYTES * 2) + 2)))))
/* KSS_P508 */
#define G2_LEN G1_LEN
#define GT_LEN G1_LEN

#endif
