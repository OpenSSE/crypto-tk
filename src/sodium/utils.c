#ifndef __STDC_WANT_LIB_EXT1__
# define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif

#ifdef _WIN32
# include <windows.h>
# include <wincrypt.h>
#else
# include <unistd.h>
#endif

#include "core.h"
//#include "randombytes.h"
#include "utils.h"

#ifndef ENOSYS
# define ENOSYS ENXIO
#endif

#if defined(_WIN32) && \
    (!defined(WINAPI_FAMILY) || WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP)
# define WINAPI_DESKTOP
#endif

#define CANARY_SIZE 16U
#define GARBAGE_VALUE 0xdb

#ifndef MAP_NOCORE
# define MAP_NOCORE 0
#endif
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
# define MAP_ANON MAP_ANONYMOUS
#endif
#if defined(WINAPI_DESKTOP) || (defined(MAP_ANON) && defined(HAVE_MMAP)) || \
    defined(HAVE_POSIX_MEMALIGN)
# define HAVE_ALIGNED_MALLOC
#endif
#if defined(HAVE_MPROTECT) && \
    !(defined(PROT_NONE) && defined(PROT_READ) && defined(PROT_WRITE))
# undef HAVE_MPROTECT
#endif
#if defined(HAVE_ALIGNED_MALLOC) && \
    (defined(WINAPI_DESKTOP) || defined(HAVE_MPROTECT))
# define HAVE_PAGE_PROTECTION
#endif
#if !defined(MADV_DODUMP) && defined(MADV_CORE)
# define MADV_DODUMP   MADV_CORE
# define MADV_DONTDUMP MADV_NOCORE
#endif

static size_t        page_size;
static unsigned char canary[CANARY_SIZE];

/* LCOV_EXCL_START */
#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_memzero_lto(void *const  pnt,
                                            const size_t len)
{
    (void) pnt; /* LCOV_EXCL_LINE */
    (void) len; /* LCOV_EXCL_LINE */
}
#endif
/* LCOV_EXCL_STOP */

void
sodium_memzero(void *const pnt, const size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(pnt, len);
#elif defined(HAVE_MEMSET_S)
    if (len > 0U && memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(pnt, len);
#elif HAVE_WEAK_SYMBOLS
    memset(pnt, 0, len);
    _sodium_dummy_symbol_to_prevent_memzero_lto(pnt, len);
#else
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
#endif
}

int
_sodium_alloc_init(void)
{
#ifdef HAVE_ALIGNED_MALLOC
# if defined(_SC_PAGESIZE)
    long page_size_ = sysconf(_SC_PAGESIZE);
    if (page_size_ > 0L) {
        page_size = (size_t) page_size_;
    }
# elif defined(WINAPI_DESKTOP)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    page_size = (size_t) si.dwPageSize;
# endif
    if (page_size < CANARY_SIZE || page_size < sizeof(size_t)) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
#endif
#warning Use randomness to fill the canary
//    randombytes_buf(canary, sizeof canary);
    memset(canary, (int) GARBAGE_VALUE, sizeof canary);

    
    return 0;
}

int
sodium_mlock(void *const addr, const size_t len)
{
#if defined(MADV_DONTDUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DONTDUMP);
#endif
#ifdef HAVE_MLOCK
    return mlock(addr, len);
#elif defined(WINAPI_DESKTOP)
    return -(VirtualLock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int
sodium_munlock(void *const addr, const size_t len)
{
    sodium_memzero(addr, len);
#if defined(MADV_DODUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DODUMP);
#endif
#ifdef HAVE_MLOCK
    return munlock(addr, len);
#elif defined(WINAPI_DESKTOP)
    return -(VirtualUnlock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_noaccess(void *ptr, size_t size)
{
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_NONE);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_NOACCESS, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_readonly(void *ptr, size_t size)
{
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READONLY, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_readwrite(void *ptr, size_t size)
{
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ | PROT_WRITE);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READWRITE, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

#ifdef HAVE_ALIGNED_MALLOC

__attribute__((noreturn)) static void
_out_of_bounds(void)
{
# ifdef SIGSEGV
    raise(SIGSEGV);
# elif defined(SIGKILL)
    raise(SIGKILL);
# endif
    abort(); /* not something we want any higher-level API to catch */
} /* LCOV_EXCL_LINE */

static inline size_t
_page_round(const size_t size)
{
    const size_t page_mask = page_size - 1U;

    return (size + page_mask) & ~page_mask;
}

static __attribute__((malloc)) unsigned char *
_alloc_aligned(const size_t size)
{
    void *ptr;

# if defined(MAP_ANON) && defined(HAVE_MMAP)
    if ((ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_ANON | MAP_PRIVATE | MAP_NOCORE, -1, 0)) ==
        MAP_FAILED) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    }               /* LCOV_EXCL_LINE */
# elif defined(HAVE_POSIX_MEMALIGN)
    if (posix_memalign(&ptr, page_size, size) != 0) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    }               /* LCOV_EXCL_LINE */
# elif defined(WINAPI_DESKTOP)
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
# else
#  error Bug
# endif
    return (unsigned char *) ptr;
}

static void
_free_aligned(unsigned char *const ptr, const size_t size)
{
# if defined(MAP_ANON) && defined(HAVE_MMAP)
    (void) munmap(ptr, size);
# elif defined(HAVE_POSIX_MEMALIGN)
    free(ptr);
# elif defined(WINAPI_DESKTOP)
    VirtualFree(ptr, 0U, MEM_RELEASE);
# else
#  error Bug
#endif
}

static unsigned char *
_unprotected_ptr_from_user_ptr(void *const ptr)
{
    uintptr_t      unprotected_ptr_u;
    unsigned char *canary_ptr;
    size_t         page_mask;

    canary_ptr = ((unsigned char *) ptr) - sizeof canary;
    page_mask = page_size - 1U;
    unprotected_ptr_u = ((uintptr_t) canary_ptr & (uintptr_t) ~page_mask);
    if (unprotected_ptr_u <= page_size * 2U) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    return (unsigned char *) unprotected_ptr_u;
}

#endif /* HAVE_ALIGNED_MALLOC */

#ifndef HAVE_ALIGNED_MALLOC
static __attribute__((malloc)) void *
_sodium_malloc(const size_t size)
{
    return malloc(size > (size_t) 0U ? size : (size_t) 1U);
}
#else
static __attribute__((malloc)) void *
_sodium_malloc(const size_t size)
{
    void          *user_ptr;
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         size_with_canary;
    size_t         total_size;
    size_t         unprotected_size;

    if (size >= (size_t) SIZE_MAX - page_size * 4U) {
        errno = ENOMEM;
        return NULL;
    }
    if (page_size <= sizeof canary || page_size < sizeof unprotected_size) {
        sodium_misuse(); /* LCOV_EXCL_LINE */
    }
    size_with_canary = (sizeof canary) + size;
    unprotected_size = _page_round(size_with_canary);
    total_size       = page_size + page_size + unprotected_size + page_size;
    if ((base_ptr = _alloc_aligned(total_size)) == NULL) {
        return NULL; /* LCOV_EXCL_LINE */
    }
    unprotected_ptr = base_ptr + page_size * 2U;
    _mprotect_noaccess(base_ptr + page_size, page_size);
# ifndef HAVE_PAGE_PROTECTION
    memcpy(unprotected_ptr + unprotected_size, canary, sizeof canary);
# endif
    _mprotect_noaccess(unprotected_ptr + unprotected_size, page_size);
    sodium_mlock(unprotected_ptr, unprotected_size);
    canary_ptr =
        unprotected_ptr + _page_round(size_with_canary) - size_with_canary;
    user_ptr = canary_ptr + sizeof canary;
    memcpy(canary_ptr, canary, sizeof canary);
    memcpy(base_ptr, &unprotected_size, sizeof unprotected_size);
    _mprotect_readonly(base_ptr, page_size);
    assert(_unprotected_ptr_from_user_ptr(user_ptr) == unprotected_ptr);

    return user_ptr;
}
#endif /* !HAVE_ALIGNED_MALLOC */

__attribute__((malloc)) void *
sodium_malloc(const size_t size)
{
    void *ptr;

    if ((ptr = _sodium_malloc(size)) == NULL) {
        return NULL;
    }
    memset(ptr, (int) GARBAGE_VALUE, size);

    return ptr;
}

__attribute__((malloc)) void *
sodium_allocarray(size_t count, size_t size)
{
    size_t total_size;

    if (count > (size_t) 0U && size >= (size_t) SIZE_MAX / count) {
        errno = ENOMEM;
        return NULL;
    }
    total_size = count * size;

    return sodium_malloc(total_size);
}

#ifndef HAVE_ALIGNED_MALLOC
void
sodium_free(void *ptr)
{
    free(ptr);
}
#else
void
sodium_free(void *ptr)
{
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         total_size;
    size_t         unprotected_size;

    if (ptr == NULL) {
        return;
    }
    canary_ptr      = ((unsigned char *) ptr) - sizeof canary;
    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr        = unprotected_ptr - page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);
    total_size = page_size + page_size + unprotected_size + page_size;
    _mprotect_readwrite(base_ptr, total_size);
    if (sodium_memcmp(canary_ptr, canary, sizeof canary) != 0) {
        _out_of_bounds();
    }
# ifndef HAVE_PAGE_PROTECTION
    if (sodium_memcmp(unprotected_ptr + unprotected_size, canary,
                      sizeof canary) != 0) {
        _out_of_bounds();
    }
# endif
    sodium_munlock(unprotected_ptr, unprotected_size);
    _free_aligned(base_ptr, total_size);
}
#endif /* HAVE_ALIGNED_MALLOC */

#ifndef HAVE_PAGE_PROTECTION
static int
_sodium_mprotect(void *ptr, int (*cb)(void *ptr, size_t size))
{
    (void) ptr;
    (void) cb;
    errno = ENOSYS;
    return -1;
}
#else
static int
_sodium_mprotect(void *ptr, int (*cb)(void *ptr, size_t size))
{
    unsigned char *base_ptr;
    unsigned char *unprotected_ptr;
    size_t         unprotected_size;

    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr        = unprotected_ptr - page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);

    return cb(unprotected_ptr, unprotected_size);
}
#endif

int
sodium_mprotect_noaccess(void *ptr)
{
    return _sodium_mprotect(ptr, _mprotect_noaccess);
}

int
sodium_mprotect_readonly(void *ptr)
{
    return _sodium_mprotect(ptr, _mprotect_readonly);
}

int
sodium_mprotect_readwrite(void *ptr)
{
    return _sodium_mprotect(ptr, _mprotect_readwrite);
}
