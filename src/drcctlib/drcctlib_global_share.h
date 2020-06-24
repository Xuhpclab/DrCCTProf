#ifndef _DRCCTLIB_GLOBAL_SHARE_H_
#define _DRCCTLIB_GLOBAL_SHARE_H_

#include "dr_api.h"

#ifdef X64
#    define CCTLIB_64
#else
#    define CCTLIB_32
#endif

#if defined(ARM) || defined(AARCH64)
#    define ARM_CCTLIB
#    ifdef ARM
#        define ARM32_CCTLIB
#    else
#        define ARM64_CCTLIB
#    endif
#else
#    define INTEL_CCTLIB
#endif

#ifdef ARM_CCTLIB
#    define IF_ARM_CCTLIB(value) value
#    define IF_ARM_CCTLIB_ELSE(value1, value2) value1
#else
#    define IF_ARM_CCTLIB(value)
#    define IF_ARM_CCTLIB_ELSE(value1, value2) value2
#endif

#ifdef ARM32_CCTLIB
#    define IF_ARM32_CCTLIB(value) value
#else
#    define IF_ARM32_CCTLIB(value)
#endif

#ifdef ARM64_CCTLIB
#    define IF_ARM64_CCTLIB(value) value
#    define IF_NOT_ARM64_CCTLIB(value)
#else
#    define IF_ARM64_CCTLIB(value)
#    define IF_NOT_ARM64_CCTLIB(value) value
#endif

// #define DRCCTLIB_DEBUG
#ifdef DRCCTLIB_DEBUG
#    define IF_DRCCTLIB_DEBUG(value) value
#else
#    define IF_DRCCTLIB_DEBUG(value)
#endif

#define context_handle_t int32_t
#define aligned_ctxt_hndl_t int64_t

#define THREAD_MAX_NUM 10000
#define FOR_SPEC_TEST
#ifdef FOR_SPEC_TEST
#    define CONTEXT_HANDLE_MAX 2147483647L // 1^31 - 1 8GB
#    define MEM_CACHE_PAGE1_BIT 11         // 8KB max cost 56GB
#    define MEM_CACHE_PAGE2_BIT 20         // 28MB
#else
#    define CONTEXT_HANDLE_MAX 16777216L // 1^24 64MB
#    define MEM_CACHE_PAGE1_BIT 4        // 128B max cost 447MB
#    define MEM_CACHE_PAGE2_BIT 20       // 28MB
#endif
#define TLS_MEM_CACHE_MIN_NUM 8192 // 2^13
#define MEM_CACHE_DEBRIS_SIZE 1024 // 2^0

// THREAD_SHARED_MEMORY(TSM) (bb_shadow_t)
#define TSM_CACHE_PAGE1_BIT 4  // max support 1,048,576
#define TSM_CACHE_PAGE2_BIT 16 // 65536

#define DISASM_CACHE_SIZE 80
#define MAXIMUM_SYMNAME 256

#define DRCCTLIB_THREAD_EVENT_PRI 5

#endif //_DRCCTLIB_GLOBAL_SHARE_H_