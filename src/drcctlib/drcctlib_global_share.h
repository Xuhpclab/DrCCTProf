#ifndef _DRCCTLIB_GLOBAL_SHARE_H_
#define _DRCCTLIB_GLOBAL_SHARE_H_

#include "dr_api.h"

#if defined(X86_64) || defined(ARM_64) || defined(AARCH64)
#    define CCTLIB_64
#    define IF_CCTLIB_64_CCTLIB(value) value
#else
#    define CCTLIB_32
#    define IF_CCTLIB_64_CCTLIB(value)
#endif

#if defined(ARM) || defined(AARCH64)
#    define ARM_CCTLIB
#    ifdef ARM
#        define ARM32_CCTLIB
#    else
#        define ARM64_CCTLIB
#    endif
#else
#    define x86_CCTLIB
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

// debug control
// #define DRCCTLIB_DEBUG
// #define DRCCTLIB_DEBUG_LOG_CCT_INFO
#ifdef DRCCTLIB_DEBUG
#    define IF_DRCCTLIB_DEBUG(value) value
#else
#    define IF_DRCCTLIB_DEBUG(value)
#endif

/*
* global define type
* context_handle_t: ip_node_t ptr offset
* aligned_ctxt_hndl_t: aligned context_handle_t for instruction level control
* slot_t: slot of instruction in basic block
*/
#define context_handle_t int32_t
#define aligned_ctxt_hndl_t int64_t

#define THREAD_MAX_NUM 8192

#define ATOMIC_ADD_CTXT_HNDL(origin, val) dr_atomic_add32_return_sum(&origin, val)
#define ATOMIC_ADD_THREAD_ID_MAX(origin) dr_atomic_add32_return_sum(&origin, 1)



#define FOR_SPEC_TEST
#ifdef FOR_SPEC_TEST
#    define CONTEXT_HANDLE_MAX 2147483647L // max context handle num (1^31 - 1) cost 8GB()/16GB
#    define MEM_CACHE_PAGE1_BIT 11         // 8KB max cost 56GB
#    define MEM_CACHE_PAGE2_BIT 20         // 28MB
// cache global 100KB per thread
#    define BB_CACHE_MESSAGE_MAX_NUM 256 // 2^8 * 16B = 4KB
#    define MEM_REF_CACHE_MAX 4096       // 2^12 * 24B = 96KB
#else
#    define CONTEXT_HANDLE_MAX 16777216L // 1^24 64MB
#    define MEM_CACHE_PAGE1_BIT 4        // 128B max cost 447MB
#    define MEM_CACHE_PAGE2_BIT 20       // 28MB
// cache global 100KB per thread
#    define BB_CACHE_MESSAGE_MAX_NUM 256 // 2^8 * 16B = 4KB
#    define MEM_REF_CACHE_MAX 4096       // 2^12 * 24B = 96KB
#endif

#define TLS_MEM_CACHE_MIN_NUM 8192 // 2^13
#define MEM_CACHE_DEBRIS_SIZE 1024 // 2^0

// THREAD_SHARED_MEMORY(TSM) (bb_shadow_t)
#define TSM_CACHE_PAGE1_BIT 4  // max support 1,048,576
#define TSM_CACHE_PAGE2_BIT 16 // 65536

#define DISASM_CACHE_SIZE 80
#define MAXIMUM_SYMNAME 256

#define DRCCTLIB_THREAD_EVENT_PRI 5


// #define IPNODE_STORE_BNODE_IDX

#endif //_DRCCTLIB_GLOBAL_SHARE_H_