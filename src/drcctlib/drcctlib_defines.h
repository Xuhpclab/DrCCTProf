/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_GLOBAL_SHARE_H_
#define _DRCCTLIB_GLOBAL_SHARE_H_

#include <string.h>
#include <unistd.h>

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
#ifdef DRCCTLIB_DEBUG
#    define IF_DRCCTLIB_DEBUG(value) value
#else
#    define IF_DRCCTLIB_DEBUG(value)
#endif

// #define DRCCTLIB_DEBUG_LOG_CCT_INFO
// #define IPNODE_STORE_BNODE_IDX
// #define IN_PROCESS_SPEEDUP

#define context_handle_t int32_t
#define aligned_ctxt_hndl_t int64_t

#define DISASM_CACHE_SIZE 80
#define MAXIMUM_SYMNAME 256
#define MAXIMUM_FILEPATH 1024

#define THREAD_MAX_NUM 8192
#define SPEEDUP_SUPPORT_THREAD_MAX_NUM 32
// #define FOR_SPEC_TEST
#ifdef FOR_SPEC_TEST
#    define CONTEXT_HANDLE_MAX 2147483647L // max context handle num (1^31 - 1) cost 8GB()/16GB
#else
#    define CONTEXT_HANDLE_MAX 16777216L // 1^24 64MB
#endif

#define DRCCTLIB_THREAD_EVENT_PRI 5
#define DRCCTLIB_MODULE_REGISTER_PRI 5

// #define DRCCTLIB_SUPPORT_ATTACH_DETACH

/**
 * DrCCTLib Calling Context.
 * Clients may access this calling context
 * via drcctlib_get_full_cct.
 */
typedef struct _inner_context_t {
    /**
     * The name of the function/symbol
     * associated with this calling context
     */
    char func_name[MAXIMUM_SYMNAME];

    /**
     * The file path of the source code of the guest program
     * at the current point in the program.
     * Will not be available when the guest program is
     * compiled without debug information.
     */
    char file_path[MAXIMUM_FILEPATH];

    char module_path[MAXIMUM_FILEPATH];

    /**
     * String representation of the dissassembly of the code.
     */
    char code_asm[DISASM_CACHE_SIZE];

    /**
     * The context handle that refers to this context.
     */
    context_handle_t ctxt_hndl;

    /**
     * The line of the source code of the guest program
     * at the current point in the program.
     * Will not be available when the guest program is compiled
     * without debug information.
     */
    int line_no;

    /**
     * The instruction pointer at the current point in the program.
     * May be null.
     */
    app_pc ip;

    /**
     * The context that occurs before this context.
     */
    struct _inner_context_t *pre_ctxt;
} inner_context_t;

#endif //_DRCCTLIB_GLOBAL_SHARE_H_