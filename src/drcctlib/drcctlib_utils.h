/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_UTILS_H_
#define _DRCCTLIB_UTILS_H_

#include <string.h>
#include <unistd.h>
#include <cinttypes>

#include "dr_api.h"
#include "drcctlib_defines.h"

#define DRCCTLIB_PRINTF_TEMPLATE(_CLIENT, _FORMAT, _ARGS...)                        \
    do {                                                                            \
        char _HOST_NAME[MAXIMUM_FILEPATH] = "";                                         \
        gethostname(_HOST_NAME, MAXIMUM_FILEPATH);                                      \
        dr_printf("[drcctlib[" _CLIENT "](%s%d) msg]====" _FORMAT "\n", _HOST_NAME, \
                  getpid(), ##_ARGS);                                               \
    } while (0)

#define DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE(_CLIENT, _FORMAT, _ARGS...) \
    do {                                                                  \
        DRCCTLIB_PRINTF_TEMPLATE(_CLIENT, _FORMAT, ##_ARGS);              \
        dr_exit_process(-1);                                              \
    } while (0)

#ifdef ARM_CCTLIB
#    define ARCH_NAME_PREFIX "arm"
#elif defined(x86_CCTLIB)
#    define ARCH_NAME_PREFIX "x86"
#else
#    define ARCH_NAME_PREFIX "unknown"
#endif

#define DRCCTLIB_INIT_LOG_FILE_NAME(_BUFFER, _CLIENT, _SUFFIX)                       \
    do {                                                                             \
        sprintf(_BUFFER + strlen(_BUFFER), ARCH_NAME_PREFIX ".");                    \
        gethostname(_BUFFER + strlen(_BUFFER), MAXIMUM_FILEPATH - strlen(_BUFFER));      \
        sprintf(_BUFFER + strlen(_BUFFER), "-%d.%s.%s", getpid(), _CLIENT, _SUFFIX); \
    } while (0)

#define DRCCTLIB_INIT_THREAD_LOG_FILE_NAME(_BUFFER, _CLIENT, _THREAD_ID, _SUFFIX) \
    do {                                                                          \
        sprintf(_BUFFER + strlen(_BUFFER), ARCH_NAME_PREFIX ".");                 \
        gethostname(_BUFFER + strlen(_BUFFER), MAXIMUM_FILEPATH - strlen(_BUFFER));   \
        sprintf(_BUFFER + strlen(_BUFFER), "-%d.%s-%d.%s", getpid(), _CLIENT,     \
                _THREAD_ID, _SUFFIX);                                             \
    } while (0)

DR_EXPORT
uint64_t
hexadecimal_char_to_uint64(char* hex, int size);

#endif //_DRCCTLIB_UTILS_H_