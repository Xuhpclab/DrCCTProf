/* 
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_UTILS_H_
#define _DRCCTLIB_UTILS_H_

#include <string.h>
#include <unistd.h>

#include "dr_api.h"
#include "drcctlib_defines.h"


#define DRCCTLIB_PRINTF_TEMPLATE(client, format, args...)                        \
    do {                                                                         \
        char name[MAXIMUM_PATH] = "";                                            \
        gethostname(name, MAXIMUM_PATH);                                         \
        pid_t pid = getpid();                                                    \
        dr_printf("[drcctlib[" client "](%s%d) msg]====" format "\n", name, pid, \
                  ##args);                                                       \
    } while (0)

#define DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE(client, format, args...) \
    do {                                                               \
        DRCCTLIB_PRINTF_TEMPLATE(client, format, ##args);              \
        dr_exit_process(-1);                                           \
    } while (0)

#ifdef ARM_CCTLIB
#    define ARCH_NAME_PREFIX "arm"
#elif defined(x86_CCTLIB)
#    define ARCH_NAME_PREFIX "x86"
#else
#    define ARCH_NAME_PREFIX "unknown"
#endif

#define DRCCTLIB_INIT_LOG_FILE_NAME(buffer, client_name, suffix)                       \
    do {                                                                             \
        sprintf(buffer + strlen(buffer), ARCH_NAME_PREFIX ".");                      \
        gethostname(buffer + strlen(buffer), MAXIMUM_PATH - strlen(buffer));    \
        sprintf(buffer + strlen(buffer), "-%d.%s.%s", getpid(), client_name, suffix); \
    } while (0)

#define DRCCTLIB_INIT_THREAD_LOG_FILE_NAME(buffer, client_name, thread_id, suffix)  \
    do {                                                                          \
        sprintf(buffer + strlen(buffer), ARCH_NAME_PREFIX ".");                   \
        gethostname(buffer + strlen(buffer), MAXIMUM_PATH - strlen(buffer)); \
        sprintf(buffer + strlen(buffer), "-%d.%s-%d.%s", getpid(), client_name, \
                thread_id, suffix);                                                 \
    } while (0)

#endif //_DRCCTLIB_UTILS_H_