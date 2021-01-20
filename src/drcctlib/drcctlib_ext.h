/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_EXT_H_
#define _DRCCTLIB_EXT_H_

#include "drcctlib_defines.h"
#include "drcctlib_utils.h"

// stack config
typedef struct _thread_stack_config_t {
    int thread_id;
    void *stack_base;
    void *stack_end;
} thread_stack_config_t;

DR_EXPORT
thread_stack_config_t
drcctlib_get_thread_stack_config(void *drcontext);

#endif // _DRCCTLIB_EXT_H_
