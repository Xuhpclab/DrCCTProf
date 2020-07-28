#ifndef _DRCCTLIB_EXT_H_
#define _DRCCTLIB_EXT_H_

#include "drcctlib_global_share.h"

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
