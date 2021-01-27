/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */
#include "dr_api.h"
#include "drwrap.h"
#include "dr_go_wrap.h"

typedef enum _drwrap_where_t {
    DRWRAP_WHERE_OUTSIDE_CALLBACK,
    DRWRAP_WHERE_PRE_FUNC,
    DRWRAP_WHERE_POST_FUNC
} drwrap_where_t;

typedef struct _drwrap_context_t {
    void *drcontext;
    app_pc func;
    dr_mcontext_t *mc;
    app_pc retaddr;
    bool mc_modified;
    bool is_redirect_requested;
    drwrap_callconv_t callconv;
    drwrap_where_t where_am_i;
} drwrap_context_t;

static inline reg_t *
dgw_stack_arg_addr(drwrap_context_t *wrapcxt, uint arg)
{
    return (reg_t *)(wrapcxt->mc->xsp +
                     (arg+1) * sizeof(reg_t));
}

static inline reg_t *
dgw_arg_addr(drwrap_context_t *wrapcxt, int arg)
{
    if (wrapcxt == NULL || wrapcxt->mc == NULL)
        return NULL;
    drwrap_get_arg(wrapcxt, 0);
    return dgw_stack_arg_addr(wrapcxt, arg);
}

void *
dgw_get_go_func_arg(void *wrapcxt_opaque, int arg)
{
    drwrap_context_t *wrapcxt = (drwrap_context_t *)wrapcxt_opaque;
    if (wrapcxt->where_am_i != DRWRAP_WHERE_PRE_FUNC)
        return NULL; /* can only get args in pre */
    reg_t *addr = dgw_arg_addr(wrapcxt, arg);
    if (addr == NULL)
        return NULL;
    else
        return (void *)*addr;
}

static inline reg_t *
dgw_stack_ret_addr(drwrap_context_t *wrapcxt, uint max_args, uint ret)
{
    return (reg_t *)(wrapcxt->mc->xsp + 
                     (max_args+ret) * sizeof(reg_t));
}


static inline reg_t *
dgw_ret_addr(drwrap_context_t *wrapcxt, int max_args, int ret)
{
    if (wrapcxt == NULL || wrapcxt->mc == NULL)
        return NULL;
    drwrap_get_retval(wrapcxt);
    return dgw_stack_ret_addr(wrapcxt, max_args, ret);
}

void *
dgw_get_go_func_retaddr(void *wrapcxt_opaque, int max_args, int ret)
{
    drwrap_context_t *wrapcxt = (drwrap_context_t *)wrapcxt_opaque;
    if (wrapcxt->where_am_i != DRWRAP_WHERE_POST_FUNC)
        return NULL; /* can only get retval in post */
    reg_t *addr = dgw_ret_addr(wrapcxt, max_args, ret);
    if (wrapcxt == NULL || wrapcxt->mc == NULL)
        return NULL;
    if (addr == NULL)
        return NULL;
    else
        return (void *)*addr;
}