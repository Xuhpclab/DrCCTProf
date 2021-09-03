/*
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_H_
#define _DRCCTLIB_H_

#include <cstdint>
#include <vector>

#include "dr_api.h"
#include "drcctlib_defines.h"
#include "drcctlib_utils.h"
#include "drcctlib_filter_func_list.h"

enum {
    DRCCTLIB_DEFAULT = 0x00,
    DRCCTLIB_CACHE_MODE = 0x01,
    DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE = 0x02,
    DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR = 0x04,
    DRCCTLIB_CACHE_EXCEPTION = 0x08
};

enum {
    INSTR_STATE_CLIENT_INTEREST = 0x01,
    INSTR_STATE_CALL_DIRECT = 0x02,
    INSTR_STATE_CALL_IN_DIRECT = 0x04,
    INSTR_STATE_RETURN = 0x08,
    INSTR_STATE_MEM_ACCESS = 0X10,
    INSTR_STATE_THREAD_ROOT_VIRTUAL = 0x20,
    INSTR_STATE_BB_START_NOP = 0X40
};

typedef struct _instr_instrument_msg_t {
    instrlist_t *bb;
    instr_t *instr;
    bool interest_start;
    int32_t slot;
    int32_t state;
    struct _instr_instrument_msg_t *next;
} instr_instrument_msg_t;

typedef struct _mem_ref_msg_t {
    int64_t index;
    int64_t slot;
    app_pc addr;
} mem_ref_msg_t;

DR_EXPORT
/**
 * Initialize DrCCTLib with
 * an instruction filter,
 * an instrumentation function for instructions,
 * an instrumentation function the beginning of basic blocks,
 * an instrumentation function for the end of basic blocks,
 * and a mode bitvector flag.
 *
 * Options for the instruction filter can be found in
 * @see drcctlib_filter_func_list.h ,
 *
 * Options for the mode flag include
 * @see DRCCTLIB_DEFAULT
 * @see DRCCTLIB_CACHE_MODE
 * @see DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE
 * @see DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR
 * @see DRCCTLIB_CACHE_EXCEPTION
 *
 * And examples of their usage can be found in the clients directory.
 *
 * @param filter the instruction filter
 * @param func1 the instrumentation function
 * allowing the user to inject code before each instruction.
 * May be null.
 * @param func2 the instrumentation function allowing the user to
 * inject code before each basic block.
 * May be null.
 * @param func3 the instrumentation function allowing the user
 * to inject code after each basic block.
 * May be null.
 * @flag the flag telling DRCCTLib how to operate.
 */
bool
drcctlib_init_ex(bool (*filter)(instr_t *), file_t file,
                 void (*func1)(void *, instr_instrument_msg_t *),
                 void (*func2)(void *, int32_t, int32_t),
                 void (*func3)(void *, context_handle_t, int32_t, int32_t,
                               mem_ref_msg_t *, void **),
                 char flag);

DR_EXPORT
void
drcctlib_init(bool (*filter)(instr_t *), file_t file,
              void (*func1)(void *, instr_instrument_msg_t *), bool do_data_centric);

DR_EXPORT
void
drcctlib_exit(void);

DR_EXPORT
int
drcctlib_get_thread_id();

DR_EXPORT
void
drcctlib_get_context_handle_in_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                   int32_t slot, reg_id_t store_reg, reg_id_t addr_reg);

DR_EXPORT
context_handle_t
drcctlib_get_context_handle(void *drcontext, int32_t slot);

DR_EXPORT
context_handle_t
drcctlib_get_context_handle(void *drcontext);

DR_EXPORT
context_handle_t
drcctlib_get_global_context_handle_num();

// API for ctxt_hndl
DR_EXPORT
bool
drcctlib_ctxt_hndl_is_valid(context_handle_t ctxt_hndl);

DR_EXPORT
inner_context_t *
drcctlib_get_cct(context_handle_t ctxt_hndl, int max_depth);

DR_EXPORT
void
drcctlib_free_cct(inner_context_t *contxt_list);

/**
 * Given the context handle,
 * return the full calling context.
 * @param ctxt_hdnl the context handle
 */
DR_EXPORT
inner_context_t *
drcctlib_get_full_cct(context_handle_t ctxt_hndl);

DR_EXPORT
inner_context_t *
drcctlib_get_full_cct(context_handle_t ctxt_hndl, int max_depth);

DR_EXPORT
void
drcctlib_free_full_cct(inner_context_t *contxt_list);

DR_EXPORT
void
drcctlib_print_backtrace_first_item(file_t file, context_handle_t ctxt_hndl, bool print_asm,
                              bool print_source_line);

DR_EXPORT
void
drcctlib_print_backtrace(file_t file, context_handle_t ctxt_hndl, bool print_asm,
                        bool print_source_line, int max_depth);

DR_EXPORT
/**
 * Legacy, deprecated backtrace first item print routine.
 * \deprecated drcctlib_print_backtrace_item() should be used instead.
 */
void
drcctlib_print_ctxt_hndl_msg(file_t file, context_handle_t ctxt_hndl, bool print_asm,
                             bool print_source_line);

DR_EXPORT
/**
 * Legacy, deprecated backtrace list print routine.
 * \deprecated drcctlib_print_backtrace() should be used instead.
 */
void
drcctlib_print_full_cct(file_t file, context_handle_t ctxt_hndl, bool print_asm,
                        bool print_source_line, int max_depth);

DR_EXPORT
app_pc
drcctlib_get_ctxt_hndl_pc(context_handle_t ctxt_hndl);

DR_EXPORT
int32_t
drcctlib_get_ctxt_hndl_state(context_handle_t ctxt_hndl);

DR_EXPORT
context_handle_t
drcctlib_get_caller_handle(context_handle_t ctxt_hndl);

DR_EXPORT
bool
drcctlib_have_same_caller_prefix(context_handle_t ctxt_hndl1,
                                 context_handle_t ctxt_hndl2);

DR_EXPORT
bool
drcctlib_have_same_call_path(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2);
DR_EXPORT
bool
drcctlib_have_same_source_line(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2);

enum { UNKNOWN_OBJECT, STACK_OBJECT, DYNAMIC_OBJECT, STATIC_OBJECT };
// The handle representing a data object
typedef struct _data_handle_t {
    uint8_t object_type;
    union {
        context_handle_t path_handle;
        int32_t sym_name;
    };
} data_handle_t;

/* API for data centric */

DR_EXPORT
data_handle_t
drcctlib_get_data_hndl_ignore_stack_data(void *drcontext, void *address);

DR_EXPORT
data_handle_t
drcctlib_get_data_hndl_runtime(void *drcontext, void *address);

DR_EXPORT
data_handle_t
drcctlib_get_data_hndl(void *drcontext, void *address);

DR_EXPORT
char *
drcctlib_get_str_from_strpool(int index);

DR_EXPORT
context_handle_t
drcctlib_get_hndl_from_strpool(int index);

typedef struct _datacentric_node_t {
    data_handle_t hndl;
    uint64_t count;
} datacentric_node_t;

DR_EXPORT
std::vector<datacentric_node_t> *
drcctlib_get_static_datacentric_nodes();

DR_EXPORT
std::vector<datacentric_node_t> *
drcctlib_get_dynamic_datacentric_nodes();

DR_EXPORT
inner_context_t *
drcctlib_get_full_cct_of_datacentric_nodes(datacentric_node_t datacentric_node);

DR_EXPORT
inner_context_t *
drcctlib_get_full_cct_of_static_datacentric_nodes(int index);

#endif // _DRCCTLIB_H_
