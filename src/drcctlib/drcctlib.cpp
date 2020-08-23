/* 
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <sys/time.h>
#include <sys/resource.h>
#include <cinttypes>
#include <vector>

#include "libelf.h"

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"
#include "hashtable.h"

#include "drcctlib.h"
#include "drcctlib_ext.h"
#include "drcctlib_priv_share.h"
#include "splay_tree.h"
#include "shadow_memory.h"
#include "memory_cache.h"

#define DRCCTLIB_PRINTF(format, args...) DRCCTLIB_PRINTF_TEMPLATE("fwk", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("fwk", format, ##args)

#ifdef ARM32_CCTLIB
#    define DR_DISASM_DRCCTLIB DR_DISASM_ARM
#elif defined(ARM64_CCTLIB)
#    define DR_DISASM_DRCCTLIB DR_DISASM_DR
#else
#    define DR_DISASM_DRCCTLIB DR_DISASM_INTEL
#endif

#ifdef ARM_CCTLIB
#    define DR_STACK_REG DR_REG_SP
#else
#    define DR_STACK_REG DR_REG_RSP
#endif

#ifdef x86_CCTLIB
#    define OPND_CREATE_SLOT OPND_CREATE_INT32
#    define OPND_CREATE_STATE OPND_CREATE_INT32
#    define OPND_CREATE_SHADOWPRT OPND_CREATE_INTPTR
#elif defined(ARM_CCTLIB)
#    define OPND_CREATE_SLOT OPND_CREATE_INT
#    define OPND_CREATE_STATE OPND_CREATE_INT
#    define OPND_CREATE_SHADOWPRT OPND_CREATE_INT
#endif
#define OPND_CREATE_PT_CUR_SLOT OPND_CREATE_MEM32
#define OPND_CREATE_PT_CUR_STATE OPND_CREATE_MEM32

#ifdef CCTLIB_64
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM64
#else
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM32
#endif

#ifdef ARM_CCTLIB
#    define OPND_CREATE_IMMEDIATE_INT OPND_CREATE_INT
#else
#    ifdef CCTLIB_64
#        define OPND_CREATE_IMMEDIATE_INT OPND_CREATE_INT64
#    else
#        define OPND_CREATE_IMMEDIATE_INT OPND_CREATE_INT32
#    endif
#endif

// mem_cache and tls_mem_cache config (bb_node_cache && splay_node_cache)
#ifdef FOR_SPEC_TEST
#    define MEM_CACHE_PAGE1_BIT 11 // 8KB max cost 56GB
#    define MEM_CACHE_PAGE2_BIT 20 // 28MB
#else
#    define MEM_CACHE_PAGE1_BIT 4  // 128B max cost 447MB
#    define MEM_CACHE_PAGE2_BIT 20 // 28MB
#endif
#define TLS_MEM_CACHE_MIN_NUM 8192 // 2^13
#define MEM_CACHE_DEBRIS_SIZE 1024 // 2^10

// THREAD_SHARED_MEMORY(TSM) (bb_shadow_t)
#define TSM_CACHE_PAGE1_BIT 4  // max support 1,048,576
#define TSM_CACHE_PAGE2_BIT 16 // 65536

// cache global 100KB per thread (pt->bb_cache && pt->inner_mem_ref_cache)
#define BB_CACHE_MESSAGE_MAX_NUM 256 // 2^8 * 16B = 4KB
#define INNER_MEM_REF_CACHE_MAX 4096 // 2^12 * 24B = 96KB

#define INVALID_CTXT_HNDL 0
#define THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE 1
#define VALID_START_CTXT_HNDL 2

#define THREAD_ROOT_BB_SHARED_BB_KEY 0

#define MAX_CCT_PRINT_DEPTH 15
#define STRING_POOL_NODES_MAX 7483647L
// #define STRING_POOL_NODES_MAX 2147483647L // 1^31 - 1

#define ATOMIC_ADD_CTXT_HNDL(origin, val) dr_atomic_add32_return_sum(&origin, val)
#define ATOMIC_ADD_THREAD_ID_MAX(origin) dr_atomic_add32_return_sum(&origin, 1)

typedef struct _bb_shadow_t {
    bb_key_t key;
    slot_t slot_num;
    state_t end_ins_state;
    int32_t mem_ref_num;
    app_pc *ip_shadow;
    state_t *state_shadow;
    char *disasm_shadow;
#ifdef IN_PROCESS_SPEEDUP
    cct_bb_node_t **last_same_key_bb_pt_list;
#endif
} bb_shadow_t;

typedef struct _client_cb_t {
    void (*func_instr_analysis)(void *, instr_instrument_msg_t *);
    void (*func_insert_bb_start)(void *, int32_t, int32_t);
    void (*func_insert_bb_end)(void *, context_handle_t, int32_t, int32_t,
                               mem_ref_msg_t *, void **);
} client_cb_t;

typedef struct _bb_instrument_msg_t {
    slot_t slot_max;
    bb_key_t bb_key;
    state_t bb_end_state;
    int32_t mem_ref_num;
    bb_shadow_t *bb_shadow;
} bb_instrument_msg_t;

#ifdef CCTLIB_64
#    define thread_aligned_num_t int64_t
typedef struct _bb_cache_message_t {
    thread_aligned_num_t index;
    bb_shadow_t *bb_shadow;
} bb_cache_message_t;
#endif

#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
typedef struct _per_thread_cct_info_t {
    uint64_t call_num;
    uint64_t return_num;
    uint64_t tree_high;
    uint64_t cur_tree_high;
    uint64_t ins_num;
    uint64_t bb_node_num;
    uint64_t real_node_num;
    uint64_t mem_ref_num;
    uint64_t splay_tree_search_num;
    uint64_t cct_create_clean_call_num;
} per_thread_cct_info_t;

typedef struct _cct_info_t {
    uint64_t ins_num;
    uint64_t bb_node_num;
    uint64_t real_node_num;
    uint64_t mem_ref_num;
    uint64_t splay_tree_search_num;
    uint64_t cct_create_clean_call_num;
} cct_info_t;
#endif

// TLS(thread local storage)
typedef struct _per_thread_t {
    int id;
    // for root
    cct_bb_node_t *root_bb_node;
    // for current handle
    cct_bb_node_t *cur_bb_node;

    void *cur_buf1;
    tls_memory_cache_t<cct_bb_node_t> *bb_node_cache;
    tls_memory_cache_t<splay_node_t> *splay_node_cache;
    splay_node_t *next_splay_node;
    splay_node_t *dummy_splay_node;

    aligned_ctxt_hndl_t cur_bb_child_ctxt_start_idx;
    state_t pre_instr_state;
    slot_t cur_slot;
    state_t cur_state;

    // Signal
    cct_bb_node_t *signal_raise_bb_node;
    slot_t signal_raise_slot;
    state_t signal_raise_state;

    // DO_DATA_CENTRIC
    void *stack_base;
    void *stack_size;
    bool init_stack_cache;
    bool stack_unlimited;

    size_t dmem_alloc_size;
    context_handle_t dmem_alloc_ctxt_hndl;

#ifdef CCTLIB_64
    // For cache control
    void *cur_buf2;
    bb_cache_message_t *bb_cache;
    // For mem access cache control
    void *cur_buf3;
    mem_ref_msg_t *inner_mem_ref_cache;
    // For cache run
    bb_shadow_t *pre_bb_shadow;
    void *bb_call_back_cache_data;
#endif
#ifdef IN_PROCESS_SPEEDUP
    int speedup_cache_index;
#endif
    IF_DRCCTLIB_DEBUG(file_t log_file_bb;)
    IF_DRCCTLIB_DEBUG(file_t log_file_instr;)
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    per_thread_cct_info_t cct_info;
#endif
} per_thread_t;

#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
void *global_cct_info_lock;
static cct_info_t global_cct_info;
#endif

static per_thread_t **global_pt_cache_buff;
static int global_thread_id_max = 0;

static int init_count = 0;

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static reg_id_t tls_seg1;
static uint tls_offs1;
static reg_id_t tls_seg2;
static uint tls_offs2;
static reg_id_t tls_seg3;
static uint tls_offs3;
#define TLS_SLOT(tls_base, tls_offs, enum_val) \
    (void **)((byte *)(tls_base) + (tls_offs) + (enum_val))
#define BUF_PTR1(tls_base, enum_val) \
    *(aligned_ctxt_hndl_t **)TLS_SLOT(tls_base, tls_offs1, enum_val)
#define BUF_PTR2(tls_base, enum_val) \
    *(bb_cache_message_t **)TLS_SLOT(tls_base, tls_offs2, enum_val)
#define BUF_PTR3(tls_base, enum_val) \
    *(mem_ref_msg_t **)TLS_SLOT(tls_base, tls_offs3, enum_val)
#define MINSERT instrlist_meta_preinsert

static int tls_idx;
static file_t global_log_file;

static client_cb_t global_client_cb;

// static file_t global_debug_file;
static char global_flags = DRCCTLIB_DEFAULT;

static bool (*global_instr_filter)(instr_t *) = DRCCTLIB_FILTER_ZERO_INSTR;

static cct_ip_node_t *global_ip_node_buff;
static context_handle_t global_ip_node_buff_idle_idx = VALID_START_CTXT_HNDL;

#define BB_TABLE_HASH_BITS 10
static hashtable_t global_bb_key_table;

static void *bb_shadow_lock;
static void *bb_node_cache_lock;
static void *splay_node_cache_lock;
static void *bb_shadow_cache_lock;
static memory_cache_t<cct_bb_node_t> *global_bb_node_cache;
static memory_cache_t<splay_node_t> *global_splay_node_cache;
static thread_shared_memory_cache_t<bb_shadow_t> *global_bb_shadow_cache;

static char *global_string_pool;
static int global_string_pool_idle_idx = 0;
#define ATOMIC_ADD_STRING_POOL_INDEX(origin, val) dr_atomic_add32_return_sum(&origin, val)

static ConcurrentShadowMemory<data_handle_t> *global_shadow_memory;

// ctxt to ipnode
static inline context_handle_t
ip_node_to_ctxt_hndl(cct_ip_node_t *ip)
{
    return (context_handle_t)(ip - global_ip_node_buff);
}
// ipnode to ctxt
static inline cct_ip_node_t *
ctxt_hndl_to_ip_node(context_handle_t ctxt_hndl)
{
    return global_ip_node_buff + ctxt_hndl;
}

static inline bool
ctxt_hndl_is_valid(context_handle_t ctxt_hndl)
{
    return ctxt_hndl >= THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE &&
        ctxt_hndl < global_ip_node_buff_idle_idx;
}

static inline bool
ip_node_is_valid(cct_ip_node_t *ip)
{
    context_handle_t ctxt_hndl = ip_node_to_ctxt_hndl(ip);
    return ctxt_hndl_is_valid(ctxt_hndl);
}

static inline cct_bb_node_t *
ip_node_parent_bb_node(cct_ip_node_t *ip)
{
#ifdef IPNODE_STORE_BNODE_IDX
    return global_bb_node_cache->get_object_by_index(ip->parent_bb_node_cache_index);
#else
    return ip->parent_bb_node;
#endif
}

static inline cct_bb_node_t *
ctxt_hndl_parent_bb_node(context_handle_t ctxt_hndl)
{
    return ip_node_parent_bb_node(ctxt_hndl_to_ip_node(ctxt_hndl));
}

static inline void
bb_node_init_cache_index(cct_bb_node_t *bb_node, int32_t index)
{
#ifdef IPNODE_STORE_BNODE_IDX
    bb_node->cache_index = index;
#endif
}

static inline context_handle_t
bb_node_end_ctxt(cct_bb_node_t *bb_node)
{
    return bb_node->child_ctxt_start_idx + bb_node->max_slots - 1;
}

static inline cct_ip_node_t *
bb_node_end_ip(cct_bb_node_t *bb_node)
{
    return ctxt_hndl_to_ip_node(bb_node_end_ctxt(bb_node));
}

static inline cct_bb_node_t *
bb_node_parent_bb(cct_bb_node_t *bb_node)
{
    return bb_node->parent_bb;
}

static inline context_handle_t
bb_node_caller_ctxt_hndl(cct_bb_node_t *bb_node)
{
    cct_bb_node_t *parent_bb = bb_node_parent_bb(bb_node);
    if (parent_bb == NULL) {
        return THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE;
    }
    return bb_node_end_ctxt(parent_bb);
}

static inline context_handle_t
cur_child_ctxt_start_idx(slot_t num)
{
    context_handle_t next_start_idx =
        ATOMIC_ADD_CTXT_HNDL(global_ip_node_buff_idle_idx, num);
    if (next_start_idx >= CONTEXT_HANDLE_MAX) {
        DRCCTLIB_EXIT_PROCESS("Preallocated IPNodes exhausted. CCTLib couldn't fit your "
                              "application in its memory. Try a smaller program.");
    }

    return next_start_idx - num;
}

#ifdef ARM_CCTLIB
static bool
instr_is_exclusive_load(instr_t *instr)
{
    switch (instr_get_opcode(instr)) {
    case OP_ldaxp:
    case OP_ldaxr:
    case OP_ldaxrb:
    case OP_ldaxrh:
    case OP_ldxp:
    case OP_ldxr:
    case OP_ldxrb:
    case OP_ldxrh: return true;
    }
    return false;
}

static bool
instr_is_ldstex(instr_t *instr)
{
    if (instr_get_opcode(instr) == OP_ldstex) {
        return true;
    }
    return false;
}
#endif

// instr state flag
static inline bool
instr_state_contain(state_t instr_state_flag, state_t state)
{
    return (instr_state_flag & state) > 0;
}

static inline bool
instr_need_instrument_check_flag(state_t instr_state_flag)
{
    return instr_state_contain(instr_state_flag, INSTR_STATE_CLIENT_INTEREST) ||
        instr_state_contain(instr_state_flag, INSTR_STATE_CALL_DIRECT) ||
        instr_state_contain(instr_state_flag, INSTR_STATE_CALL_IN_DIRECT) ||
        instr_state_contain(instr_state_flag, INSTR_STATE_RETURN);
}

static inline bool
instr_need_instrument(instr_t *instr)
{
    if (instr_is_call_direct(instr) || instr_is_call_indirect(instr) ||
        instr_is_return(instr)) {
        return true;
    }
    if (global_instr_filter(instr)) {
        return true;
    }
    return false;
}

static inline state_t
instr_get_state(instr_t *instr)
{
    state_t flag = 0;
    if (global_instr_filter(instr)) {
        flag = flag | INSTR_STATE_CLIENT_INTEREST;
    }
    if (instr_reads_memory(instr) || instr_writes_memory(instr)) {
        flag = flag | INSTR_STATE_MEM_ACCESS;
    }
    if (instr_is_call_direct(instr)) {
        flag = flag | INSTR_STATE_CALL_DIRECT;
    } else if (instr_is_call_indirect(instr)) {
        flag = flag | INSTR_STATE_CALL_IN_DIRECT;
    } else if (instr_is_return(instr)) {
        flag = flag | INSTR_STATE_RETURN;
    }
    return flag;
}

static inline void
bb_init_shadow_config(instrlist_t *bb, slot_t *interest_ins_num, state_t *end_state,
                      int32_t *mem_ref_num)
{
#ifdef ARM32_CCTLIB
    instr_t *bb_first = instr_get_next_app(instrlist_first_app(bb));
#else
    instr_t *bb_first = instrlist_first_app(bb);
#endif

#ifdef ARM_CCTLIB
    if (instr_is_exclusive_store(bb_first)) {
        return;
    }
    bool skip = false;
#endif
    for (instr_t *instr = bb_first; instr != NULL; instr = instr_get_next_app(instr)) {
#ifdef ARM_CCTLIB
        if (!skip && (instr_is_exclusive_load(instr) || instr_is_ldstex(instr))) {
            skip = true;
        }
        if (!skip) {
#endif
            state_t state = instr_get_state(instr);
            if (instr_need_instrument_check_flag(state)) {
                *end_state = state;
                (*interest_ins_num)++;
            }
            if (instr_state_contain(state, INSTR_STATE_CLIENT_INTEREST)) {
                for (int i = 0; i < instr_num_srcs(instr); i++) {
                    if (opnd_is_memory_reference(instr_get_src(instr, i))) {
                        (*mem_ref_num)++;
                    }
                }
                for (int i = 0; i < instr_num_dsts(instr); i++) {
                    if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
                        (*mem_ref_num)++;
                    }
                }
            }
#ifdef ARM_CCTLIB
        }
        if (skip && (instr_is_exclusive_store(instr) || instr_is_ldstex(instr))) {
            skip = false;
        }
#endif
    }
    return;
}

static inline void
bb_shadow_create(bb_shadow_t *bb_shadow, int32_t index)
{
    bb_shadow->key = index;
    bb_shadow->ip_shadow = NULL;
    bb_shadow->state_shadow = NULL;
    bb_shadow->disasm_shadow = NULL;
#ifdef IN_PROCESS_SPEEDUP
    bb_shadow->last_same_key_bb_pt_list = NULL;
#endif
}

static inline void
bb_shadow_init_config(bb_shadow_t *bb_shadow, slot_t slot_num, state_t end_ins_state,
                      int32_t mem_ref_num)
{
    bb_shadow->slot_num = slot_num;
    bb_shadow->end_ins_state = end_ins_state;
    bb_shadow->mem_ref_num = mem_ref_num;
}

static inline void
bb_shadow_create_cache(bb_shadow_t *bb_shadow)
{
    if (bb_shadow->slot_num <= 0) {
        return;
    }
    bb_shadow->ip_shadow = (app_pc *)dr_raw_mem_alloc(
        bb_shadow->slot_num * sizeof(app_pc), DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    bb_shadow->state_shadow = (state_t *)dr_raw_mem_alloc(
        bb_shadow->slot_num * sizeof(state_t), DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    bb_shadow->disasm_shadow =
        (char *)dr_raw_mem_alloc(bb_shadow->slot_num * DISASM_CACHE_SIZE * sizeof(char),
                                 DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
#ifdef IN_PROCESS_SPEEDUP
    bb_shadow->last_same_key_bb_pt_list = (cct_bb_node_t **)dr_raw_mem_alloc(
        SPEEDUP_SUPPORT_THREAD_MAX_NUM * sizeof(cct_bb_node_t *),
        DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
#endif
}

static inline void
bb_shadow_free_cache(bb_shadow_t *bb_shadow)
{
    if (bb_shadow->slot_num <= 0 || bb_shadow->ip_shadow == NULL) {
        return;
    }
    dr_raw_mem_free(bb_shadow->ip_shadow, bb_shadow->slot_num * sizeof(app_pc));
    dr_raw_mem_free(bb_shadow->state_shadow, bb_shadow->slot_num * sizeof(state_t));
    dr_raw_mem_free(bb_shadow->disasm_shadow,
                    bb_shadow->slot_num * DISASM_CACHE_SIZE * sizeof(char));
#ifdef IN_PROCESS_SPEEDUP
    dr_raw_mem_free(bb_shadow->last_same_key_bb_pt_list,
                    SPEEDUP_SUPPORT_THREAD_MAX_NUM * sizeof(cct_bb_node_t *));
#endif
}

static inline cct_bb_node_t *
bb_node_create(tls_memory_cache_t<cct_bb_node_t> *tls_cache, bb_key_t key,
               cct_bb_node_t *parent_bb, slot_t num)
{
    cct_bb_node_t *new_node = tls_cache->get_next_object();
    new_node->parent_bb = parent_bb;
    new_node->key = key;
    new_node->child_ctxt_start_idx = cur_child_ctxt_start_idx(num);
    new_node->max_slots = num;
    new_node->callee_splay_tree_root = NULL;
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    new_node->callee_tree_size = 0;
#endif
    cct_ip_node_t *children = ctxt_hndl_to_ip_node(new_node->child_ctxt_start_idx);
    for (slot_t i = 0; i < num; ++i) {
#ifdef IPNODE_STORE_BNODE_IDX
        children[i].parent_bb_node_cache_index = new_node->cache_index;
#else
        children[i].parent_bb_node = new_node;
#endif
    }
    return new_node;
}

static inline void
instr_instrument_client_cb(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    if (instr_state_contain(instrument_msg->state, INSTR_STATE_CLIENT_INTEREST) &&
        global_client_cb.func_instr_analysis != NULL) {
        (*global_client_cb.func_instr_analysis)(drcontext, instrument_msg);
    }
}

static inline instr_instrument_msg_t *
instr_instrument_msg_create(instrlist_t *bb, instr_t *instr, bool interest_start,
                            slot_t slot, state_t state)
{
    instr_instrument_msg_t *msg =
        (instr_instrument_msg_t *)dr_global_alloc(sizeof(instr_instrument_msg_t));
    msg->bb = bb;
    msg->instr = instr;
    msg->interest_start = interest_start;
    msg->slot = slot;
    msg->state = state;
    msg->next = NULL;
    return msg;
}

static inline void
instr_instrument_msg_delete(instr_instrument_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    dr_global_free(msg, sizeof(instr_instrument_msg_t));
}

static inline bb_instrument_msg_t *
bb_instrument_msg_create(bb_key_t bb_key, slot_t slot_max, state_t bb_end_state,
                         int32_t mem_ref_num, bb_shadow_t *bb_shadow)
{
    bb_instrument_msg_t *bb_msg =
        (bb_instrument_msg_t *)dr_global_alloc(sizeof(bb_instrument_msg_t));
    bb_msg->slot_max = slot_max;
    bb_msg->bb_key = bb_key;
    bb_msg->bb_end_state = bb_end_state;
    bb_msg->mem_ref_num = mem_ref_num;
    bb_msg->bb_shadow = bb_shadow;
    return bb_msg;
}

static inline void
bb_instrument_msg_delete(bb_instrument_msg_t *bb_msg)
{
    if (bb_msg == NULL) {
        return;
    }
    dr_global_free(bb_msg, sizeof(bb_instrument_msg_t));
}

#ifdef CCTLIB_64
static inline void
per_thread_bb_end_cb(void *drcontext, context_handle_t bb_child_ctxt_start_idx,
                     slot_t slot_num, int32_t memory_ref_num,
                     mem_ref_msg_t *mem_ref_cache, void **bb_call_back_cache_data_ptr)
{
    if (global_client_cb.func_insert_bb_end != NULL) {
        (*global_client_cb.func_insert_bb_end)(drcontext, bb_child_ctxt_start_idx,
                                               slot_num, memory_ref_num, mem_ref_cache,
                                               bb_call_back_cache_data_ptr);
    }
}

static inline void
per_thread_init_stack_cache(void *drcontext, per_thread_t *pt)
{
    if (pt->bb_cache[0].bb_shadow != NULL) {
        if (!pt->init_stack_cache) {
            dr_mcontext_t mcontext = {
                sizeof(mcontext),
                DR_MC_ALL,
            };
            dr_get_mcontext(drcontext, &mcontext);
            pt->stack_base = (void *)(ptr_int_t)reg_get_value(DR_STACK_REG, &mcontext);
            // DRCCTLIB_PRINTF("pt %d stack_base %p stack size %p stack_end %p", pt->id,
            //                 pt->stack_base, (ptr_int_t)pt->stack_size,
            //                 (ptr_int_t)pt->stack_base - (ptr_int_t)pt->stack_size);
            pt->init_stack_cache = true;
        }
        pt->bb_cache[1].bb_shadow = pt->bb_cache[0].bb_shadow;
        pt->bb_cache[0].bb_shadow = NULL;
    }
}

static inline void
per_thread_refresh_bb_cache(void *drcontext, per_thread_t *pt)
{
    if (pt->bb_cache[1].bb_shadow == NULL) {
        return;
    }
    // read & write
    cct_bb_node_t *cur_bb_node = pt->cur_bb_node;
    splay_node_t *next_splay_node = pt->next_splay_node;
    bb_shadow_t *pre_bb_shadow = pt->pre_bb_shadow;
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    per_thread_cct_info_t temp_cct_info = pt->cct_info;
    int64_t splay_tree_search_num = 0;
#    endif

    // read only
    bb_cache_message_t *bb_cache = pt->bb_cache;
    cct_bb_node_t *root_node = pt->root_bb_node;
    void **bb_call_back_cache_data_ptr = &pt->bb_call_back_cache_data;
    tls_memory_cache_t<cct_bb_node_t> *bb_node_cache = pt->bb_node_cache;
    tls_memory_cache_t<splay_node_t> *splay_node_cache = pt->splay_node_cache;
    splay_node_t *dummy_splay_node = pt->dummy_splay_node;
#    ifdef IN_PROCESS_SPEEDUP
    int speedup_cache_index = pt->speedup_cache_index;
#    endif

    for (thread_aligned_num_t i = 1; i < BB_CACHE_MESSAGE_MAX_NUM; i++) {
        if (bb_cache[i].bb_shadow != NULL) {
            per_thread_bb_end_cb(drcontext, cur_bb_node->child_ctxt_start_idx,
                                 pre_bb_shadow->slot_num, 0, NULL,
                                 bb_call_back_cache_data_ptr);

            bb_shadow_t *cur_bb_shadow = bb_cache[i].bb_shadow;
            cct_bb_node_t *new_caller_bb_node = NULL;
            if (instr_state_contain(pre_bb_shadow->end_ins_state,
                                    INSTR_STATE_THREAD_ROOT_VIRTUAL)) {
                new_caller_bb_node = root_node;
            } else if (instr_state_contain(pre_bb_shadow->end_ins_state,
                                           INSTR_STATE_CALL_DIRECT) ||
                       instr_state_contain(pre_bb_shadow->end_ins_state,
                                           INSTR_STATE_CALL_IN_DIRECT)) {
                new_caller_bb_node = cur_bb_node;
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                temp_cct_info.call_num++;
                temp_cct_info.cur_tree_high++;
#    endif
            } else if (instr_state_contain(pre_bb_shadow->end_ins_state,
                                           INSTR_STATE_RETURN)) {
                if (bb_node_parent_bb(cur_bb_node) == root_node) {
                    new_caller_bb_node = bb_node_parent_bb(cur_bb_node);
                } else {
                    new_caller_bb_node =
                        bb_node_parent_bb(bb_node_parent_bb(cur_bb_node));
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                    temp_cct_info.cur_tree_high--;
#    endif
                }
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                temp_cct_info.return_num++;
#    endif
            } else {
                new_caller_bb_node = bb_node_parent_bb(cur_bb_node);
            }

#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
            temp_cct_info.ins_num += cur_bb_shadow->slot_num;
            temp_cct_info.bb_node_num++;
            if (temp_cct_info.tree_high < temp_cct_info.cur_tree_high) {
                temp_cct_info.tree_high = temp_cct_info.cur_tree_high;
            }
#    endif
#    ifdef IN_PROCESS_SPEEDUP
            if (speedup_cache_index >= 0 &&
                cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index] != NULL) {
                if (bb_node_parent_bb(
                        cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index]) ==
                    new_caller_bb_node) {
                    cur_bb_node =
                        cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index];
#        ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                    splay_tree_search_num++;
#        endif
                    pre_bb_shadow = cur_bb_shadow;
                    bb_cache[i].bb_shadow = NULL;
                    continue;
                }
            }
#    endif
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
            splay_node_t *new_root = splay_tree_update_test(
                new_caller_bb_node->callee_splay_tree_root,
                (splay_node_key_t)cur_bb_shadow->key, dummy_splay_node, next_splay_node,
                &splay_tree_search_num);
#    else
            splay_node_t *new_root = splay_tree_update(
                new_caller_bb_node->callee_splay_tree_root,
                (splay_node_key_t)cur_bb_shadow->key, dummy_splay_node, next_splay_node);
#    endif
            if (new_root->payload == NULL) {
                new_root->payload =
                    (void *)bb_node_create(bb_node_cache, cur_bb_shadow->key,
                                           new_caller_bb_node, cur_bb_shadow->slot_num);
                next_splay_node = splay_node_cache->get_next_object();
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                temp_cct_info.real_node_num++;
                new_caller_bb_node->callee_tree_size++;
#    endif
            }
            new_caller_bb_node->callee_splay_tree_root = new_root;
            cur_bb_node = (cct_bb_node_t *)(new_root->payload);
#    ifdef IN_PROCESS_SPEEDUP
            if (speedup_cache_index >= 0) {
                cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index] =
                    cur_bb_node;
            }
#    endif
            pre_bb_shadow = cur_bb_shadow;
            bb_cache[i].bb_shadow = NULL;
        } else {
            break;
        }
    }
    pt->cur_bb_node = cur_bb_node;
    pt->next_splay_node = next_splay_node;
    pt->pre_bb_shadow = pre_bb_shadow;
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    temp_cct_info.cct_create_clean_call_num++;
    temp_cct_info.splay_tree_search_num += splay_tree_search_num;
    pt->cct_info = temp_cct_info;
#    endif

    pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
    pt->pre_instr_state = pt->pre_bb_shadow->end_ins_state;
    BUF_PTR2(pt->cur_buf2, INSTRACE_TLS_OFFS_BUF_PTR) = pt->bb_cache + 1;
}

static inline void
per_thread_update_cct_tree()
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    per_thread_init_stack_cache(drcontext, pt);
    per_thread_refresh_bb_cache(drcontext, pt);
}

static inline void
per_thread_refresh_bb_cache_and_mem_ref_cache(void *drcontext, per_thread_t *pt)
{
    if (pt->bb_cache[1].bb_shadow == NULL) {
        return;
    }
    // read & write
    cct_bb_node_t *cur_bb_node = pt->cur_bb_node;
    splay_node_t *next_splay_node = pt->next_splay_node;
    bb_shadow_t *pre_bb_shadow = pt->pre_bb_shadow;
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    per_thread_cct_info_t temp_cct_info = pt->cct_info;
    int64_t splay_tree_search_num = 0;
#    endif

    // read only
    bb_cache_message_t *bb_cache = pt->bb_cache;
    mem_ref_msg_t *inner_mem_ref_cache = pt->inner_mem_ref_cache;
    cct_bb_node_t *root_node = pt->root_bb_node;
    void **bb_call_back_cache_data_ptr = &pt->bb_call_back_cache_data;
    tls_memory_cache_t<cct_bb_node_t> *bb_node_cache = pt->bb_node_cache;
    tls_memory_cache_t<splay_node_t> *splay_node_cache = pt->splay_node_cache;
    splay_node_t *dummy_splay_node = pt->dummy_splay_node;
#    ifdef IN_PROCESS_SPEEDUP
    int speedup_cache_index = pt->speedup_cache_index;
#    endif

    thread_aligned_num_t pre_bb_start_index = 0;

    for (thread_aligned_num_t i = 1; i < BB_CACHE_MESSAGE_MAX_NUM; i++) {
        if (bb_cache[i].bb_shadow != NULL) {
            per_thread_bb_end_cb(drcontext, cur_bb_node->child_ctxt_start_idx,
                                 pre_bb_shadow->slot_num, pre_bb_shadow->mem_ref_num,
                                 inner_mem_ref_cache + pre_bb_start_index,
                                 bb_call_back_cache_data_ptr);

            pre_bb_start_index += pre_bb_shadow->mem_ref_num;
            bb_shadow_t *cur_bb_shadow = bb_cache[i].bb_shadow;
            cct_bb_node_t *new_caller_bb_node = NULL;
            if (instr_state_contain(pre_bb_shadow->end_ins_state,
                                    INSTR_STATE_THREAD_ROOT_VIRTUAL)) {
                new_caller_bb_node = root_node;
            } else if (instr_state_contain(pre_bb_shadow->end_ins_state,
                                           INSTR_STATE_CALL_DIRECT) ||
                       instr_state_contain(pre_bb_shadow->end_ins_state,
                                           INSTR_STATE_CALL_IN_DIRECT)) {
                new_caller_bb_node = cur_bb_node;
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                temp_cct_info.call_num++;
                temp_cct_info.cur_tree_high++;
#    endif
            } else if (instr_state_contain(pre_bb_shadow->end_ins_state,
                                           INSTR_STATE_RETURN)) {
                if (bb_node_parent_bb(cur_bb_node) == root_node) {
                    new_caller_bb_node = bb_node_parent_bb(cur_bb_node);
                } else {
                    new_caller_bb_node =
                        bb_node_parent_bb(bb_node_parent_bb(cur_bb_node));
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                    temp_cct_info.cur_tree_high--;
#    endif
                }
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                temp_cct_info.return_num++;
#    endif
            } else {
                new_caller_bb_node = bb_node_parent_bb(cur_bb_node);
            }

#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
            temp_cct_info.ins_num += cur_bb_shadow->slot_num;
            temp_cct_info.mem_ref_num += cur_bb_shadow->mem_ref_num;
            temp_cct_info.bb_node_num++;
            if (temp_cct_info.tree_high < temp_cct_info.cur_tree_high) {
                temp_cct_info.tree_high = temp_cct_info.cur_tree_high;
            }
#    endif
#    ifdef IN_PROCESS_SPEEDUP
            if (speedup_cache_index >= 0 &&
                cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index] != NULL) {
                if (bb_node_parent_bb(
                        cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index]) ==
                    new_caller_bb_node) {
                    cur_bb_node =
                        cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index];
#        ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                    splay_tree_search_num++;
#        endif
                    pre_bb_shadow = cur_bb_shadow;
                    bb_cache[i].bb_shadow = NULL;
                    continue;
                }
            }
#    endif
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
            splay_node_t *new_root = splay_tree_update_test(
                new_caller_bb_node->callee_splay_tree_root,
                (splay_node_key_t)cur_bb_shadow->key, dummy_splay_node, next_splay_node,
                &splay_tree_search_num);
#    else
            splay_node_t *new_root = splay_tree_update(
                new_caller_bb_node->callee_splay_tree_root,
                (splay_node_key_t)cur_bb_shadow->key, dummy_splay_node, next_splay_node);
#    endif
            if (new_root->payload == NULL) {
                new_root->payload =
                    (void *)bb_node_create(bb_node_cache, cur_bb_shadow->key,
                                           new_caller_bb_node, cur_bb_shadow->slot_num);
                next_splay_node = splay_node_cache->get_next_object();
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
                temp_cct_info.real_node_num++;
                new_caller_bb_node->callee_tree_size++;
#    endif
            }
            new_caller_bb_node->callee_splay_tree_root = new_root;
            cur_bb_node = (cct_bb_node_t *)(new_root->payload);
#    ifdef IN_PROCESS_SPEEDUP
            if (speedup_cache_index >= 0) {
                cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index] =
                    cur_bb_node;
            }
#    endif
            pre_bb_shadow = cur_bb_shadow;
            bb_cache[i].bb_shadow = NULL;
        } else {
            break;
        }
    }
    pt->cur_bb_node = cur_bb_node;
    pt->next_splay_node = next_splay_node;
    pt->pre_bb_shadow = pre_bb_shadow;
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    temp_cct_info.cct_create_clean_call_num++;
    temp_cct_info.splay_tree_search_num += splay_tree_search_num;
    pt->cct_info = temp_cct_info;
#    endif

    pt->cur_bb_child_ctxt_start_idx = cur_bb_node->child_ctxt_start_idx;
    pt->pre_instr_state = pre_bb_shadow->end_ins_state;
    BUF_PTR2(pt->cur_buf2, INSTRACE_TLS_OFFS_BUF_PTR) = bb_cache + 1;

    thread_aligned_num_t pre_bb_end_index =
        pre_bb_start_index + pre_bb_shadow->mem_ref_num;
    thread_aligned_num_t max_index = INNER_MEM_REF_CACHE_MAX >= pre_bb_end_index
        ? pre_bb_end_index
        : INNER_MEM_REF_CACHE_MAX;
    thread_aligned_num_t last_index = pre_bb_start_index;
    for (; last_index < max_index; last_index++) {
        if (inner_mem_ref_cache[last_index].addr != 0) {
            inner_mem_ref_cache[last_index - pre_bb_start_index].slot =
                inner_mem_ref_cache[last_index].slot;
            inner_mem_ref_cache[last_index - pre_bb_start_index].addr =
                inner_mem_ref_cache[last_index].addr;
            inner_mem_ref_cache[last_index].addr = 0;
        } else {
            break;
        }
    }
    BUF_PTR3(pt->cur_buf3, INSTRACE_TLS_OFFS_BUF_PTR) =
        inner_mem_ref_cache + last_index - pre_bb_start_index;
    for (thread_aligned_num_t index = last_index - pre_bb_start_index;
         index < pre_bb_start_index; index++) {
        inner_mem_ref_cache[index].addr = 0;
    }
}

static inline void
per_thread_update_cct_tree_memory_cache()
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    per_thread_init_stack_cache(drcontext, pt);
    per_thread_refresh_bb_cache_and_mem_ref_cache(drcontext, pt);
}

static inline void
refresh_per_thread_cct_tree(void *drcontext, per_thread_t *pt)
{
    if ((global_flags & DRCCTLIB_CACHE_MODE) == 0) {
        return;
    }
    per_thread_init_stack_cache(drcontext, pt);
    if ((global_flags & DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR) != 0) {
        per_thread_refresh_bb_cache_and_mem_ref_cache(drcontext, pt);
    } else {
        per_thread_refresh_bb_cache(drcontext, pt);
    }
}

static inline void
per_thread_end_bb_cache_refresh(void *drcontext, per_thread_t *pt)
{
    if ((global_flags & DRCCTLIB_CACHE_MODE) == 0) {
        return;
    }
    per_thread_bb_end_cb(drcontext, pt->cur_bb_node->child_ctxt_start_idx,
                         pt->pre_bb_shadow->slot_num, 0, NULL,
                         &pt->bb_call_back_cache_data);
}

#    ifdef ARM64_CCTLIB
#        define DRCCTLIB_LOAD_IMM32_0(dc, Rt, imm) \
            INSTR_CREATE_movz((dc), (Rt), (imm), OPND_CREATE_INT(0))
#        define DRCCTLIB_LOAD_IMM32_16(dc, Rt, imm) \
            INSTR_CREATE_movk((dc), (Rt), (imm), OPND_CREATE_INT(16))
#        define DRCCTLIB_LOAD_IMM32_32(dc, Rt, imm) \
            INSTR_CREATE_movk((dc), (Rt), (imm), OPND_CREATE_INT(32))
#        define DRCCTLIB_LOAD_IMM32_48(dc, Rt, imm) \
            INSTR_CREATE_movk((dc), (Rt), (imm), OPND_CREATE_INT(48))
static inline void
minstr_load_wint_to_reg(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
                        int32_t wint_num)
{
    MINSERT(ilist, where,
            DRCCTLIB_LOAD_IMM32_0(drcontext, opnd_create_reg(reg),
                                  OPND_CREATE_IMMEDIATE_INT(wint_num & 0xffff)));
    MINSERT(ilist, where,
            DRCCTLIB_LOAD_IMM32_16(drcontext, opnd_create_reg(reg),
                                   OPND_CREATE_IMMEDIATE_INT((wint_num >> 16) & 0xffff)));
}

static inline void
minstr_load_wwint_to_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                         reg_id_t reg, uint64_t wwint_num)
{
    MINSERT(ilist, where,
            DRCCTLIB_LOAD_IMM32_0(drcontext, opnd_create_reg(reg),
                                  OPND_CREATE_IMMEDIATE_INT(wwint_num & 0xffff)));
    MINSERT(
        ilist, where,
        DRCCTLIB_LOAD_IMM32_16(drcontext, opnd_create_reg(reg),
                               OPND_CREATE_IMMEDIATE_INT((wwint_num >> 16) & 0xffff)));
    MINSERT(
        ilist, where,
        DRCCTLIB_LOAD_IMM32_32(drcontext, opnd_create_reg(reg),
                               OPND_CREATE_IMMEDIATE_INT((wwint_num >> 32) & 0xffff)));
    MINSERT(
        ilist, where,
        DRCCTLIB_LOAD_IMM32_48(drcontext, opnd_create_reg(reg),
                               OPND_CREATE_IMMEDIATE_INT((wwint_num >> 48) & 0xffff)));
}
#    endif

static inline void
instrument_before_every_bb_first(void *drcontext, instr_instrument_msg_t *instrument_msg,
                                 bb_instrument_msg_t *bb_msg)
{
    instrlist_t *ilist = instrument_msg->bb;
    instr_t *where = instrument_msg->instr;

    reg_id_t reg_1, reg_2, reg_3;
    instr_t *skip_to_call = INSTR_CREATE_label(drcontext);
    instr_t *skip_clean_call = INSTR_CREATE_label(drcontext);
#    ifndef ARM64_CCTLIB
    if (drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "instrument_before_every_bb_first drreg_reserve_aflags != DRREG_SUCCESS");
    }
#    endif
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_1) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_2) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_3) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "instrument_before_every_bb_first drreg_reserve_register != DRREG_SUCCESS");
    }

    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg2,
                           tls_offs2 + INSTRACE_TLS_OFFS_BUF_PTR, reg_1);
#    ifdef ARM64_CCTLIB
    // bb_cache[cur_index]->bb_shadow init
    minstr_load_wwint_to_reg(drcontext, ilist, where, reg_2,
                             (uint64_t)(void *)bb_msg->bb_shadow);
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_1, offsetof(bb_cache_message_t, bb_shadow)),
                opnd_create_reg(reg_2)));

    // get bb_cache[cur_index]->index
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_2),
                              OPND_CREATE_MEM64(reg_1, 0)));
    // bb_cache[cur_index]->index == 1 jump to clean call
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_3),
                                  OPND_CREATE_IMMEDIATE_INT(1)));
    MINSERT(ilist, where,
            XINST_CREATE_sub(drcontext, opnd_create_reg(reg_3), opnd_create_reg(reg_2)));
    MINSERT(ilist, where,
            INSTR_CREATE_cbz(drcontext, opnd_create_instr(skip_to_call),
                             opnd_create_reg(reg_3)));
    // bb_cache[cur_index]->index == BB_CACHE_MESSAGE_MAX_NUM jump to clean call
    minstr_load_wint_to_reg(drcontext, ilist, where, reg_3, BB_CACHE_MESSAGE_MAX_NUM);
    MINSERT(ilist, where,
            XINST_CREATE_sub(drcontext, opnd_create_reg(reg_3), opnd_create_reg(reg_2)));
    MINSERT(ilist, where,
            INSTR_CREATE_cbz(drcontext, opnd_create_instr(skip_to_call),
                             opnd_create_reg(reg_3)));
    // cur_index++
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_2),
                                  OPND_CREATE_IMMEDIATE_INT(sizeof(bb_cache_message_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_1), opnd_create_reg(reg_2)));
#    else
    // bb_cache[cur_index]->bb_shadow init
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_2),
                                  OPND_CREATE_SHADOWPRT(bb_msg->bb_shadow)));
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_1, offsetof(bb_cache_message_t, bb_shadow)),
                opnd_create_reg(reg_2)));

    // get bb_cache[cur_index]->index
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_2),
                              OPND_CREATE_MEM64(reg_1, 0)));
    // bb_cache[cur_index]->index == 1 jump to clean call
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_2), OPND_CREATE_INT32(1)));
    MINSERT(
        ilist, where,
        XINST_CREATE_jump_cond(drcontext, DR_PRED_Z, opnd_create_instr(skip_to_call)));
    // bb_cache[cur_index]->index == BB_CACHE_MESSAGE_MAX_NUM jump to clean call
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_2),
                             OPND_CREATE_INT32(BB_CACHE_MESSAGE_MAX_NUM)));
    MINSERT(
        ilist, where,
        XINST_CREATE_jump_cond(drcontext, DR_PRED_Z, opnd_create_instr(skip_to_call)));
    // cur_index++
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_1),
                             OPND_CREATE_INT32(sizeof(bb_cache_message_t))));
#    endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg2,
                            tls_offs2 + INSTRACE_TLS_OFFS_BUF_PTR, reg_1);
#    ifdef ARM64_CCTLIB
    // skip clean call
    MINSERT(ilist, where,
            INSTR_CREATE_cbnz(drcontext, opnd_create_instr(skip_clean_call),
                              opnd_create_reg(reg_2)));
#    else
    // skip clean call
    MINSERT(ilist, where,
            XINST_CREATE_jump(drcontext, opnd_create_instr(skip_clean_call)));
#    endif
    MINSERT(ilist, where, skip_to_call);
    dr_insert_clean_call(drcontext, ilist, where, (void *)per_thread_update_cct_tree,
                         false, 0);
    MINSERT(ilist, where, skip_clean_call);

    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_2) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_3) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "instrument_before_every_bb_first drreg_unreserve_register != DRREG_SUCCESS");
    }
#    ifndef ARM64_CCTLIB
    if (drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "instrument_before_every_bb_first drreg_unreserve_aflags != DRREG_SUCCESS");
    }
#    endif
}

static inline void
instrument_memory_cache_every_mem_access(void *drcontext, instrlist_t *ilist,
                                         instr_t *where, slot_t slot, opnd_t ref,
                                         reg_id_t reg_mem_ref_ptr, reg_id_t reg_1,
                                         reg_id_t reg_2)
{
#    ifdef ARM64_CCTLIB
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_1, reg_2)) {
        MINSERT(ilist, where,
                XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_1),
                                      OPND_CREATE_IMMEDIATE_INT(0)));
    }
    // store mem_ref_msg_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_msg_t, addr)),
                opnd_create_reg(reg_1)));

    // store mem_ref_msg_t->slot
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_1),
                                  OPND_CREATE_IMMEDIATE_INT(slot)));
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_msg_t, slot)),
                opnd_create_reg(reg_1)));

    // reg_mem_ref_ptr to next mem_ref_msg_t
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_1),
                                  OPND_CREATE_IMMEDIATE_INT(sizeof(mem_ref_msg_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             opnd_create_reg(reg_1)));
#    else
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_1, reg_2)) {
        // store mem_ref_msg_t->addr
        MINSERT(ilist, where,
                XINST_CREATE_store(
                    drcontext,
                    OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_msg_t, addr)),
                    OPND_CREATE_INT32(0)));
    } else {
        // store mem_ref_msg_t->addr
        MINSERT(ilist, where,
                XINST_CREATE_store(
                    drcontext,
                    OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_msg_t, addr)),
                    opnd_create_reg(reg_1)));
    }
    // store mem_ref_msg_t->slot
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_msg_t, slot)),
                OPND_CREATE_INT32(slot)));

    // reg_mem_ref_ptr to next mem_ref_msg_t
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             OPND_CREATE_INT32(sizeof(mem_ref_msg_t))));
#    endif
}

static inline void
instrument_memory_cache_every_memory_instr(void *drcontext,
                                           instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *ilist = instrument_msg->bb;
    instr_t *where = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
#    ifndef ARM64_CCTLIB
    if (drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_every_memory_instr "
                              "drreg_reserve_aflags != DRREG_SUCCESS");
    }
#    endif
    reg_id_t reg_1, reg_2, reg_mem_ref_ptr;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_1) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_2) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_every_memory_instr "
                              "drreg_reserve_register != DRREG_SUCCESS");
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg3,
                           tls_offs3 + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    for (int i = 0; i < instr_num_srcs(where); i++) {
        if (opnd_is_memory_reference(instr_get_src(where, i))) {
            instrument_memory_cache_every_mem_access(drcontext, ilist, where, slot,
                                                     instr_get_src(where, i),
                                                     reg_mem_ref_ptr, reg_1, reg_2);
        }
    }
    for (int i = 0; i < instr_num_dsts(where); i++) {
        if (opnd_is_memory_reference(instr_get_dst(where, i))) {
            instrument_memory_cache_every_mem_access(drcontext, ilist, where, slot,
                                                     instr_get_dst(where, i),
                                                     reg_mem_ref_ptr, reg_1, reg_2);
        }
    }
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg3,
                            tls_offs3 + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    if (drreg_unreserve_register(drcontext, ilist, where, reg_1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_2) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_every_memory_instr "
                              "drreg_unreserve_register != DRREG_SUCCESS");
    }
#    ifndef ARM64_CCTLIB
    if (drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_every_memory_instr "
                              "drreg_unreserve_aflags != DRREG_SUCCESS");
    }
#    endif
}

static inline void
instrument_memory_cache_before_every_bb_first(void *drcontext,
                                              instr_instrument_msg_t *instrument_msg,
                                              bb_instrument_msg_t *bb_msg)
{
    instrlist_t *ilist = instrument_msg->bb;
    instr_t *where = instrument_msg->instr;

    reg_id_t reg_1, reg_2, reg_3;
    reg_id_t reg_mem_ref_ptr;
    instr_t *skip_to_call = INSTR_CREATE_label(drcontext);
    instr_t *skip_clean_call = INSTR_CREATE_label(drcontext);
    if (drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_before_every_bb_first "
                              "drreg_reserve_aflags != DRREG_SUCCESS");
    }
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_1) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_2) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_3) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_before_every_bb_first "
                              "drreg_reserve_register != DRREG_SUCCESS");
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg2,
                           tls_offs2 + INSTRACE_TLS_OFFS_BUF_PTR, reg_1);
#    ifdef ARM64_CCTLIB
    // bb_cache[cur_index]->bb_shadow init
    minstr_load_wwint_to_reg(drcontext, ilist, where, reg_2,
                             (uint64_t)(void *)bb_msg->bb_shadow);
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_1, offsetof(bb_cache_message_t, bb_shadow)),
                opnd_create_reg(reg_2)));

    // get bb_cache[cur_index]->index
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_2),
                              OPND_CREATE_MEM64(reg_1, 0)));

    // bb_cache[cur_index]->index == 1 jump to clean call
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_3),
                                  OPND_CREATE_IMMEDIATE_INT(1)));
    MINSERT(ilist, where,
            XINST_CREATE_sub(drcontext, opnd_create_reg(reg_3), opnd_create_reg(reg_2)));
    MINSERT(ilist, where,
            INSTR_CREATE_cbz(drcontext, opnd_create_instr(skip_to_call),
                             opnd_create_reg(reg_3)));
    // bb_cache[cur_index]->index == BB_CACHE_MESSAGE_MAX_NUM jump to clean call
    minstr_load_wint_to_reg(drcontext, ilist, where, reg_3, BB_CACHE_MESSAGE_MAX_NUM);
    MINSERT(ilist, where,
            XINST_CREATE_sub(drcontext, opnd_create_reg(reg_3), opnd_create_reg(reg_2)));
    MINSERT(ilist, where,
            INSTR_CREATE_cbz(drcontext, opnd_create_instr(skip_to_call),
                             opnd_create_reg(reg_3)));
    // inner_mem_ref_cache[cur_index]->index + bb_msg->mem_ref_num >
    // INNER_MEM_REF_CACHE_MAX jump to clean call
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg3,
                           tls_offs3 + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_2),
                              OPND_CREATE_MEM64(reg_mem_ref_ptr, 0)));
    minstr_load_wint_to_reg(drcontext, ilist, where, reg_3, bb_msg->mem_ref_num);
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_2), opnd_create_reg(reg_3)));
    minstr_load_wint_to_reg(drcontext, ilist, where, reg_3, INNER_MEM_REF_CACHE_MAX);
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_2), opnd_create_reg(reg_3)));
    MINSERT(
        ilist, where,
        XINST_CREATE_jump_cond(drcontext, DR_PRED_GT, opnd_create_instr(skip_to_call)));

    // cur_index++
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_2),
                                  OPND_CREATE_IMMEDIATE_INT(sizeof(bb_cache_message_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_1), opnd_create_reg(reg_2)));
#    else
    // bb_cache[cur_index]->bb_shadow init
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_2),
                                  OPND_CREATE_SHADOWPRT(bb_msg->bb_shadow)));
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_1, offsetof(bb_cache_message_t, bb_shadow)),
                opnd_create_reg(reg_2)));

    // get bb_cache[cur_index]->index
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_2),
                              OPND_CREATE_MEM64(reg_1, 0)));
    // bb_cache[cur_index]->index == 1 jump to clean call
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_2), OPND_CREATE_INT32(1)));
    MINSERT(
        ilist, where,
        XINST_CREATE_jump_cond(drcontext, DR_PRED_Z, opnd_create_instr(skip_to_call)));
    // bb_cache[cur_index]->index == BB_CACHE_MESSAGE_MAX_NUM jump to clean call
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_2),
                             OPND_CREATE_INT32(BB_CACHE_MESSAGE_MAX_NUM)));
    MINSERT(
        ilist, where,
        XINST_CREATE_jump_cond(drcontext, DR_PRED_Z, opnd_create_instr(skip_to_call)));
    // inner_mem_ref_cache[cur_index]->index + bb_msg->mem_ref_num >
    // INNER_MEM_REF_CACHE_MAX jump to clean call
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg3,
                           tls_offs3 + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_3),
                              OPND_CREATE_MEM64(reg_mem_ref_ptr, 0)));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_3),
                             OPND_CREATE_INT32(bb_msg->mem_ref_num)));
    MINSERT(ilist, where,
            XINST_CREATE_cmp(drcontext, opnd_create_reg(reg_3),
                             OPND_CREATE_INT32(INNER_MEM_REF_CACHE_MAX)));
    MINSERT(
        ilist, where,
        XINST_CREATE_jump_cond(drcontext, DR_PRED_NS, opnd_create_instr(skip_to_call)));
    // cur_index++
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_1),
                             OPND_CREATE_INT32(sizeof(bb_cache_message_t))));
#    endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg2,
                            tls_offs2 + INSTRACE_TLS_OFFS_BUF_PTR, reg_1);
#    ifdef ARM64_CCTLIB
    // skip clean call
    MINSERT(ilist, where,
            INSTR_CREATE_cbnz(drcontext, opnd_create_instr(skip_clean_call),
                              opnd_create_reg(reg_2)));
#    else
    // skip clean call
    MINSERT(ilist, where,
            XINST_CREATE_jump(drcontext, opnd_create_instr(skip_clean_call)));
#    endif
    MINSERT(ilist, where, skip_to_call);
    dr_insert_clean_call(drcontext, ilist, where,
                         (void *)per_thread_update_cct_tree_memory_cache, false, 0);
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg3,
                           tls_offs3 + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    MINSERT(ilist, where, skip_clean_call);
    if (instr_state_contain(instrument_msg->state, INSTR_STATE_CLIENT_INTEREST)) {
        for (int i = 0; i < instr_num_srcs(where); i++) {
            if (opnd_is_memory_reference(instr_get_src(where, i))) {
                instrument_memory_cache_every_mem_access(drcontext, ilist, where, 0,
                                                        instr_get_src(where, i),
                                                        reg_mem_ref_ptr, reg_1, reg_2);
            }
        }
        for (int i = 0; i < instr_num_dsts(where); i++) {
            if (opnd_is_memory_reference(instr_get_dst(where, i))) {
                instrument_memory_cache_every_mem_access(drcontext, ilist, where, 0,
                                                        instr_get_dst(where, i),
                                                        reg_mem_ref_ptr, reg_1, reg_2);
            }
        }
    }
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg3,
                            tls_offs3 + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_2) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_3) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_before_every_bb_first "
                              "drreg_unreserve_register != DRREG_SUCCESS");
    }
    if (drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_memory_cache_before_every_bb_first "
                              "drreg_unreserve_aflags != DRREG_SUCCESS");
    }
}
#endif

static void
instrument_before_bb_first_instr(bb_shadow_t *cur_bb_shadow)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    pt->cct_info.cct_create_clean_call_num++;
#endif
    if (!pt->init_stack_cache) {
        dr_mcontext_t mcontext = {
            sizeof(mcontext),
            DR_MC_ALL,
        };
        dr_get_mcontext(drcontext, &mcontext);
        pt->stack_base = (void *)(ptr_int_t)reg_get_value(DR_STACK_REG, &mcontext);
        // DRCCTLIB_PRINTF("pt %d stack_base %p stack size %p stack_end %p", pt->id,
        //                 pt->stack_base, (ptr_int_t)pt->stack_size,
        //                 (ptr_int_t)pt->stack_base - (ptr_int_t)pt->stack_size);
        pt->init_stack_cache = true;
    }
    IF_DRCCTLIB_DEBUG(dr_fprintf(pt->log_file_bb, "+%d/%d/%d+|%d(Ox%p)/",
                                 cur_bb_shadow->key, cur_bb_shadow->slot_num,
                                 cur_bb_shadow->end_ins_state, pt->cur_bb_node->key,
                                 pt->cur_bb_node);)

    cct_bb_node_t *new_caller_bb_node = NULL;
    if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_THREAD_ROOT_VIRTUAL)) {
        new_caller_bb_node = pt->root_bb_node;
    } else if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_CALL_DIRECT) ||
               instr_state_contain(pt->pre_instr_state, INSTR_STATE_CALL_IN_DIRECT)) {
        new_caller_bb_node = pt->cur_bb_node;
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
        pt->cct_info.call_num++;
        pt->cct_info.cur_tree_high++;
#endif
    } else if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_RETURN)) {
        if (bb_node_parent_bb(pt->cur_bb_node) == pt->root_bb_node) {
            new_caller_bb_node = bb_node_parent_bb(pt->cur_bb_node);
        } else {
            new_caller_bb_node = bb_node_parent_bb(bb_node_parent_bb(pt->cur_bb_node));
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
            pt->cct_info.cur_tree_high--;
#endif
        }
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
        pt->cct_info.return_num++;
#endif
    } else {
        new_caller_bb_node = bb_node_parent_bb(pt->cur_bb_node);
    }

#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    pt->cct_info.ins_num += cur_bb_shadow->slot_num;
    pt->cct_info.bb_node_num++;
    if (pt->cct_info.tree_high < pt->cct_info.cur_tree_high) {
        pt->cct_info.tree_high = pt->cct_info.cur_tree_high;
    }
#endif

#ifdef IN_PROCESS_SPEEDUP
    int speedup_cache_index = pt->speedup_cache_index;
    if (speedup_cache_index >= 0 &&
        cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index] != NULL) {
        if (bb_node_parent_bb(
                cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index]) ==
            new_caller_bb_node) {
            pt->cur_bb_node =
                cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index];
#    ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
            pt->cct_info.splay_tree_search_num++;
#    endif
            pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
            pt->pre_instr_state = cur_bb_shadow->end_ins_state;
            IF_DRCCTLIB_DEBUG(dr_fprintf(pt->log_file_bb, "%d(Ox%p)/%d(Ox%p)|\n",
                                         pt->cur_bb_node->key, pt->cur_bb_node,
                                         new_caller_bb_node->key, new_caller_bb_node);)
            if (global_client_cb.func_insert_bb_start != NULL) {
                (*global_client_cb.func_insert_bb_start)(
                    drcontext, cur_bb_shadow->slot_num, cur_bb_shadow->mem_ref_num);
            }
            return;
        }
    }
#endif
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    int64_t o_num = 0;
    splay_node_t *new_root = splay_tree_update_test(
        new_caller_bb_node->callee_splay_tree_root, (splay_node_key_t)cur_bb_shadow->key,
        pt->dummy_splay_node, pt->next_splay_node, &o_num);
    pt->cct_info.splay_tree_search_num += o_num;
#else
    splay_node_t *new_root = splay_tree_update(new_caller_bb_node->callee_splay_tree_root,
                                               (splay_node_key_t)cur_bb_shadow->key,
                                               pt->dummy_splay_node, pt->next_splay_node);
#endif
    if (new_root->payload == NULL) {
        new_root->payload =
            (void *)bb_node_create(pt->bb_node_cache, cur_bb_shadow->key,
                                   new_caller_bb_node, cur_bb_shadow->slot_num);
        pt->next_splay_node = pt->splay_node_cache->get_next_object();
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
        pt->cct_info.real_node_num++;
        new_caller_bb_node->callee_tree_size++;
#endif
    }
    new_caller_bb_node->callee_splay_tree_root = new_root;
    pt->cur_bb_node = (cct_bb_node_t *)(new_root->payload);
    pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
    pt->pre_instr_state = cur_bb_shadow->end_ins_state;
#ifdef IN_PROCESS_SPEEDUP
    if (speedup_cache_index >= 0) {
        cur_bb_shadow->last_same_key_bb_pt_list[speedup_cache_index] = pt->cur_bb_node;
    }
#endif
    IF_DRCCTLIB_DEBUG(dr_fprintf(pt->log_file_bb, "%d(Ox%p)/%d(Ox%p)|\n",
                                 pt->cur_bb_node->key, pt->cur_bb_node,
                                 new_caller_bb_node->key, new_caller_bb_node);)
    if (global_client_cb.func_insert_bb_start != NULL) {
        (*global_client_cb.func_insert_bb_start)(drcontext, cur_bb_shadow->slot_num,
                                                 cur_bb_shadow->mem_ref_num);
    }
}

static inline void
instrument_before_every_instr_meta_instr(void *drcontext,
                                         instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    slot_t slot = instrument_msg->slot;
    state_t state_flag = instrument_msg->state;

#ifdef ARM_CCTLIB
    reg_id_t reg_store_imm;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_store_imm) !=
        DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                              "drreg_reserve_register != DRREG_SUCCESS");
    }
    opnd_t opnd_reg_store_imm = opnd_create_reg(reg_store_imm);
#endif
    reg_id_t reg_tls;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_tls) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                              "drreg_reserve_register != DRREG_SUCCESS");
    }
    drmgr_insert_read_tls_field(drcontext, tls_idx, bb, instr, reg_tls);

    opnd_t opnd_mem_pis =
        OPND_CREATE_PT_CUR_STATE(reg_tls, offsetof(per_thread_t, cur_state));
    opnd_t opnd_imm_pis = OPND_CREATE_STATE(state_flag);
    // pt->cur_state = state_flag;
#ifdef ARM_CCTLIB
    MINSERT(bb, instr,
            XINST_CREATE_load_int(drcontext, opnd_reg_store_imm, opnd_imm_pis));
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_pis, opnd_reg_store_imm));
#else
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_pis, opnd_imm_pis));
#endif

    opnd_t opnd_mem_cs =
        OPND_CREATE_PT_CUR_SLOT(reg_tls, offsetof(per_thread_t, cur_slot));
    opnd_t opnd_imm_cs = OPND_CREATE_SLOT(slot);
    // pt->cur_slot = slot;
#ifdef ARM_CCTLIB
    MINSERT(bb, instr, XINST_CREATE_load_int(drcontext, opnd_reg_store_imm, opnd_imm_cs));
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_cs, opnd_reg_store_imm));
#else
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_cs, opnd_imm_cs));
#endif

#ifdef ARM_CCTLIB
    if (drreg_unreserve_register(drcontext, bb, instr, reg_store_imm) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                              "drreg_unreserve_register != DRREG_SUCCESS");
    }
#endif
    if (drreg_unreserve_register(drcontext, bb, instr, reg_tls) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                              "drreg_unreserve_register != DRREG_SUCCESS");
    }
}

#ifdef DRCCTLIB_DEBUG
static void
instr_exlusive_check(void *drcontext, bb_key_t bb_key,
                     instr_instrument_msg_t *instrument_msg)
{
    instr_t *instr = instrument_msg->instr;
    slot_t slot = instrument_msg->slot;
    bool is_exlusive = false;
#    ifdef ARM_CCTLIB
    if (instr_is_exclusive_load(instr)) {
        is_exlusive = true;
    }
    if (instr_is_exclusive_store(instr)) {
        is_exlusive = true;
    }
#    endif
    if (is_exlusive) {
        per_thread_t *pt =
            (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
        char code[DISASM_CACHE_SIZE];
        instr_disassemble_to_buffer(drcontext, instr, code, DISASM_CACHE_SIZE);
        dr_fprintf(pt->log_file_instr, "!%d/%d/%s\n", bb_key, slot, code);
    }
}
#endif

static void
drcctlib_event_pre_interest_bb(void *drcontext, bb_instrument_msg_t *bb_msg,
                         instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
#ifdef CCTLIB_64
    if ((global_flags & DRCCTLIB_CACHE_MODE) != 0) {
        if ((global_flags & DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR) != 0) {
            instrument_memory_cache_before_every_bb_first(drcontext, instrument_msg,
                                                            bb_msg);
        } else {
            instrument_before_every_bb_first(drcontext, instrument_msg, bb_msg);
        }
    } else {
        dr_insert_clean_call(drcontext, bb, instr,
                                (void *)instrument_before_bb_first_instr, false, 1,
                                OPND_CREATE_SHADOWPRT(bb_msg->bb_shadow));
    }
#else
    dr_insert_clean_call(drcontext, bb, instr,
                             (void *)instrument_before_bb_first_instr, false, 1,
                             OPND_CREATE_SHADOWPRT(bb_msg->bb_shadow));
#endif
    if (instrument_msg->slot == 0) {
        IF_DRCCTLIB_DEBUG(
            instr_exlusive_check(drcontext, bb_msg->bb_key, instrument_msg);)
        instr_instrument_client_cb(drcontext, instrument_msg);
    }
    instr_instrument_msg_delete(instrument_msg);
}

static void
drcctlib_event_pre_instr(void *drcontext, bb_instrument_msg_t *bb_msg,
                         instr_instrument_msg_t *instrument_msg)
{
#ifdef CCTLIB_64
    if ((global_flags & DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR) != 0) {
        if (instr_state_contain(instrument_msg->state, INSTR_STATE_CLIENT_INTEREST)) {
            instrument_memory_cache_every_memory_instr(drcontext, instrument_msg);
        }
    }
#endif
    if ((global_flags & DRCCTLIB_CACHE_EXCEPTION) != 0) {
        instrument_before_every_instr_meta_instr(drcontext, instrument_msg);
    }
    IF_DRCCTLIB_DEBUG(
        instr_exlusive_check(drcontext, bb_msg->bb_key, instrument_msg);)
    instr_instrument_client_cb(drcontext, instrument_msg);
    instr_instrument_msg_delete(instrument_msg);
}

static dr_emit_flags_t
drcctlib_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                         bool for_trace, bool translating, void *user_data)
{
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
drcctlib_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data)
{
    IF_DRCCTLIB_DEBUG(per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
                          dr_get_current_drcontext(), tls_idx);)
#ifdef ARM32_CCTLIB
    instr_t *first_nop_instr = instrlist_first_app(bb);
    instr_t *first_instr = instr_get_next_app(first_nop_instr);
#else
    instr_t *first_instr = instrlist_first_app(bb);
#endif

    slot_t interest_instr_num = 0;
    state_t end_state = 0;
    int32_t mem_ref_num = 0;
    bb_init_shadow_config(bb, &interest_instr_num, &end_state, &mem_ref_num);
    if (interest_instr_num == 0) {
        *user_data = NULL;
        return DR_EMIT_DEFAULT;
    }

    bb_key_t bb_key = 0;
    bb_shadow_t *bb_shadow;
    app_pc tag_pc = instr_get_app_pc(first_instr);
    dr_mutex_lock(bb_shadow_lock);
    void *stored_key = hashtable_lookup(&global_bb_key_table, (void *)tag_pc);
    if (stored_key != NULL) {
        bb_shadow = NULL;
        bb_key = (bb_key_t)(ptr_int_t)stored_key;
        bb_shadow = global_bb_shadow_cache->get_object_by_index(bb_key);
    } else {
        bb_shadow = global_bb_shadow_cache->get_next_object();
        bb_shadow_init_config(bb_shadow, interest_instr_num, end_state, mem_ref_num);

        bb_key = bb_shadow->key;
        hashtable_add(&global_bb_key_table, (void *)tag_pc, (void *)(ptr_int_t)bb_key);
    }
    dr_mutex_unlock(bb_shadow_lock);

    if (bb_shadow != NULL) {
        bb_shadow_create_cache(bb_shadow);
    }

    bb_instrument_msg_t *bb_msg =
        bb_instrument_msg_create((uint64_t)(void *)bb_shadow, interest_instr_num,
                                 end_state, mem_ref_num, bb_shadow);

#ifdef DRCCTLIB_DEBUG
    if (bb_shadow != NULL) {
        dr_fprintf(pt->log_file_instr, "\n\n-%d/%d/%d/%d\n", for_trace ? 1 : 0,
                   translating ? 1 : 0, bb_key, interest_instr_num);
    }
#endif
    IF_ARM_CCTLIB(bool skip = false;)
    bool interest_start = false;
    slot_t slot = 0;
    for (instr_t *instr = first_instr; instr != NULL; instr = instr_get_next_app(instr)) {
#ifdef ARM_CCTLIB
        if (!skip && (instr_is_exclusive_load(instr) || instr_is_ldstex(instr))) {
            skip = true;
        }
        if (!skip) {
#endif
            state_t state_flag = instr_get_state(instr);
            if (instr_need_instrument_check_flag(state_flag)) {
                if (bb_shadow != NULL) {
                    bb_shadow->ip_shadow[slot] = instr_get_app_pc(instr);
                    bb_shadow->state_shadow[slot] = state_flag;
                    instr_disassemble_to_buffer(drcontext, instr,
                                                bb_shadow->disasm_shadow +
                                                    slot * DISASM_CACHE_SIZE,
                                                DISASM_CACHE_SIZE);
                    IF_DRCCTLIB_DEBUG(
                        dr_fprintf(pt->log_file_instr, "+%d/%d/%s\n", bb_key, slot,
                                   bb_shadow->disasm_shadow + slot * DISASM_CACHE_SIZE);)
                }
                if (!interest_start &&
                    instr_state_contain(state_flag, INSTR_STATE_CLIENT_INTEREST)) {
                    interest_start = true;
                }
                if(slot == 0) {
#ifdef ARM32_CCTLIB
                    drcctlib_event_pre_interest_bb(drcontext, bb_msg,
                                            instr_instrument_msg_create(bb, first_nop_instr,
                                                                        false, -1,
                                                                        INSTR_STATE_BB_START_NOP));
                    drcctlib_event_pre_instr(drcontext, bb_msg,
                                        instr_instrument_msg_create(bb, instr,
                                                                    interest_start, 0,
                                                                    state_flag));
#else               
                    if (instr != first_instr) {
                        drcctlib_event_pre_interest_bb(drcontext, bb_msg,
                                         instr_instrument_msg_create(bb, first_instr,
                                                                     false, -1,
                                                                     INSTR_STATE_BB_START_NOP));
                        drcctlib_event_pre_instr(drcontext, bb_msg,
                                         instr_instrument_msg_create(bb, instr,
                                                                     interest_start, 0,
                                                                     state_flag));
                    } else {
                        drcctlib_event_pre_interest_bb(drcontext, bb_msg,
                                         instr_instrument_msg_create(bb, instr,
                                                                     interest_start, 0,
                                                                     state_flag));
                    }
#endif
                } else {
                    drcctlib_event_pre_instr(drcontext, bb_msg,
                                         instr_instrument_msg_create(bb, instr,
                                                                     interest_start, slot,
                                                                     state_flag));
                }
                slot++;
            }
#ifdef ARM_CCTLIB
        }
        if (skip && (instr_is_exclusive_store(instr) || instr_is_ldstex(instr))) {
            skip = false;
        }
#endif
    }
    bb_instrument_msg_delete(bb_msg);
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
drcctlib_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                          bool translating)
{
#ifdef ARM32_CCTLIB
    instr_t *first_instr = instrlist_first_app(bb);
    instr_t *pre_first_nop_instr = XINST_CREATE_move(
        drcontext, opnd_create_reg(DR_REG_R0), opnd_create_reg(DR_REG_R0));
    instrlist_preinsert(bb, first_instr, pre_first_nop_instr);
#endif
    return DR_EMIT_DEFAULT;
}

static void
drcctlib_event_kernel_xfer(void *drcontext, const dr_kernel_xfer_info_t *info)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (info->type == DR_XFER_SIGNAL_DELIVERY) {
        IF_CCTLIB_64_CCTLIB(refresh_per_thread_cct_tree(drcontext, pt);)
        pt->signal_raise_bb_node = pt->cur_bb_node;
        pt->signal_raise_slot = pt->cur_slot;
        pt->signal_raise_state = pt->cur_state;
        DRCCTLIB_PRINTF(
            "drcctlib_event_kernel_xfer DR_XFER_SIGNAL_DELIVERY %d(thread %d)\n",
            info->sig, pt->id);
    }
    if (info->type == DR_XFER_SIGNAL_RETURN) {
        IF_CCTLIB_64_CCTLIB(refresh_per_thread_cct_tree(drcontext, pt);)
        pt->cur_bb_node = pt->signal_raise_bb_node;
        pt->cur_slot = pt->signal_raise_slot;
        pt->cur_state = pt->signal_raise_state;
        DRCCTLIB_PRINTF(
            "drcctlib_event_kernel_xfer DR_XFER_SIGNAL_RETURN %d(thread %d)\n", info->sig,
            pt->id);
    }
}

static dr_signal_action_t
drcctlib_event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    DRCCTLIB_PRINTF("drcctlib_event_signal %d(thread %d)\n", siginfo->sig, pt->id);
    return DR_SIGNAL_DELIVER;
}

static inline void
pt_init(void *drcontext, per_thread_t *const pt, int id)
{
    pt->id = id;
    pt->bb_node_cache = new tls_memory_cache_t<cct_bb_node_t>(
        global_bb_node_cache, bb_node_cache_lock, TLS_MEM_CACHE_MIN_NUM);
    pt->splay_node_cache = new tls_memory_cache_t<splay_node_t>(
        global_splay_node_cache, splay_node_cache_lock, TLS_MEM_CACHE_MIN_NUM);
    pt->dummy_splay_node = pt->splay_node_cache->get_next_object();
    pt->next_splay_node = pt->splay_node_cache->get_next_object();
    cct_bb_node_t *root_bb_node =
        bb_node_create(pt->bb_node_cache, THREAD_ROOT_BB_SHARED_BB_KEY, NULL, 1);
    pt->root_bb_node = root_bb_node;

    pt->cur_bb_node = root_bb_node;
    pt->pre_instr_state = INSTR_STATE_THREAD_ROOT_VIRTUAL;
    pt->cur_slot = 0;
    pt->cur_state = INSTR_STATE_CLIENT_INTEREST;

    pt->cur_buf1 = dr_get_dr_segment_base(tls_seg1);

    pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
    BUF_PTR1(pt->cur_buf1, INSTRACE_TLS_OFFS_BUF_PTR) =
        &(pt->cur_bb_child_ctxt_start_idx);

    pt->signal_raise_bb_node = NULL;
    pt->signal_raise_slot = 0;
    pt->signal_raise_state = INSTR_STATE_CLIENT_INTEREST;

    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        // Set stack sizes if data-centric is needed
        struct rlimit rlim;
        if (getrlimit(RLIMIT_STACK, &rlim)) {
            DRCCTLIB_EXIT_PROCESS("Failed to getrlimit()");
        }
        if (getrlimit(RLIMIT_STACK, &rlim)) {
            DRCCTLIB_EXIT_PROCESS("Failed to getrlimit()");
        }
        pt->stack_base = (void *)(ptr_int_t)0;
        if (rlim.rlim_cur == RLIM_INFINITY) {
            pt->stack_unlimited = true;
            pt->init_stack_cache = true;
            pt->stack_size = (void *)(ptr_int_t)0;
        } else {
            pt->stack_unlimited = false;
            pt->init_stack_cache = false;
            pt->stack_size = (void *)(ptr_int_t)rlim.rlim_cur;
        }
        pt->dmem_alloc_size = 0;
        pt->dmem_alloc_ctxt_hndl = 0;
    } else {
        pt->stack_unlimited = false;
        pt->init_stack_cache = true;
        pt->stack_base = (void *)(ptr_int_t)0;
        pt->stack_size = (void *)(ptr_int_t)0;
        pt->dmem_alloc_size = 0;
        pt->dmem_alloc_ctxt_hndl = 0;
    }

#ifdef CCTLIB_64
    if ((global_flags & DRCCTLIB_CACHE_MODE) != 0) {
        pt->bb_cache = (bb_cache_message_t *)dr_global_alloc(BB_CACHE_MESSAGE_MAX_NUM *
                                                             sizeof(bb_cache_message_t));
        for (thread_aligned_num_t i = 0; i < BB_CACHE_MESSAGE_MAX_NUM; i++) {
            pt->bb_cache[i].index = i + 1;
            pt->bb_cache[i].bb_shadow = NULL;
        }
        pt->cur_buf2 = dr_get_dr_segment_base(tls_seg2);
        BUF_PTR2(pt->cur_buf2, INSTRACE_TLS_OFFS_BUF_PTR) = pt->bb_cache;
        if ((global_flags & DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR) != 0) {
            pt->inner_mem_ref_cache = (mem_ref_msg_t *)dr_global_alloc(
                INNER_MEM_REF_CACHE_MAX * sizeof(mem_ref_msg_t));
            for (thread_aligned_num_t i = 0; i < INNER_MEM_REF_CACHE_MAX; i++) {
                pt->inner_mem_ref_cache[i].index = i + 1;
            }
            pt->cur_buf3 = dr_get_dr_segment_base(tls_seg3);
            BUF_PTR3(pt->cur_buf3, INSTRACE_TLS_OFFS_BUF_PTR) = pt->inner_mem_ref_cache;
        } else {
            pt->inner_mem_ref_cache = NULL;
            pt->cur_buf3 = NULL;
        }
    }
    pt->pre_bb_shadow =
        global_bb_shadow_cache->get_object_by_index(THREAD_ROOT_BB_SHARED_BB_KEY);
    pt->bb_call_back_cache_data = NULL;
#endif
#ifdef IN_PROCESS_SPEEDUP
    pt->speedup_cache_index = pt->id > SPEEDUP_SUPPORT_THREAD_MAX_NUM ? -1 : pt->id;
#endif
#ifdef DRCCTLIB_DEBUG
#    ifdef ARM_CCTLIB
    char bb_file_name[MAXIMUM_PATH] = "arm.";
    char instr_file_name[MAXIMUM_PATH] = "arm.";
#    else
    char bb_file_name[MAXIMUM_PATH] = "x86.";
    char instr_file_name[MAXIMUM_PATH] = "x86.";
#    endif
    gethostname(bb_file_name + strlen(bb_file_name), MAXIMUM_PATH - strlen(bb_file_name));
    gethostname(instr_file_name + strlen(instr_file_name),
                MAXIMUM_PATH - strlen(instr_file_name));
    pid_t pid = getpid();

    sprintf(bb_file_name + strlen(bb_file_name), "%d.bb.thread%d.log", pid, id);
    pt->log_file_bb =
        dr_open_file(bb_file_name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(pt->log_file_bb != INVALID_FILE);

    sprintf(instr_file_name + strlen(instr_file_name), "%d.instr.thread%d.log", pid, id);
    pt->log_file_instr =
        dr_open_file(instr_file_name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(pt->log_file_instr != INVALID_FILE);
#endif

#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    pt->cct_info = { 0 };
#endif
}

static void
drcctlib_event_thread_start(void *drcontext)
{
    int id = ATOMIC_ADD_THREAD_ID_MAX(global_thread_id_max);
    id--;
    if (id > THREAD_MAX_NUM) {
        DRCCTLIB_EXIT_PROCESS(
            "Thread num > THREAD_MAX_NUM(%d), please change the value of THREAD_MAX_NUM.",
            THREAD_MAX_NUM);
    }
    // DRCCTLIB_PRINTF("thread %d start init", id);
    per_thread_t *pt = (per_thread_t *)dr_global_alloc(sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_event_thread_start pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt_init(drcontext, pt, id);
    global_pt_cache_buff[id] = pt;
    // DRCCTLIB_PRINTF("thread %d init", id);
    // dr_fprintf(global_debug_file, "thread %d init\n", id);
}

static void
drcctlib_event_thread_end(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // DRCCTLIB_PRINTF("thread %d start end", pt->id);
#ifdef CCTLIB_64
    refresh_per_thread_cct_tree(drcontext, pt);
    per_thread_end_bb_cache_refresh(drcontext, pt);
    if ((global_flags & DRCCTLIB_CACHE_MODE) != 0) {
        dr_global_free(pt->bb_cache,
                       BB_CACHE_MESSAGE_MAX_NUM * sizeof(bb_cache_message_t));
        if ((global_flags & DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR) != 0) {
            dr_global_free(pt->inner_mem_ref_cache,
                           INNER_MEM_REF_CACHE_MAX * sizeof(mem_ref_msg_t));
        }
    }
#endif
#ifdef DRCCTLIB_DEBUG
    dr_close_file(pt->log_file_bb);
    dr_close_file(pt->log_file_instr);
#endif

#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    dr_mutex_lock(global_cct_info_lock);
    DRCCTLIB_PRINTF("Thread[%d]:call:%llu/return%llu/tree_high%llu", pt->id,
                    pt->cct_info.call_num, pt->cct_info.return_num,
                    pt->cct_info.tree_high);
    global_cct_info.real_node_num += pt->cct_info.real_node_num;
    global_cct_info.bb_node_num += pt->cct_info.bb_node_num;
    global_cct_info.mem_ref_num += pt->cct_info.mem_ref_num;
    global_cct_info.ins_num += pt->cct_info.ins_num;
    global_cct_info.splay_tree_search_num += pt->cct_info.splay_tree_search_num;
    global_cct_info.cct_create_clean_call_num += pt->cct_info.cct_create_clean_call_num;
    dr_mutex_unlock(global_cct_info_lock);
#endif
    pt->bb_node_cache->free_unuse_object();
    pt->splay_node_cache->free_unuse_object();
    // DRCCTLIB_PRINTF("thread %d end", pt->id);
    // dr_fprintf(global_debug_file, "thread %d end\n", pt->id);
}

static inline int32_t
next_string_pool_idx(char *name)
{
    int32_t len = strlen(name) + 1;
    int32_t next_idx = ATOMIC_ADD_STRING_POOL_INDEX(global_string_pool_idle_idx, len);
    if (next_idx >= STRING_POOL_NODES_MAX) {
        DRCCTLIB_EXIT_PROCESS(
            "Preallocated String Pool exhausted. CCTLib couldn't fit your "
            "application in its memory. Try a smaller program.");
    }
    strncpy(global_string_pool + next_idx - len, name, len);
    return next_idx - len;
}

static void
init_shadow_memory_space(void *addr, uint32_t accessLen, data_handle_t initializer)
{
    uint64_t endAddr = (uint64_t)addr + accessLen;

    for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr;) {

        data_handle_t *status =
            global_shadow_memory->GetOrCreateShadowAddress((size_t)curAddr);
        int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)curAddr);

        for (int i = 0; (i < maxBytesInThisPage) && curAddr < endAddr; i++, curAddr++) {
            status[i] = initializer;
        }
    }
}

// static void
// capture_mmap_size(void *wrapcxt, void **user_data)
// {
//     // Remember the CCT node and the allocation size
//     void* drcontext = (void *)drwrap_get_drcontext(wrapcxt);
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         drcontext, tls_idx);
//     pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 1);
//     IF_CCTLIB_64_CCTLIB(refresh_per_thread_cct_tree(drcontext, pt);)
//     pt->dmem_alloc_ctxt_hndl =
//         pt->cur_bb_node->child_ctxt_start_idx;
// }

static void
capture_malloc_size(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    void *drcontext = (void *)drwrap_get_drcontext(wrapcxt);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 0);
    IF_CCTLIB_64_CCTLIB(refresh_per_thread_cct_tree(drcontext, pt);)
    pt->dmem_alloc_ctxt_hndl = pt->cur_bb_node->child_ctxt_start_idx;
}

static void
capture_calloc_size(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    void *drcontext = (void *)drwrap_get_drcontext(wrapcxt);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    pt->dmem_alloc_size =
        (size_t)drwrap_get_arg(wrapcxt, 0) * (size_t)drwrap_get_arg(wrapcxt, 1);
    IF_CCTLIB_64_CCTLIB(refresh_per_thread_cct_tree(drcontext, pt);)
    pt->dmem_alloc_ctxt_hndl = pt->cur_bb_node->child_ctxt_start_idx;
}

static void
capture_realloc_size(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    void *drcontext = (void *)drwrap_get_drcontext(wrapcxt);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 1);
    IF_CCTLIB_64_CCTLIB(refresh_per_thread_cct_tree(drcontext, pt);)
    pt->dmem_alloc_ctxt_hndl = pt->cur_bb_node->child_ctxt_start_idx;
}

static void
datacentric_dynamic_alloc(void *wrapcxt, void *user_data)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);

    void *ptr = drwrap_get_retval(wrapcxt);
    data_handle_t data_hndl;
    data_hndl.object_type = DYNAMIC_OBJECT;
    data_hndl.path_handle = pt->dmem_alloc_ctxt_hndl;
    init_shadow_memory_space(ptr, pt->dmem_alloc_size, data_hndl);
}

// compute static variables
#ifdef X64
#    define elf_getshdr elf64_getshdr
#    define Elf_Shdr Elf64_Shdr
#    define Elf_Sym Elf64_Sym
#    define ELF_ST_TYPE ELF64_ST_TYPE
#else
#    define elf_getshdr elf32_getshdr
#    define Elf_Shdr Elf32_Shdr
#    define Elf_Sym Elf32_Sym
#    define ELF_ST_TYPE ELF32_ST_TYPE
#endif
static void
datacentric_static_alloc(const module_data_t *info)
{
    // DRCCTLIB_PRINTF("datacentric_static_alloc %s", info->full_path);
    // dr_fprintf(global_debug_file, "datacentric_static_alloc %s \n", info->full_path);
    file_t fd = dr_open_file(info->full_path, DR_FILE_READ);
    uint64 file_size;
    if (fd == INVALID_FILE) {
        if (strcmp(info->full_path, "[vdso]") != 0) {
            DRCCTLIB_PRINTF("------ unable to open %s", info->full_path);
        }
        return;
    }
    if (!dr_file_size(fd, &file_size)) {
        DRCCTLIB_PRINTF("------ unable to get file size %s", info->full_path);
        return;
    }
    size_t map_size = file_size;
    void *map_base = dr_map_file(fd, &map_size, 0, NULL, DR_MEMPROT_READ, DR_MAP_PRIVATE);
    /* map_size can be larger than file_size */
    if (map_base == NULL || map_size < file_size) {
        DRCCTLIB_PRINTF("------ unable to map %s", info->full_path);
        return;
    }
    // DRCCTLIB_PRINTF("------ success map %s", info->full_path);
    // in memory
    Elf *elf = elf_memory((char *)map_base,
                          map_size); // Initialize 'elf' pointer to our file descriptor
    for (Elf_Scn *scn = elf_getscn(elf, 0); scn != NULL; scn = elf_nextscn(elf, scn)) {
        Elf_Shdr *shdr = elf_getshdr(scn);
        if (shdr == NULL || shdr->sh_type != SHT_SYMTAB)
            continue;
        int symbol_count = shdr->sh_size / shdr->sh_entsize;
        Elf_Sym *syms = (Elf_Sym *)(((char *)map_base) + shdr->sh_offset);
        for (int i = 0; i < symbol_count; i++) {
            if ((syms[i].st_size == 0) ||
                (ELF_ST_TYPE(syms[i].st_info) != STT_OBJECT)) { // not a variable
                continue;
            }
            data_handle_t data_hndl;
            data_hndl.object_type = STATIC_OBJECT;
            char *sym_name = elf_strptr(elf, shdr->sh_link, syms[i].st_name);
            data_hndl.sym_name = sym_name ? next_string_pool_idx(sym_name) : 0;
            // DRCCTLIB_PRINTF("STATIC_OBJECT %s %d", sym_name,
            // (uint32_t)syms[i].st_size); dr_fprintf(global_debug_file, "STATIC_OBJECT %s
            // %d \n", sym_name, (uint32_t)syms[i].st_size);
            init_shadow_memory_space((void *)((uint64_t)(info->start) + syms[i].st_value),
                                     (uint32_t)syms[i].st_size, data_hndl);
        }
    }
    dr_unmap_file(map_base, map_size);
    dr_close_file(fd);
    // DRCCTLIB_PRINTF("finish datacentric_static_alloc %s", info->full_path);
    // dr_fprintf(global_debug_file, "finish datacentric_static_alloc %s \n",
    // info->full_path);
}

static inline app_pc
moudle_get_function_entry(const module_data_t *info, const char *func_name,
                          bool check_internal_func)
{
    app_pc functionEntry;
    if (check_internal_func) {
        size_t offs;
        if (drsym_lookup_symbol(info->full_path, func_name, &offs, DRSYM_DEMANGLE) ==
            DRSYM_SUCCESS) {
            functionEntry = offs + info->start;
        } else {
            functionEntry = NULL;
        }
    } else {
        functionEntry = (app_pc)dr_get_proc_address(info->handle, func_name);
    }
    return functionEntry;
}

static inline bool
insert_func_instrument_by_drwap(const module_data_t *info, const char *func_name,
                                void (*pre_func_cb)(void *wrapcxt,
                                                    INOUT void **user_data),
                                void (*post_func_cb)(void *wrapcxt, void *user_data))
{
    app_pc func_entry = moudle_get_function_entry(info, func_name, false);
    if (func_entry != NULL) {
        return drwrap_wrap(func_entry, pre_func_cb, post_func_cb);
    } else {
        return false;
    }
}

#define FUNC_NAME_MMAP "mmap"
#define FUNC_NAME_MALLOC "malloc"
#define FUNC_NAME_CALLOC "calloc"
#define FUNC_NAME_REALLOC "realloc"
#define FUNC_NAME_FREE "free"
static void
drcctlib_event_module_load_analysis(void *drcontext, const module_data_t *info,
                                    bool loaded)
{
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        // static analysis
        datacentric_static_alloc(info);
        // dynamic analysis
        // insert_func_instrument_by_drwap(info, FUNC_NAME_MMAP, capture_mmap_size,
        //                                             datacentric_dynamic_alloc);
        insert_func_instrument_by_drwap(info, FUNC_NAME_MALLOC, capture_malloc_size,
                                        datacentric_dynamic_alloc);
        insert_func_instrument_by_drwap(info, FUNC_NAME_CALLOC, capture_calloc_size,
                                        datacentric_dynamic_alloc);
        insert_func_instrument_by_drwap(info, FUNC_NAME_REALLOC, capture_realloc_size,
                                        datacentric_dynamic_alloc);
    }
}

static void
drcctlib_event_module_unload_analysis(void *drcontext, const module_data_t *info)
{
}

static inline void
init_thread_root_shared_bb_shadow()
{
    bb_shadow_t *thread_root_shared_bb_shadow = global_bb_shadow_cache->get_next_object();
    bb_shadow_init_config(thread_root_shared_bb_shadow, 1,
                          INSTR_STATE_THREAD_ROOT_VIRTUAL, 0);
    bb_shadow_create_cache(thread_root_shared_bb_shadow);
    thread_root_shared_bb_shadow->ip_shadow[0] = 0;
    strcpy(thread_root_shared_bb_shadow->disasm_shadow, "thread root bb");
    thread_root_shared_bb_shadow->state_shadow[0] = INSTR_STATE_THREAD_ROOT_VIRTUAL;
}

static inline void
init_progress_root_ip_node()
{
    cct_ip_node_t *progress_root_ip =
        global_ip_node_buff + THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE;
#ifdef IPNODE_STORE_BNODE_IDX
    progress_root_ip->parent_bb_node_cache_index = -1;
#else
    progress_root_ip->parent_bb_node = NULL;
#endif
}

static inline void
init_global_buff()
{
    global_ip_node_buff =
        (cct_ip_node_t *)dr_raw_mem_alloc(CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t),
                                          DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (global_ip_node_buff == NULL) {
        DRCCTLIB_EXIT_PROCESS(
            "init_global_buff error: dr_raw_mem_alloc fail global_ip_node_buff");
    } else {
        init_progress_root_ip_node();
    }
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        global_string_pool =
            (char *)dr_raw_mem_alloc(STRING_POOL_NODES_MAX * sizeof(char),
                                     DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
        if (global_string_pool == NULL) {
            DRCCTLIB_EXIT_PROCESS(
                "init_global_buff error: dr_raw_mem_alloc fail global_string_pool");
        }
    }

    global_bb_node_cache = new memory_cache_t<cct_bb_node_t>(
        MEM_CACHE_PAGE1_BIT, MEM_CACHE_PAGE2_BIT, MEM_CACHE_DEBRIS_SIZE,
        bb_node_init_cache_index);
    global_splay_node_cache = new memory_cache_t<splay_node_t>(
        MEM_CACHE_PAGE1_BIT, MEM_CACHE_PAGE2_BIT, MEM_CACHE_DEBRIS_SIZE,
        splay_node_init_cache_index);
    global_bb_shadow_cache = new thread_shared_memory_cache_t<bb_shadow_t>(
        TSM_CACHE_PAGE1_BIT, TSM_CACHE_PAGE2_BIT, bb_shadow_create, bb_shadow_free_cache,
        bb_shadow_cache_lock);
    init_thread_root_shared_bb_shadow();

    global_pt_cache_buff =
        (per_thread_t **)dr_raw_mem_alloc(THREAD_MAX_NUM * sizeof(per_thread_t *),
                                          DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (global_pt_cache_buff == NULL) {
        DRCCTLIB_EXIT_PROCESS(
            "init_global_buff error: dr_raw_mem_alloc fail global_pt_cache_buff");
    }
}

static inline void
free_global_buff()
{
    dr_raw_mem_free(global_ip_node_buff, CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t));
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        dr_raw_mem_free(global_string_pool, STRING_POOL_NODES_MAX * sizeof(char));
    }

    for (int i = 0; i < THREAD_MAX_NUM; i++) {
        if (global_pt_cache_buff[i] != NULL) {
            delete global_pt_cache_buff[i]->bb_node_cache;
            delete global_pt_cache_buff[i]->splay_node_cache;
            dr_global_free(global_pt_cache_buff[i], sizeof(per_thread_t));
        }
    }
    dr_raw_mem_free(global_pt_cache_buff, THREAD_MAX_NUM * sizeof(per_thread_t *));

    delete global_bb_node_cache;
    delete global_splay_node_cache;
    delete global_bb_shadow_cache;
}

static inline void
create_global_locks()
{
    bb_shadow_lock = dr_mutex_create();
    bb_node_cache_lock = dr_mutex_create();
    splay_node_cache_lock = dr_mutex_create();
    bb_shadow_cache_lock = dr_mutex_create();
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    global_cct_info_lock = dr_mutex_create();
#endif
}

static inline void
destroy_global_locks()
{
    dr_mutex_destroy(bb_shadow_lock);
    dr_mutex_destroy(bb_node_cache_lock);
    dr_mutex_destroy(splay_node_cache_lock);
    dr_mutex_destroy(bb_shadow_cache_lock);
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    dr_mutex_destroy(global_cct_info_lock);
#endif
}

static size_t
get_peak_rss()
{
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    return (size_t)(rusage.ru_maxrss);
}

static void
print_stats()
{
    if (global_log_file != INVALID_FILE) {
        dr_fprintf(global_log_file, "\nTotalCallPaths = %" PRIu32,
                   global_ip_node_buff_idle_idx);
        // Peak resource usage
        dr_fprintf(global_log_file, "\nPeakRSS = %zu", get_peak_rss());
    }
}

static per_thread_t *
pt_get_from_gcache_by_id(int id)
{
    return global_pt_cache_buff[id];
}

static int
get_thread_id_by_root_bb(cct_bb_node_t *bb)
{
    for (int id = 0; id < global_thread_id_max; id++) {
        per_thread_t *pt = pt_get_from_gcache_by_id(id);
        if (pt->root_bb_node == bb) {
            return id;
        }
    }
    return -1;
}

static inline context_t *
ctxt_create(context_handle_t ctxt_hndl, int line_no, app_pc ip)
{
    context_t *ctxt = (context_t *)dr_global_alloc(sizeof(context_t));
    ctxt->ctxt_hndl = ctxt_hndl;
    ctxt->line_no = line_no;
    ctxt->ip = ip;
    ctxt->pre_ctxt = NULL;
    return ctxt;
}

static inline void
ctxt_free(context_t *ctxt)
{
    if (ctxt == NULL) {
        return;
    }
    ctxt_free(ctxt->pre_ctxt);
    dr_global_free(ctxt, sizeof(context_t));
}

static inline context_t *
ctxt_get_from_ctxt_hndl(context_handle_t ctxt_hndl)
{
    if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        context_t *ctxt = ctxt_create(ctxt_hndl, 0, 0);
        sprintf(ctxt->func_name, "PROCESS[%d]_ROOT_CTXT", getpid());
        sprintf(ctxt->file_path, " ");
        sprintf(ctxt->code_asm, " ");
        return ctxt;
    }
    cct_bb_node_t *bb = ctxt_hndl_parent_bb_node(ctxt_hndl);
    if (bb->key == THREAD_ROOT_BB_SHARED_BB_KEY) {
        int id = get_thread_id_by_root_bb(bb);
        if (id == -1) {
            DRCCTLIB_EXIT_PROCESS(
                "bb->key == THREAD_ROOT_BB_SHARED_BB_KEY get_thread_id_by_root_bb == -1");
        }
        context_t *ctxt = ctxt_create(ctxt_hndl, 0, 0);
        sprintf(ctxt->func_name, "THREAD[%d]_ROOT_CTXT", id);
        sprintf(ctxt->file_path, " ");
        sprintf(ctxt->code_asm, " ");
        return ctxt;
    }
    bb_shadow_t *shadow = global_bb_shadow_cache->get_object_by_index(bb->key);
    app_pc addr = shadow->ip_shadow[ctxt_hndl - bb->child_ctxt_start_idx];
    // DRCCTLIB_PRINTF("ctxt_hndl %d addr %lu bb->child_ctxt_start_idx %d
    // bb->max_slots %d", ctxt_hndl, addr, bb->child_ctxt_start_idx, bb->max_slots);
    char *code = shadow->disasm_shadow +
        (ctxt_hndl - bb->child_ctxt_start_idx) * DISASM_CACHE_SIZE;
    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAXIMUM_SYMNAME];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        context_t *ctxt = ctxt_create(ctxt_hndl, 0, addr);
        sprintf(ctxt->func_name, "badIp");
        sprintf(ctxt->file_path, " ");
        sprintf(ctxt->code_asm, "%s", code);
        return ctxt;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = MAXIMUM_SYMNAME;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEFAULT_FLAGS);

    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        context_t *ctxt;
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            ctxt = ctxt_create(ctxt_hndl, 0, addr);
        } else {
            ctxt = ctxt_create(ctxt_hndl, sym.line, addr);
        }
        sprintf(ctxt->func_name, "%s", sym.name);
        sprintf(ctxt->file_path, "%s", sym.file);
        sprintf(ctxt->code_asm, "%s", code);
        dr_free_module_data(data);
        return ctxt;
    } else {
        context_t *ctxt = ctxt_create(ctxt_hndl, 0, addr);
        sprintf(ctxt->func_name, "<noname>");
        sprintf(ctxt->file_path, "%s", sym.file);
        sprintf(ctxt->code_asm, "%s", code);
        dr_free_module_data(data);
        return ctxt;
    }
}

// void
// drcctlib_init_debug_file()
// {
// #ifdef ARM_CCTLIB
//     char debug_file_name[MAXIMUM_PATH] = "arm.";
// #else
//     char debug_file_name[MAXIMUM_PATH] = "x86.";
// #endif
//     gethostname(debug_file_name + strlen(debug_file_name),
//                 MAXIMUM_PATH - strlen(debug_file_name));
//     pid_t pid = getpid();
//     sprintf(debug_file_name + strlen(debug_file_name), "debug.%d.log", pid);
//     global_debug_file =
//         dr_open_file(debug_file_name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
//     DR_ASSERT(global_debug_file != INVALID_FILE);
//     DRCCTLIB_PRINTF("global_debug_file(%s) create success!", debug_file_name);
// }

bool
drcctlib_internal_init(char flag)
{
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&init_count, 1);
    if (count > 1)
        return true;
    // drcctlib_init_debug_file();
    global_flags = flag;
#ifndef CCTLIB_64
    if ((global_flags & DRCCTLIB_CACHE_MODE) != 0) {
        DRCCTLIB_PRINTF("Only 64-bit support DRCCTLIB_CACHE_MODE");
        global_flags -= DRCCTLIB_CACHE_MODE;
    }
    if ((global_flags & DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR) != 0) {
        DRCCTLIB_PRINTF("Only 64-bit support DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR");
        global_flags -= DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR;
    }
#endif
    if (!drmgr_init()) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drmgr");
        return false;
    }
    if (!drutil_init()) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drutil");
        return false;
    }
    if (!drwrap_init() || !drwrap_set_global_flags(DRWRAP_SAFE_READ_ARGS)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drwrap");
        return false;
    }
    if (drsym_init(0) != DRSYM_SUCCESS) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drsym");
        return false;
    }
    drreg_options_t ops = { sizeof(ops), 5, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drreg");
        return false;
    }

    disassemble_set_syntax(DR_DISASM_DRCCTLIB);

    drmgr_register_kernel_xfer_event(drcctlib_event_kernel_xfer);
    drmgr_register_signal_event(drcctlib_event_signal);
    if (!drmgr_register_bb_app2app_event(drcctlib_event_bb_app2app, NULL)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib fail to register bb app2app event");
        return false;
    }
    if (!drmgr_register_bb_instrumentation_event(drcctlib_event_bb_analysis,
                                                 drcctlib_event_bb_insert, NULL)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib fail to register bb instrumentation event");
        return false;
    }
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        if (elf_version(EV_CURRENT) == EV_NONE) {
            DRCCTLIB_PRINTF("INIT DATA CENTRIC FAIL: Elf Library is out of date!");
            global_flags -= DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE;
        } else {
            global_shadow_memory = new ConcurrentShadowMemory<data_handle_t>();
        }
    }

    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        drwrap_set_global_flags(DRWRAP_SAFE_READ_RETADDR);
        drwrap_set_global_flags(DRWRAP_SAFE_READ_ARGS);
        drmgr_register_module_load_event(drcctlib_event_module_load_analysis);
        drmgr_register_module_unload_event(drcctlib_event_module_unload_analysis);
    }

    create_global_locks();
    init_global_buff();
    hashtable_init(&global_bb_key_table, BB_TABLE_HASH_BITS, HASH_INTPTR, false);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1)
        return false;
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri), "drcctlib-thread_init",
                                         NULL, NULL, DRCCTLIB_THREAD_EVENT_PRI };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri), "drcctlib-thread-exit",
                                         NULL, NULL, DRCCTLIB_THREAD_EVENT_PRI };
    if (!drmgr_register_thread_init_event_ex(drcctlib_event_thread_start,
                                             &thread_init_pri))
        return false;
    if (!drmgr_register_thread_exit_event_ex(drcctlib_event_thread_end, &thread_exit_pri))
        return false;

    if (!dr_raw_tls_calloc(&tls_seg1, &tls_offs1, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_calloc1 fail");
        return false;
    }
    if (!dr_raw_tls_calloc(&tls_seg2, &tls_offs2, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_calloc2 fail");
        return false;
    }
    if (!dr_raw_tls_calloc(&tls_seg3, &tls_offs3, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_calloc4 fail");
        return false;
    }

    return true;
}

DR_EXPORT
void
drcctlib_exit(void)
{
    // DRCCTLIB_PRINTF("----drcctlib_exit start");
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&init_count, -1);
    if (count != 0)
        return;
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    DRCCTLIB_PRINTF("+++++++++++++++global_ins_num %llu "
                    "global_bb_node_num %llu "
                    "global_real_node_num %llu "
                    "global_search_num %llu "
                    "global_mem_ref_num %llu "
                    "global_cct_create_clean_call_num %llu",
                    global_cct_info.ins_num, global_cct_info.bb_node_num,
                    global_cct_info.real_node_num, global_cct_info.splay_tree_search_num,
                    global_cct_info.mem_ref_num,
                    global_cct_info.cct_create_clean_call_num);
#endif

    if (!dr_raw_tls_cfree(tls_offs1, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_cfree1 fail");
    }
    if (!dr_raw_tls_cfree(tls_offs2, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_cfree2 fail");
    }
    if (!dr_raw_tls_cfree(tls_offs3, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_cfree4 fail");
    }
    print_stats();
    if (!drmgr_unregister_bb_app2app_event(drcctlib_event_bb_app2app) ||
        !drmgr_unregister_bb_instrumentation_event(drcctlib_event_bb_analysis) ||
        // !drmgr_unregister_bb_insertion_event(drcctlib_event_bb_insert) ||
        !drmgr_unregister_kernel_xfer_event(drcctlib_event_kernel_xfer) ||
        !drmgr_unregister_signal_event(drcctlib_event_signal) ||
        !drmgr_unregister_thread_init_event(drcctlib_event_thread_start) ||
        !drmgr_unregister_thread_exit_event(drcctlib_event_thread_end) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("failed to unregister in drcctlib_exit");
    }
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        drmgr_unregister_module_load_event(drcctlib_event_module_load_analysis);
        drmgr_unregister_module_unload_event(drcctlib_event_module_unload_analysis);
    }
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        delete global_shadow_memory;
    }

    hashtable_delete(&global_bb_key_table);
    // free cct_ip_node and cct_bb_node
    free_global_buff();
    destroy_global_locks();

    drmgr_exit();
    drutil_exit();
    drwrap_exit();
    if (drsym_exit() != DRSYM_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drsym");
    }
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }

    // dr_close_file(global_debug_file);
    if (global_log_file != INVALID_FILE) {
        dr_close_file(global_log_file);
    }
}

void
drcctlib_register_instr_filter(bool (*filter)(instr_t *))
{
    global_instr_filter = filter;
}

void
drcctlib_register_client_cb(void (*func_instr_analysis)(void *, instr_instrument_msg_t *),
                            void (*func_insert_bb_start)(void *, int32_t, int32_t),
                            void (*func_insert_bb_end)(void *, context_handle_t, int32_t,
                                                       int32_t, mem_ref_msg_t *, void **))
{
    global_client_cb.func_instr_analysis = func_instr_analysis;
    global_client_cb.func_insert_bb_start = func_insert_bb_start;
    global_client_cb.func_insert_bb_end = func_insert_bb_end;
}

void
drcctlib_config_log_file(file_t file)
{
    global_log_file = file;
}

DR_EXPORT
bool
drcctlib_init_ex(bool (*filter)(instr_t *), file_t file,
                 void (*func1)(void *, instr_instrument_msg_t *),
                 void (*func2)(void *, int32_t, int32_t),
                 void (*func3)(void *, context_handle_t, int32_t, int32_t,
                               mem_ref_msg_t *, void **),
                 char flag)
{
    if (!drcctlib_internal_init(flag)) {
        return false;
    }
    drcctlib_register_instr_filter(filter);
    drcctlib_config_log_file(file);
    drcctlib_register_client_cb(func1, func2, func3);
    return true;
}

DR_EXPORT
void
drcctlib_init(bool (*filter)(instr_t *), file_t file,
                 void (*func1)(void *, instr_instrument_msg_t *),
                 bool do_data_centric)
{
    char flag = DRCCTLIB_DEFAULT;
    if(do_data_centric) {
        flag = DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE;
    }
    drcctlib_init_ex(filter, file, func1, NULL, NULL, flag);
}

DR_EXPORT
int
drcctlib_get_thread_id()
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    return (int)(pt->id);
}

DR_EXPORT
void
drcctlib_get_context_handle_in_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                   int32_t slot, reg_id_t store_reg, reg_id_t addr_reg)
{
#ifdef CCTLIB_64
    if ((global_flags & DRCCTLIB_CACHE_MODE) != 0) {
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        refresh_per_thread_cct_tree(drcontext, pt);
    }
#endif
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg1,
                           tls_offs1 + INSTRACE_TLS_OFFS_BUF_PTR, addr_reg);
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(store_reg),
                              OPND_CREATE_CTXT_HNDL_MEM(addr_reg, 0)));
#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(addr_reg),
                                  OPND_CREATE_SLOT(slot)));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(store_reg),
                             opnd_create_reg(addr_reg)));
#else
    MINSERT(
        ilist, where,
        XINST_CREATE_add(drcontext, opnd_create_reg(store_reg), OPND_CREATE_SLOT(slot)));
#endif
}

DR_EXPORT
context_handle_t
drcctlib_get_context_handle(void *drcontext, int32_t slot){
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (slot >= pt->cur_bb_node->max_slots) {
        DRCCTLIB_EXIT_PROCESS("slot > cur_bb_node->max_slots");
    }
    return pt->cur_bb_node->child_ctxt_start_idx + slot;
}

DR_EXPORT
context_handle_t
drcctlib_get_global_context_handle_num()
{
    return global_ip_node_buff_idle_idx;
}

DR_EXPORT
bool
drcctlib_ctxt_hndl_is_valid(context_handle_t ctxt_hndl)
{
    return ctxt_hndl_is_valid(ctxt_hndl);
}

DR_EXPORT
context_t *
drcctlib_get_full_cct(context_handle_t ctxt_hndl, int max_depth)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_full_cct !ctxt_hndl_is_valid");
    }
    bool get_all = false;
    if (max_depth == 0) {
        get_all = true;
    }
    context_t *start = NULL;
    context_t *list_pre_ptr = NULL;
    int depth = 0;
    while (true) {
        context_t *pre_ctxt = ctxt_get_from_ctxt_hndl(ctxt_hndl);
        if (start == NULL) {
            start = pre_ctxt;
            list_pre_ptr = pre_ctxt;
        } else {
            list_pre_ptr->pre_ctxt = pre_ctxt;
            list_pre_ptr = pre_ctxt;
        }

        if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
            break;
        }
        if (!get_all && depth >= max_depth) {
            context_t *ctxt = ctxt_create(ctxt_hndl, 0, 0);
            sprintf(ctxt->func_name,
                    "Truncated call path (due to client deep call chain)");
            sprintf(ctxt->file_path, " ");
            sprintf(ctxt->code_asm, " ");
            list_pre_ptr->pre_ctxt = ctxt;
            list_pre_ptr = ctxt;
            break;
        }
        if (!get_all && depth >= MAX_CCT_PRINT_DEPTH) {
            context_t *ctxt = ctxt_create(ctxt_hndl, 0, 0);
            sprintf(ctxt->func_name,
                    "Truncated call path (due to drcctlib deep call chain)");
            sprintf(ctxt->file_path, " ");
            sprintf(ctxt->code_asm, " ");
            list_pre_ptr->pre_ctxt = ctxt;
            list_pre_ptr = ctxt;
            break;
        }

        ctxt_hndl = bb_node_caller_ctxt_hndl(ctxt_hndl_parent_bb_node(ctxt_hndl));
        depth++;
    }
    return start;
}

DR_EXPORT
void
drcctlib_free_full_cct(context_t * contxt_list)
{
    ctxt_free(contxt_list);
}

DR_EXPORT
void
drcctlib_print_ctxt_hndl_msg(file_t file, context_handle_t ctxt_hndl, bool print_asm,
                             bool print_file_path)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_print_ctxt_hndl_msg: !ctxt_hndl_is_valid");
    }

    if (file == INVALID_FILE) {
        file = global_log_file;
    }
    context_t *ctxt = ctxt_get_from_ctxt_hndl(ctxt_hndl);
    if (print_asm && print_file_path) {
        dr_fprintf(file, "%s(%d):\"(%p)%s\"[%s]\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip, ctxt->code_asm, ctxt->file_path);
    } else if (print_asm) {
        dr_fprintf(file, "%s(%d):\"(%p)%s\"\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip, ctxt->code_asm);
    } else if (print_file_path) {
        dr_fprintf(file, "%s(%d):\"(%p)\"[%s]\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip, ctxt->file_path);
    } else {
        dr_fprintf(file, "%s(%d):\"(%p)\"\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip);
    }
    ctxt_free(ctxt);
}

DR_EXPORT
void
drcctlib_print_full_cct(file_t file, context_handle_t ctxt_hndl, bool print_asm,
                        bool print_file_path, int max_depth)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_print_full_cct: !ctxt_hndl_is_valid");
    }
    bool print_all = false;
    if (max_depth == 0) {
        print_all = true;
    }
    if (file == INVALID_FILE) {
        file = global_log_file;
    }
    int depth = 0;
    while (true) {
        drcctlib_print_ctxt_hndl_msg(file, ctxt_hndl, print_asm, print_file_path);
        if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
            break;
        }
        if (!print_all && depth >= max_depth) {
            dr_fprintf(file, "Truncated call path (due to client deep call chain)\n");
            break;
        }
        if (!print_all && depth >= MAX_CCT_PRINT_DEPTH) {
            dr_fprintf(file, "Truncated call path (due to deep call chain)\n");
            break;
        }

        ctxt_hndl = bb_node_caller_ctxt_hndl(ctxt_hndl_parent_bb_node(ctxt_hndl));
        depth++;
    }
}

DR_EXPORT
app_pc
drcctlib_get_ctxt_hndl_pc(context_handle_t ctxt_hndl)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_ctxt_hndl_pc: !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        DRCCTLIB_PRINTF(
            "drcctlib_get_ctxt_hndl_pc: THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE");
        return 0;
    }
    cct_bb_node_t *bb_node = ctxt_hndl_parent_bb_node(ctxt_hndl);
    if (bb_node->key == THREAD_ROOT_BB_SHARED_BB_KEY) {
        DRCCTLIB_PRINTF("drcctlib_get_ctxt_hndl_pc: THREAD_ROOT_BB_SHARED_BB_KEY");
        return 0;
    }
    slot_t slot = ctxt_hndl - bb_node->child_ctxt_start_idx;
    bb_shadow_t *bb_shadow = global_bb_shadow_cache->get_object_by_index(bb_node->key);
    app_pc pc = bb_shadow->ip_shadow[slot];
    return pc;
}

DR_EXPORT
int32_t
drcctlib_get_ctxt_hndl_state(context_handle_t ctxt_hndl)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_ctxt_hndl_state: !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        DRCCTLIB_PRINTF(
            "drcctlib_get_ctxt_hndl_state: THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE");
        return 0;
    }
    cct_bb_node_t *bb_node = ctxt_hndl_parent_bb_node(ctxt_hndl);
    if (bb_node->key == THREAD_ROOT_BB_SHARED_BB_KEY) {
        DRCCTLIB_PRINTF("drcctlib_get_ctxt_hndl_state: THREAD_ROOT_BB_SHARED_BB_KEY");
        return 0;
    }
    slot_t slot = ctxt_hndl - bb_node->child_ctxt_start_idx;
    bb_shadow_t *bb_shadow = global_bb_shadow_cache->get_object_by_index(bb_node->key);
    int32_t state = bb_shadow->state_shadow[slot];
    return state;
}

DR_EXPORT
context_handle_t
drcctlib_get_caller_handle(context_handle_t ctxt_hndl)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_caller_handle !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        DRCCTLIB_PRINTF("drcctlib_get_caller_handle TO INVALID_CTXT_HNDL");
        return INVALID_CTXT_HNDL;
    }
    return bb_node_caller_ctxt_hndl(ctxt_hndl_parent_bb_node(ctxt_hndl));
}

DR_EXPORT
bool
drcctlib_have_same_caller_prefix(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl1) || !ctxt_hndl_is_valid(ctxt_hndl1)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_have_same_caller_prefix !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl1 == ctxt_hndl2) {
        return true;
    }
    if (ctxt_hndl1 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE ||
        ctxt_hndl2 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        return false;
    }
    context_handle_t t1 = bb_node_caller_ctxt_hndl(ctxt_hndl_parent_bb_node(ctxt_hndl1));
    context_handle_t t2 = bb_node_caller_ctxt_hndl(ctxt_hndl_parent_bb_node(ctxt_hndl2));
    return t1 == t2;
}

DR_EXPORT
bool
drcctlib_have_same_call_path(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2)
{
    if (ctxt_hndl1 == ctxt_hndl2) {
        return true;
    }
    if (ctxt_hndl1 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE ||
        ctxt_hndl2 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        return false;
    }
    context_handle_t p1 = bb_node_caller_ctxt_hndl(ctxt_hndl_parent_bb_node(ctxt_hndl1));
    context_handle_t p2 = bb_node_caller_ctxt_hndl(ctxt_hndl_parent_bb_node(ctxt_hndl2));
    if (drcctlib_have_same_call_path(p1, p2)) {
        app_pc pc1 = drcctlib_get_ctxt_hndl_pc(ctxt_hndl1);
        app_pc pc2 = drcctlib_get_ctxt_hndl_pc(ctxt_hndl2);
        if (pc1 == pc2) {
            return true;
        }
    }
    return false;
}

DR_EXPORT
bool
drcctlib_have_same_source_line(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl1) || !ctxt_hndl_is_valid(ctxt_hndl2)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_full_cct !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl1 < VALID_START_CTXT_HNDL || ctxt_hndl2 < VALID_START_CTXT_HNDL) {
        DRCCTLIB_PRINTF("drcctlib_have_same_source_line warning ctxt_hndl < VALID_START_CTXT_HNDL ");
        return false;
    }
    if (ctxt_hndl1 == ctxt_hndl2) {
        return true;
    }
    context_t *ctxt1 = ctxt_get_from_ctxt_hndl(ctxt_hndl1);
    context_t *ctxt2 = ctxt_get_from_ctxt_hndl(ctxt_hndl2);
    int line_no1 = ctxt1->line_no;
    int line_no2 = ctxt2->line_no;
    ctxt_free(ctxt1);
    ctxt_free(ctxt2);
    return line_no1 == line_no2;
}

/* ======drcctlib data centric api====== */
DR_EXPORT
data_handle_t
drcctlib_get_data_hndl_ignore_stack_data(void *drcontext, void *address)
{
    data_handle_t data_hndl;
    data_hndl.object_type = UNKNOWN_OBJECT;
    data_hndl.path_handle = 0;
    data_handle_t *ptr =
        global_shadow_memory->GetShadowAddress((size_t)(uint64_t)address);
    if (ptr != NULL) {
        data_hndl = *ptr;
    }
    return data_hndl;
}

DR_EXPORT
data_handle_t
drcctlib_get_data_hndl_runtime(void *drcontext, void *address)
{
    data_handle_t data_hndl;
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (!pt->stack_unlimited &&
        address > (void *)((ptr_int_t)pt->stack_base - (ptr_int_t)pt->stack_size) &&
        address < pt->stack_base) {
        data_hndl.object_type = STACK_OBJECT;
        return data_hndl;
    }
    data_hndl.object_type = UNKNOWN_OBJECT;
    data_handle_t *ptr =
        global_shadow_memory->GetShadowAddress((size_t)(uint64_t)address);
    if (ptr != NULL) {
        data_hndl = *ptr;
    }
    return data_hndl;
}

DR_EXPORT
data_handle_t
drcctlib_get_data_hndl(void *drcontext, void *address)
{
    return drcctlib_get_data_hndl_runtime(drcontext, address);
}

DR_EXPORT
char *
drcctlib_get_str_from_strpool(int index)
{
    return global_string_pool + index;
}

/* ======drcctlib ext api====== */
DR_EXPORT
thread_stack_config_t
drcctlib_get_thread_stack_config(void *drcontext)
{
    thread_stack_config_t stack_config;
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    stack_config.thread_id = pt->id;
    stack_config.stack_base = pt->stack_base;
    stack_config.stack_end =
        (void *)((ptr_int_t)pt->stack_base - (ptr_int_t)pt->stack_size);
    return stack_config;
}

/* ======drcctlib priv share api====== */

int
drcctlib_priv_share_get_thread_id()
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    return (int)(pt->id);
}

splay_node_t *
drcctlib_priv_share_get_ip_node_callee_splay_tree_root(cct_ip_node_t *ip)
{
    cct_bb_node_t *parent_bb_node = ip_node_parent_bb_node(ip);
    if (parent_bb_node == NULL || ip != bb_node_end_ip(parent_bb_node)) {
        return NULL;
    }
    return parent_bb_node->callee_splay_tree_root;
}

cct_ip_node_t *
drcctlib_priv_share_trans_ctxt_hndl_to_ip_node(context_handle_t ctxt_hndl)
{
    return global_ip_node_buff + ctxt_hndl;
}

cct_bb_node_t *
drcctlib_priv_share_get_thread_root_bb_node(int id)
{
    return global_pt_cache_buff[id]->root_bb_node;
}

app_pc
drcctlib_priv_share_get_ip_from_ctxt(context_handle_t ctxt)
{
    cct_bb_node_t *bb = ctxt_hndl_parent_bb_node(ctxt);
    bb_shadow_t *bb_shadow = global_bb_shadow_cache->get_object_by_index(bb->key);
    slot_t slot = ctxt - bb->child_ctxt_start_idx;
    return bb_shadow->ip_shadow[slot];
}

app_pc
drcctlib_priv_share_get_ip_from_ip_node(cct_ip_node_t *ip_node)
{
    context_handle_t ctxt = ip_node_to_ctxt_hndl(ip_node);
    cct_bb_node_t *bb = ip_node_parent_bb_node(ip_node);
    bb_shadow_t *bb_shadow = global_bb_shadow_cache->get_object_by_index(bb->key);
    slot_t slot = ctxt - bb->child_ctxt_start_idx;
    return bb_shadow->ip_shadow[slot];
}

void
drcctlib_priv_share_get_full_calling_ip_vector(context_handle_t ctxt_hndl,
                                               std::vector<app_pc> &list)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("get_full_calling_ip_vector !ctxt_hndl_is_valid");
    }
    context_handle_t cur_ctxt = ctxt_hndl;
    while (true) {
        cct_bb_node_t *parent_bb = ctxt_hndl_parent_bb_node(cur_ctxt);
        if (parent_bb->key == THREAD_ROOT_BB_SHARED_BB_KEY) {
            break;
        }
        slot_t slot = cur_ctxt - parent_bb->child_ctxt_start_idx;
        bb_shadow_t *shadow = global_bb_shadow_cache->get_object_by_index(parent_bb->key);
        app_pc ip = shadow->ip_shadow[slot];
        list.push_back(ip);

        cur_ctxt = bb_node_caller_ctxt_hndl(parent_bb);
    }
}