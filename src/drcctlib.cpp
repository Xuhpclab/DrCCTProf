#include <fcntl.h>
// #include <gelf.h>
#include <inttypes.h>
// #include <libelf.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <sys/resource.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"
#include "hashtable.h"

#include "drcctlib.h"
#include "splay_tree.h"
#include "shadow_memory.h"
#include "memory_cache.h"

#ifdef ARM32_CCTLIB
#    define DR_DISASM_DRCCTLIB DR_DISASM_ARM
#elif defined(ARM64_CCTLIB)
#    define DR_DISASM_DRCCTLIB DR_DISASM_DR	
#else
#    define DR_DISASM_DRCCTLIB DR_DISASM_INTEL
#endif

#define MAX_CCT_PRINT_DEPTH 15

#define bb_key_t int32_t
#define slot_t int32_t
#define state_t int32_t

#define BB_KEY_MAX CONTEXT_HANDLE_MAX

#define INVALID_CONTEXT_HANDLE -1
#define THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE 0
#define CONTEXT_HANDLE_START 1

#define THREAD_ROOT_SHARDED_CALLEE_INDEX 0

#define ATOM_ADD_NEXT_BB_KEY(origin) dr_atomic_add32_return_sum(&origin, 1)
#define ATOM_ADD_CTXT_HNDL(origin, val) dr_atomic_add32_return_sum(&origin, val)
#define ATOM_ADD_THREAD_ID_MAX(origin) dr_atomic_add32_return_sum(&origin, 1)

#ifdef INTEL_CCTLIB
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT32
#    define OPND_CREATE_SLOT OPND_CREATE_INT32
#    define OPND_CREATE_INSTR_STATE_FLAG OPND_CREATE_INT32
#elif defined(ARM_CCTLIB)
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT
#    define OPND_CREATE_SLOT OPND_CREATE_INT
#    define OPND_CREATE_INSTR_STATE_FLAG OPND_CREATE_INT
#endif
#define OPND_CREATE_PT_CUR_SLOT OPND_CREATE_MEM32
#define OPND_CREATE_PT_PRE_INSTR_STATE OPND_CREATE_MEM32
#ifdef CCTLIB_32
#    define OPND_CREATE_PT_CUR_CTXT_HNDLE OPND_CREATE_MEM32
#    define OPND_CREATE_PT_CUR_BB_CHILD_CTXT_START_IDX OPND_CREATE_MEM32
#else
#    define OPND_CREATE_PT_CUR_CTXT_HNDLE OPND_CREATE_MEM64
#    define OPND_CREATE_PT_CUR_BB_CHILD_CTXT_START_IDX OPND_CREATE_MEM64
#endif

#define THREAD_ROOT_BB_SHARED_BB_KEY 0
#define UNINTERESTED_BB_SHARED_BB_KEY 1
#define UNSHARED_BB_KEY_START 2

#define DRCCTLIB_PRINTF(format, args...)                                      \
    do {                                                                      \
        char name[MAXIMUM_PATH] = "";                                         \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));        \
        pid_t pid = getpid();                                                 \
        dr_printf("[drcctlib(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                \
    do {                                                                      \
        char name[MAXIMUM_PATH] = "";                                         \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));        \
        pid_t pid = getpid();                                                 \
        dr_printf("[drcctlib(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                              \
    dr_exit_process(-1)

typedef struct _client_cb_t {
    void (*func_instr_analysis)(void *, instr_instrument_msg_t*, void *);
    void *analysis_data;
    void (*func_insert_bb_start)(void *);
    void *insert_data;
} client_cb_t;

typedef struct _bb_shadow_t {
    app_pc *ip_shadow;
    state_t *state_shadow;
    char *disasm_shadow;
    slot_t slot_num;
} bb_shadow_t;

/**
 * ref "2014 - Call paths for pin tools - Chabbi, Liu, Mellor-Crummey" figure
 *2,3,4 A cct_bb_node_t logically represents a dynamorio basic block.(different
 *with Pin CCTLib)
 **/
typedef struct _cct_bb_node_t {
    bb_key_t key;
    context_handle_t caller_ctxt_hndl;
    context_handle_t child_ctxt_start_idx;
    slot_t max_slots;
} cct_bb_node_t;

typedef struct _cct_ip_node_t {
    cct_bb_node_t *parent_bb_node;
    splay_node_t *callee_splay_tree_root;
} cct_ip_node_t;



typedef struct _bb_instrument_msg_t {
    instr_instrument_msg_t *first;
    instr_instrument_msg_t *end;
    int32_t number;
    slot_t slot_max;
    bb_key_t bb_key;
} bb_instrument_msg_t;

// TLS(thread local storage)
typedef struct _per_thread_t {
    int id;
    // for root
    cct_bb_node_t *root_bb_node;
    // for current handle
    cct_bb_node_t *cur_bb_node;

    void* cur_buf;
    tls_memory_cache_t<cct_bb_node_t>* bb_node_cache;
    tls_memory_cache_t<splay_node_t>* splay_node_cache;
    splay_node_t* next_splay_node;
    splay_node_t* dummy_splay_node;

    aligned_ctxt_hndl_t cur_ctxt_hndl;
    aligned_ctxt_hndl_t cur_bb_child_ctxt_start_idx;
    slot_t cur_slot;
    state_t pre_instr_state;

    // DO_DATA_CENTRIC
    void *stack_base;
    void *stack_end;
    size_t dmem_alloc_size;
    context_handle_t dmem_alloc_ctxt_hndl;

    IF_DRCCTLIB_DEBUG(file_t log_file;)
} per_thread_t;

typedef struct _pt_cache_t {
    bool dead;
    per_thread_t *active_data;
    per_thread_t *cache_data;
} pt_cache_t;

#define BB_TABLE_HASH_BITS 10
#define PT_CACHE_TABLE_HASH_BITS 6
static hashtable_t global_bb_key_table;
static hashtable_t global_bb_shadow_table;
static hashtable_t global_pt_cache_table;

static int init_count = 0;


enum {
    INSTRACE_TLS_OFFS_BUF_PTR1,
    INSTRACE_TLS_OFFS_BUF_PTR2,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(type, tls_base, enum_val) *(type **)TLS_SLOT(tls_base, enum_val)
#define MINSERT instrlist_meta_preinsert

static int tls_idx;

static file_t log_file;
static client_cb_t client_cb; 

static void *flags_lock;
static void *bb_shadow_lock;
/* protected by flags_lock */
static char global_flags = DRCCTLIB_DEFAULT;

static bool (*global_instr_filter)(instr_t*) = DRCCTLIB_FILTER_ZERO_INSTR;

static cct_ip_node_t *global_ip_node_buff;
static context_handle_t global_ip_node_buff_idle_idx = CONTEXT_HANDLE_START;

static int global_thread_id_max = 0;

static void *bb_node_cache_lock;
static void *splay_node_cache_lock;
static memory_cache_t<cct_bb_node_t> *global_bb_node_cache;
static memory_cache_t<splay_node_t> *global_splay_node_cache;



#define FUNC_NAME_MALLOC "malloc"
#define FUNC_NAME_CALLOC "calloc"
#define FUNC_NAME_REALLOC "realloc"
#define FUNC_NAME_FREE "free"
#define STRING_POOL_NODES_MAX 7483647L
// #define STRING_POOL_NODES_MAX 2147483647L // 1^31 - 1
#define ATOM_ADD_STRING_POOL_INDEX(origin, val) dr_atomic_add32_return_sum(&origin, val)
static char *global_string_pool;
static int global_string_pool_idle_idx = 0;
static ConcurrentShadowMemory<data_handle_t>* global_shadow_memory;


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

static inline context_handle_t
cur_child_ctxt_start_idx(slot_t num)
{
    context_handle_t next_start_idx =
        ATOM_ADD_CTXT_HNDL(global_ip_node_buff_idle_idx, num);
    if (next_start_idx >= CONTEXT_HANDLE_MAX) {
        DRCCTLIB_EXIT_PROCESS("Preallocated IPNodes exhausted. CCTLib couldn't fit your "
                              "application in its memory. Try a smaller program.");
    }

    return next_start_idx - num;
}

// instr state flag
static inline bool
instr_state_contain(state_t instr_state_flag, state_t state)
{
    return (instr_state_flag & state) > 0;
}

static inline bool
instr_need_instrument_check_f(state_t instr_state_flag)
{
    return instr_state_flag > 0;
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

static inline void
instr_state_init(instr_t *instr, state_t *instr_state_flag_ptr)
{
    if (global_instr_filter(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | INSTR_STATE_CLIENT_INTEREST;
    }
    if (instr_is_call_direct(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | INSTR_STATE_CALL_DIRECT;
    } else if (instr_is_call_indirect(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | INSTR_STATE_CALL_IN_DIRECT;
    } else if (instr_is_return(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | INSTR_STATE_RETURN;
    }
}

static inline slot_t
bb_get_num_interest_instr(instr_t *bb_first)
{
    slot_t num = 0;
    for (instr_t *instr = bb_first; instr != NULL;
         instr = instr_get_next_app(instr)) {
        if (instr_need_instrument(instr)) {
            num++;
        }
    }
    return num;
}

static inline bb_key_t
bb_get_new_key()
{
    static bb_key_t global_bb_next_key = UNSHARED_BB_KEY_START;
    bb_key_t key = ATOM_ADD_NEXT_BB_KEY(global_bb_next_key);
    key = key - 1;
    if (key == BB_KEY_MAX) {
        DRCCTLIB_EXIT_PROCESS("MAX basic blocks created! Exiting..");
    }
    return key;
}

static inline bb_shadow_t *
bb_shadow_create(slot_t num)
{
    bb_shadow_t *bb_shadow = (bb_shadow_t *)dr_global_alloc(sizeof(bb_shadow_t));
    bb_shadow->slot_num = num;
    bb_shadow->ip_shadow = (app_pc *)dr_global_alloc(num * sizeof(app_pc));
    bb_shadow->state_shadow = (state_t *)dr_global_alloc(num * sizeof(state_t));
    bb_shadow->disasm_shadow =
        (char *)dr_global_alloc(DISASM_CACHE_SIZE * num * sizeof(char *));
    return bb_shadow;
}

static inline void
bb_shadow_free(void *shadow)
{
    bb_shadow_t *bb_shadow = (bb_shadow_t *)shadow;
    slot_t num = bb_shadow->slot_num;
    dr_global_free((void *)bb_shadow->ip_shadow, num * sizeof(app_pc));
    dr_global_free((void *)bb_shadow->state_shadow, num * sizeof(state_t));
    dr_global_free((void *)bb_shadow->disasm_shadow,
                   DISASM_CACHE_SIZE * num * sizeof(char *));
    dr_global_free(shadow, sizeof(bb_shadow_t));
}

static inline cct_bb_node_t *
bb_node_create(tls_memory_cache_t<cct_bb_node_t> *tls_cache, bb_key_t key,
               context_handle_t caller_ctxt_hndl, slot_t num)
{
    cct_bb_node_t *new_node = tls_cache->get_next_object();
    new_node->caller_ctxt_hndl = caller_ctxt_hndl;
    new_node->key = key;
    new_node->child_ctxt_start_idx = cur_child_ctxt_start_idx(num);
    new_node->max_slots = num;
    cct_ip_node_t *children = ctxt_hndl_to_ip_node(new_node->child_ctxt_start_idx);
    for (slot_t i = 0; i < num; ++i) {
        children[i].parent_bb_node = new_node;
        children[i].callee_splay_tree_root = NULL;
    }
    return new_node;
}

static inline void
pt_init(void *drcontext, per_thread_t *const pt, int id)
{
    pt->id = id;
    pt->bb_node_cache = new tls_memory_cache_t<cct_bb_node_t>(global_bb_node_cache,
                                                              bb_node_cache_lock, 100000);
    pt->splay_node_cache = new tls_memory_cache_t<splay_node_t>(
        global_splay_node_cache, splay_node_cache_lock, 100000);
    pt->dummy_splay_node = pt->splay_node_cache->get_next_object();
    pt->next_splay_node = pt->splay_node_cache->get_next_object();

    cct_bb_node_t *root_bb_node =
        bb_node_create(pt->bb_node_cache, THREAD_ROOT_BB_SHARED_BB_KEY,
                       THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE, 1);

    pt->root_bb_node = root_bb_node;

    pt->cur_bb_node = root_bb_node;
    pt->cur_slot = 0;
    pt->pre_instr_state = INSTR_STATE_THREAD_ROOT_VIRTUAL;

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);

    pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
    BUF_PTR(aligned_ctxt_hndl_t, pt->cur_buf, INSTRACE_TLS_OFFS_BUF_PTR1) =
        &(pt->cur_bb_child_ctxt_start_idx);

    pt->cur_ctxt_hndl = pt->cur_bb_child_ctxt_start_idx + pt->cur_slot;
    BUF_PTR(aligned_ctxt_hndl_t, pt->cur_buf, INSTRACE_TLS_OFFS_BUF_PTR2) =
        &(pt->cur_ctxt_hndl);

    if((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0){
        // Set stack sizes if data-centric is needed
        struct rlimit rlim;
        if (getrlimit(RLIMIT_STACK, &rlim)) {
            DRCCTLIB_EXIT_PROCESS("Failed to getrlimit()");
        }
        if (rlim.rlim_cur == RLIM_INFINITY) {
            DRCCTLIB_EXIT_PROCESS("Need a finite stack size. Dont use unlimited.");
        }
        pt->stack_base =
            (void *)(ptr_int_t)reg_get_value(DR_REG_RSP, (dr_mcontext_t *)drcontext);
        pt->stack_end = (void *)((ptr_int_t)pt->stack_base - rlim.rlim_cur);
        pt->dmem_alloc_size = 0;
        pt->dmem_alloc_ctxt_hndl = 0;
    }

#ifdef DRCCTLIB_DEBUG
#    ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.";
#    else
    char name[MAXIMUM_PATH] = "x86.";
#    endif
    gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d.thread%d.log", pid, id);
    pt->log_file = dr_open_file(name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(pt->log_file != INVALID_FILE);
#endif
}

static inline void
pt_cache_free(void *cache)
{
    pt_cache_t *pt_cache = (pt_cache_t *)cache;
    dr_global_free(pt_cache->cache_data, sizeof(per_thread_t));
    dr_global_free(cache, sizeof(pt_cache_t));
}

static inline void
instr_instrument_client_cb(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    if (instr_state_contain(instrument_msg->state, INSTR_STATE_CLIENT_INTEREST) &&
        client_cb.func_instr_analysis != NULL) {
        (*client_cb.func_instr_analysis)(drcontext, instrument_msg, client_cb.analysis_data);
    }
}

static inline instr_instrument_msg_t *
instr_instrument_msg_create(instrlist_t *bb, instr_t *instr, bool interest_start, slot_t slot, state_t state)
{
    instr_instrument_msg_t *msg =
        (instr_instrument_msg_t *)dr_global_alloc(
            sizeof(instr_instrument_msg_t));
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
bb_instrument_msg_create(bb_key_t bb_key, slot_t slot_max)
{
    bb_instrument_msg_t *bb_msg = (bb_instrument_msg_t *)dr_global_alloc(sizeof(bb_instrument_msg_t));
    bb_msg->first = bb_msg->end = NULL;
    bb_msg->number = 0;
    bb_msg->slot_max = slot_max;
    bb_msg->bb_key = bb_key;
    return bb_msg;
}

static inline void
bb_instrument_msg_add(bb_instrument_msg_t *bb_msg,
                          instr_instrument_msg_t *msg)
{
    if(bb_msg->number == 0) {
        bb_msg->first = bb_msg->end = msg;
    } else {
        bb_msg->end->next = msg;
        bb_msg->end = msg;
    }
    bb_msg->number++;
}

static inline instr_instrument_msg_t *
bb_instrument_msg_pop(bb_instrument_msg_t *bb_msg)
{
    if(bb_msg->number == 0) {
        return NULL;
    }
    instr_instrument_msg_t* cur = bb_msg->first;
    
    bb_msg->first = cur->next;
    bb_msg->number--;
    if(bb_msg->number == 0) {
        bb_msg->end = NULL;
    }
    
    cur->next = NULL;
    return cur;
}

static inline instr_t *
next_instrument_instr(bb_instrument_msg_t *bb_msg)
{
    if(bb_msg == NULL){
        return NULL;
    }
    if(bb_msg->first == NULL){
        return NULL;
    }
    return bb_msg->first->instr;
}

static inline void
bb_instrument_msg_delete(bb_instrument_msg_t *bb_msg)
{
    if (bb_msg == NULL) {
        return;
    }
    dr_global_free(bb_msg, sizeof(bb_instrument_msg_t));
}

static void
instrument_before_bb_first_instr(bb_key_t new_key, slot_t num)
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    IF_DRCCTLIB_DEBUG(dr_fprintf(pt->log_file, "pre bb key %d cur slot %d -> ",
                                 pt->cur_bb_node->key, pt->cur_slot);)
    context_handle_t new_caller_ctxt = 0;
    if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_THREAD_ROOT_VIRTUAL)) {
        new_caller_ctxt =
            pt->root_bb_node->child_ctxt_start_idx + THREAD_ROOT_SHARDED_CALLEE_INDEX;
    } else if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_CALL_DIRECT) ||
               instr_state_contain(pt->pre_instr_state, INSTR_STATE_CALL_IN_DIRECT)) {
        new_caller_ctxt = pt->cur_bb_node->child_ctxt_start_idx + pt->cur_slot;
    } else if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_RETURN)) {
        if (pt->cur_bb_node->caller_ctxt_hndl !=
            pt->root_bb_node->child_ctxt_start_idx + THREAD_ROOT_SHARDED_CALLEE_INDEX) {
            new_caller_ctxt = ctxt_hndl_to_ip_node(pt->cur_bb_node->caller_ctxt_hndl)
                                  ->parent_bb_node->caller_ctxt_hndl;
        } else {
            new_caller_ctxt = pt->cur_bb_node->caller_ctxt_hndl;
        }
    } else {
        if (pt->cur_slot >= pt->cur_bb_node->max_slots) {
            cct_bb_node_t *pre_bb = pt->cur_bb_node;
            DRCCTLIB_EXIT_PROCESS(" > pre bb key %d caller_ctxt_hndl %d", pre_bb->key,
                                  pre_bb->caller_ctxt_hndl);
        }
        new_caller_ctxt = pt->cur_bb_node->caller_ctxt_hndl;
    }
    splay_node_t *new_root = splay_tree_update(
        ctxt_hndl_to_ip_node(new_caller_ctxt)->callee_splay_tree_root,
        (splay_node_key_t)new_key, pt->dummy_splay_node, pt->next_splay_node);
    if (new_root->payload == NULL) {
        new_root->payload =
            (void *)bb_node_create(pt->bb_node_cache, new_key, new_caller_ctxt, num);
        pt->next_splay_node = pt->splay_node_cache->get_next_object();
    }
    ctxt_hndl_to_ip_node(new_caller_ctxt)->callee_splay_tree_root = new_root;
    pt->cur_bb_node = (cct_bb_node_t *)(new_root->payload);
    pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
    pt->pre_instr_state = 0;
    pt->cur_slot = 0;
    if (client_cb.func_insert_bb_start != NULL) {
        (*client_cb.func_insert_bb_start)(client_cb.insert_data);
    }
    IF_DRCCTLIB_DEBUG(dr_fprintf(pt->log_file, "cur bb key %d \n", pt->cur_bb_node->key);)
}

static void
instrument_before_every_instr_clean_call(slot_t slot, state_t state_flag)
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    pt->cur_slot = slot;
    pt->pre_instr_state = state_flag;
    pt->cur_ctxt_hndl = pt->cur_bb_child_ctxt_start_idx + slot;
}

#ifdef DRCCTLIB_DEBUG
static void
instrument_before_every_instr_debug_clean_call()
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    pt->cur_slot = slot;
    pt->pre_instr_state = state_flag;
    pt->cur_ctxt_hndl = pt->cur_bb_child_ctxt_start_idx + slot;
}
#endif

static inline void
instrument_before_every_instr_meta_instr(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    slot_t slot = instrument_msg->slot;
    state_t state_flag = instrument_msg->state;

    if (drreg_reserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "instrument_before_every_instr_meta_instr drreg_reserve_aflags != DRREG_SUCCESS");
    }
#ifdef ARM_CCTLIB
    reg_id_t reg_store_imm;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_store_imm) !=
        DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                                "drreg_reserve_register != DRREG_SUCCESS");
    }
    opnd_t opnd_reg_store_imm = opnd_create_reg(reg_store_imm);
#endif
    reg_id_t reg_tls, reg_buf, reg1;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, instr, NULL, &reg_buf) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, instr, NULL, &reg_tls) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                                "drreg_reserve_register != DRREG_SUCCESS");
    }
    opnd_t opnd_reg_1 = opnd_create_reg(reg1);
    drmgr_insert_read_tls_field(drcontext, tls_idx, bb, instr, reg_tls);
    opnd_t opnd_mem_pis = OPND_CREATE_PT_PRE_INSTR_STATE(
            reg_tls, offsetof(per_thread_t, pre_instr_state));
    opnd_t opnd_mem_cs =
            OPND_CREATE_PT_CUR_SLOT(reg_tls, offsetof(per_thread_t, cur_slot));
    opnd_t opnd_mem_cch = OPND_CREATE_PT_CUR_CTXT_HNDLE(
            reg_tls, offsetof(per_thread_t, cur_ctxt_hndl));
    
    opnd_t opnd_mem_cbccsi = OPND_CREATE_PT_CUR_BB_CHILD_CTXT_START_IDX(
            reg_tls, offsetof(per_thread_t, cur_bb_child_ctxt_start_idx));
    opnd_t opnd_imm_pis = OPND_CREATE_INSTR_STATE_FLAG(state_flag);
    opnd_t opnd_imm_cs = OPND_CREATE_SLOT(slot);

    // pt->pre_instr_state = state_flag;
#ifdef ARM_CCTLIB
    MINSERT(bb, instr,
            XINST_CREATE_load_int(drcontext, opnd_reg_store_imm, opnd_imm_pis));
    MINSERT(bb, instr,
            XINST_CREATE_store(drcontext, opnd_mem_pis, opnd_reg_store_imm));
#else
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_pis, opnd_imm_pis));
#endif
    // pt->cur_slot = slot;
#ifdef ARM_CCTLIB
    MINSERT(bb, instr,
            XINST_CREATE_load_int(drcontext, opnd_reg_store_imm, opnd_imm_cs));
    MINSERT(bb, instr,
            XINST_CREATE_store(drcontext, opnd_mem_cs, opnd_reg_store_imm));
#else
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_cs, opnd_imm_cs));
#endif
    // pt->cur_ctxt_hndl = pt->cur_bb_child_ctxt_start_idx + slot;
    MINSERT(bb, instr, XINST_CREATE_load(drcontext, opnd_reg_1, opnd_mem_cbccsi));
#ifdef ARM_CCTLIB
    MINSERT(bb, instr, XINST_CREATE_add(drcontext, opnd_reg_1, opnd_reg_store_imm));
#else
    MINSERT(bb, instr, XINST_CREATE_add(drcontext, opnd_reg_1, opnd_imm_cs));
#endif
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_cch, opnd_reg_1));

#ifdef ARM_CCTLIB
    if (drreg_unreserve_register(drcontext, bb, instr, reg_store_imm) !=
        DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                                "drreg_unreserve_register != DRREG_SUCCESS");
    }
#endif
    if (drreg_unreserve_register(drcontext, bb, instr, reg_tls) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, instr, reg_buf) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, instr, reg1) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                                "drreg_unreserve_register != DRREG_SUCCESS");
    }
    if (drreg_unreserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("drreg_unreserve_aflags != DRREG_SUCCESS");
    }
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
#endif

static dr_emit_flags_t
drcctlib_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                         bool for_trace, bool translating, void *user_data)
{
    bb_instrument_msg_t *bb_msg = (bb_instrument_msg_t *)user_data;
    if (bb_msg == NULL) {
        return DR_EMIT_DEFAULT;
    }
    if (instr == next_instrument_instr(bb_msg)) {
        instr_instrument_msg_t *instrument_msg = bb_instrument_msg_pop(bb_msg);
#ifdef ARM32_CCTLIB
        if (instrument_msg->state == INSTR_STATE_BB_START_NOP) {
            dr_insert_clean_call(
                drcontext, bb, instr, (void *)instrument_before_bb_first_instr, false, 2,
                OPND_CREATE_BB_KEY(bb_msg->bb_key), OPND_CREATE_SLOT(bb_msg->slot_max));
        } else {
            if ((global_flags & DRCCTLIB_USE_CLEAN_CALL) != 0) {
                dr_insert_clean_call(drcontext, bb, instr,
                                     (void *)instrument_before_every_instr_clean_call,
                                     false, 2, OPND_CREATE_SLOT(instrument_msg->slot),
                                     OPND_CREATE_INSTR_STATE_FLAG(instrument_msg->state));
            } else {
                instrument_before_every_instr_meta_instr(drcontext, instrument_msg);
            }
            IF_DRCCTLIB_DEBUG(dr_insert_clean_call(
                                  drcontext, bb, instr,
                                  (void *)instrument_before_every_instr_debug_clean_call,
                                  false, 0);)
            instr_instrument_client_cb(drcontext, instrument_msg);
        }
#else
        if (instrument_msg->slot == 0) {
            dr_insert_clean_call(
                drcontext, bb, instr, (void *)instrument_before_bb_first_instr, false, 2,
                OPND_CREATE_BB_KEY(bb_msg->bb_key), OPND_CREATE_SLOT(bb_msg->slot_max));
        }
        if ((global_flags & DRCCTLIB_USE_CLEAN_CALL) != 0) {
            dr_insert_clean_call(drcontext, bb, instr,
                                 (void *)instrument_before_every_instr_clean_call, false,
                                 2, OPND_CREATE_SLOT(instrument_msg->slot),
                                 OPND_CREATE_INSTR_STATE_FLAG(instrument_msg->state));
        } else {
            instrument_before_every_instr_meta_instr(drcontext, instrument_msg);
        }

        IF_DRCCTLIB_DEBUG(
            dr_insert_clean_call(drcontext, bb, instr,
                                 (void *)instrument_before_every_instr_debug_clean_call,
                                 false, 0);)
        instr_instrument_client_cb(drcontext, instrument_msg);
#endif
        instr_instrument_msg_delete(instrument_msg);

        if (bb_msg->number == 0) {
            bb_instrument_msg_delete(bb_msg);
        }
    }
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
drcctlib_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data)
{
#ifdef ARM32_CCTLIB
    instr_t *first_nop_instr = instrlist_first_app(bb);
    instr_t *first_instr = instr_get_next_app(first_nop_instr);
#else
    instr_t *first_instr = instrlist_first_app(bb);
#endif

    slot_t interest_instr_num = bb_get_num_interest_instr(first_instr);
    bool uninterested_bb = (interest_instr_num == 0) ? true : false;

    bb_key_t bb_key = 0;
    bb_shadow_t *bb_shadow = NULL;
    bool uninit_shadow = false;
    app_pc tag_pc = instr_get_app_pc(first_instr);

    if (uninterested_bb) {
        bb_key = UNINTERESTED_BB_SHARED_BB_KEY;
    } else {
        dr_mutex_lock(bb_shadow_lock);
        void *stored_key = hashtable_lookup(&global_bb_key_table, (void *)tag_pc);
        if (stored_key != NULL) {
            bb_key = (bb_key_t)(ptr_int_t)stored_key;
        } else {
            bb_key = bb_get_new_key();
            hashtable_add(&global_bb_key_table, (void *)tag_pc,
                          (void *)(ptr_int_t)bb_key);
            bb_shadow = bb_shadow_create(interest_instr_num);
            hashtable_add(&global_bb_shadow_table, (void *)(ptr_int_t)bb_key,
                          (void *)bb_shadow);
            uninit_shadow = true;
        }
        dr_mutex_unlock(bb_shadow_lock);
    }
    bb_instrument_msg_t *bb_msg =
        bb_instrument_msg_create(bb_key, uninterested_bb ? 1 : interest_instr_num);

    if(!uninterested_bb) {
        IF_ARM32_CCTLIB(bb_instrument_msg_add(bb_msg,
                              instr_instrument_msg_create(bb, first_nop_instr, false, 0,
                                                          INSTR_STATE_BB_START_NOP));)
        slot_t slot = 0;
        bool init_interest_start = false;
        IF_ARM_CCTLIB(bool keep_insert_instrument = true;)
        for (instr_t *instr = first_instr; instr != NULL;
             instr = instr_get_next_app(instr)) {
            state_t instr_state_flag = 0;
            instr_state_init(instr, &instr_state_flag);
            if (instr_need_instrument_check_f(instr_state_flag)) {
                if(uninit_shadow) {
                    bb_shadow->ip_shadow[slot] = instr_get_app_pc(instr);
                    bb_shadow->state_shadow[slot] = instr_state_flag;
                    instr_disassemble_to_buffer(drcontext, instr,
                                                bb_shadow->disasm_shadow +
                                                    slot * DISASM_CACHE_SIZE,
                                                DISASM_CACHE_SIZE);
                    IF_DRCCTLIB_DEBUG(
                        dr_fprintf(pt->log_file, "bb key %d slot %d : %s \n", bb_key,
                                   slot,
                                   bb_shadow->disasm_shadow + slot * DISASM_CACHE_SIZE);)
                }
                bool interest_start = false;
                if (!init_interest_start &&
                    instr_state_contain(instr_state_flag, INSTR_STATE_CLIENT_INTEREST)) {
                    init_interest_start = true;
                    interest_start = true;
                }
#ifdef ARM_CCTLIB
                if (keep_insert_instrument) {
                    bb_instrument_msg_add(
                        bb_msg,
                        instr_instrument_msg_create(bb, instr, interest_start, slot,
                                                    instr_state_flag));
                }
                if (instr_is_exclusive_load(instr)) {
                    keep_insert_instrument = false;
                }
                if (instr_is_exclusive_store(instr)) {
                    keep_insert_instrument = true;
                }
#else
                bb_instrument_msg_add(bb_msg,
                                      instr_instrument_msg_create(bb, instr,
                                                                  interest_start, slot,
                                                                  instr_state_flag));
#endif
                slot++;
            }
        }
    }

#ifdef ARM_CCTLIB
    if(instr_is_exclusive_store(first_instr) || instr_is_exclusive_load(first_instr)) {
        *user_data = NULL;
        return DR_EMIT_DEFAULT;
    }
#endif
    *user_data = (void*)bb_msg;
    return DR_EMIT_DEFAULT;
}


static dr_emit_flags_t
drcctlib_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
#ifdef ARM32_CCTLIB
    instr_t *first_instr = instrlist_first_app(bb);
    instr_t *pre_first_nop_instr = XINST_CREATE_move(
        drcontext, opnd_create_reg(DR_REG_R0), opnd_create_reg(DR_REG_R0));
    instrlist_preinsert(bb, first_instr, pre_first_nop_instr);
#endif
    return DR_EMIT_DEFAULT;
}

static dr_signal_action_t
drcctlib_event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    DRCCTLIB_PRINTF("drcctlib_event_signal %d(thread %d)\n", siginfo->sig, pt->id);
    return DR_SIGNAL_DELIVER;
}

static void
drcctlib_event_thread_start(void *drcontext)
{

    int id = ATOM_ADD_THREAD_ID_MAX(global_thread_id_max);
    id--;

    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if(pt == NULL){
        DRCCTLIB_EXIT_PROCESS("drcctlib_event_thread_start pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt_init(drcontext, pt, id);
    pt_cache_t *pt_cache = (pt_cache_t *)dr_global_alloc(sizeof(pt_cache_t));
    pt_cache->active_data = pt;
    pt_cache->cache_data = NULL;
    pt_cache->dead = false;
    hashtable_add(&global_pt_cache_table, (void *)(ptr_int_t)id, pt_cache);
    DRCCTLIB_PRINTF("thread %d init", id);
}

static void
drcctlib_event_thread_end(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    IF_DRCCTLIB_DEBUG(dr_close_file(pt->log_file);)
    pt_cache_t *pt_cache = (pt_cache_t *)hashtable_lookup(&global_pt_cache_table,
                                                          (void *)(ptr_int_t)(pt->id));
    pt_cache->cache_data = (per_thread_t *)dr_global_alloc(sizeof(per_thread_t));
    memcpy(pt_cache->cache_data, pt_cache->active_data, sizeof(per_thread_t));
    pt_cache->dead = true;
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
    DRCCTLIB_PRINTF("thread %d end", pt_cache->cache_data->id);
}



static inline int32_t
next_string_pool_idx(char *name)
{
    int32_t len = strlen(name) + 1;
    int32_t next_idx = ATOM_ADD_STRING_POOL_INDEX(global_string_pool_idle_idx, len);
    if(next_idx >= STRING_POOL_NODES_MAX) {
        DRCCTLIB_EXIT_PROCESS("Preallocated String Pool exhausted. CCTLib couldn't fit your "
                   "application in its memory. Try a smaller program.");
    }
    strncpy(global_string_pool+ next_idx - len, name, len);
    return next_idx - len;
}
static void
init_shadow_memory_space(void *addr, uint32_t accessLen, data_handle_t *initializer)
{
    uint64_t endAddr = (uint64_t)addr + accessLen;
    uint32_t numInited = 0;

    for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr;
         curAddr += SHADOW_PAGE_SIZE) {
        data_handle_t *status =
            GetOrCreateShadowAddress<0>(*global_shadow_memory, (size_t)curAddr);
        int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)addr);

        for (int i = 0; (i < maxBytesInThisPage) && numInited < accessLen;
             numInited++, i++) {
            status[i] = *initializer;
        }
    }
}

static void
capture_malloc_size(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    // DRCCTLIB_PRINTF("capture_malloc_size %lu", (size_t)drwrap_get_arg(wrapcxt, 0));
    pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 0);
    pt->dmem_alloc_ctxt_hndl =
        pt->cur_bb_node->child_ctxt_start_idx;
}

static void
capture_malloc_pointer(void *wrapcxt, void *user_data)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    void *ptr = drwrap_get_retval(wrapcxt);
    data_handle_t data_hndl;
    data_hndl.object_type = DYNAMIC_OBJECT;
    data_hndl.path_handle = pt->dmem_alloc_ctxt_hndl;
    // DRCCTLIB_PRINTF("DYNAMIC_OBJECT %d %lu", data_hndl.path_handle, pt->dmem_alloc_size);
    init_shadow_memory_space(ptr, pt->dmem_alloc_size,
                                  &data_hndl);
}

static void
capture_calloc_size(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    // DRCCTLIB_PRINTF("capture_calloc_size %lu %lu", (size_t)drwrap_get_arg(wrapcxt, 0), (size_t)drwrap_get_arg(wrapcxt, 1));
    pt->dmem_alloc_size =
        (size_t)drwrap_get_arg(wrapcxt, 0) * (size_t)drwrap_get_arg(wrapcxt, 1);
    pt->dmem_alloc_ctxt_hndl =
        pt->cur_bb_node->child_ctxt_start_idx;
}

static void
capture_realloc_size(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    // DRCCTLIB_PRINTF("capture_realloc_size %lu", (size_t)drwrap_get_arg(wrapcxt, 1));
    pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 1);
    pt->dmem_alloc_ctxt_hndl =
        pt->cur_bb_node->child_ctxt_start_idx;
}

static void
capture_free(void *wrapcxt, void **user_data)
{
}

// compute static variables
static void
compute_static_var(char *filename, const module_data_t *info)
{
    // Elf *elf;               /* Our Elf pointer for libelf */
    // Elf_Scn *scn = NULL;    /* Section Descriptor */
    // Elf_Data *edata = NULL; /* Data Descriptor */
    // GElf_Sym sym;           /* Symbol */
    // GElf_Shdr shdr;         /* Section Header */

    // int i, symbol_count;
    // int fd = open(filename, O_RDONLY);

    // if (elf_version(EV_CURRENT) == EV_NONE) {
    //     DRCCTLIB_EXIT_PROCESS("WARNING Elf Library is out of date!");
    // }

    // // in memory
    // elf = elf_begin(fd, ELF_C_READ,
    //                 NULL); // Initialize 'elf' pointer to our file descriptor

    // // Iterate each section until symtab section for object symbols
    // while ((scn = elf_nextscn(elf, scn)) != NULL) {
    //     gelf_getshdr(scn, &shdr);

    //     if (shdr.sh_type == SHT_SYMTAB) {
    //         edata = elf_getdata(scn, edata);
    //         symbol_count = shdr.sh_size / shdr.sh_entsize;

    //         for (i = 0; i < symbol_count; i++) {
    //             if (gelf_getsym(edata, i, &sym) == NULL) {
    //                 DRCCTLIB_PRINTF("gelf_getsym return NULL");
    //                 DRCCTLIB_EXIT_PROCESS("%s", elf_errmsg(elf_errno()));
    //             }

    //             if ((sym.st_size == 0) ||
    //                 (ELF32_ST_TYPE(sym.st_info) != STT_OBJECT)) { // not a variable
    //                 continue;
    //             }

    //             data_handle_t data_hndl;
    //             data_hndl.object_type = STATIC_OBJECT;
    //             char *sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
    //             data_hndl.sym_name = sym_name ? next_string_pool_idx(sym_name) : 0;
    //             // DRCCTLIB_PRINTF("STATIC_OBJECT %s", sym_name);
    //             init_shadow_memory_space((void *)((uint64_t)(info->start) + sym.st_value),
    //                                      (uint32_t)sym.st_size, &data_hndl);
    //         }
    //     }
    // }
}

static inline app_pc
moudle_get_function_entry(const module_data_t *info, const char* func_name,
                          bool check_internal_func)
{
    app_pc functionEntry;
    if (check_internal_func) {
        size_t offs;
        if (drsym_lookup_symbol(info->full_path, func_name, &offs,
                                DRSYM_DEMANGLE) == DRSYM_SUCCESS) {
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
                                         void (*post_func_cb)(void *wrapcxt,
                                                              void *user_data))
{
    app_pc func_entry = moudle_get_function_entry(info, func_name, false);
    if (func_entry != NULL) {
        return drwrap_wrap(func_entry, pre_func_cb, post_func_cb);
    } else {
        return false;
    }
}

static void
drcctlib_event_module_load_analysis(void *drcontext, const module_data_t *info, bool loaded)
{
    // static analysis
    char filename[PATH_MAX];
    char *result = realpath(info->full_path, filename);
    if (result == NULL) {
        DRCCTLIB_PRINTF("%s ---- failed to resolve path", info->full_path);
    } else {
        DRCCTLIB_PRINTF("%s ---- success to resolve path", info->full_path);
        compute_static_var(filename, info);
    }

    // dynamic analysis
    insert_func_instrument_by_drwap(info, FUNC_NAME_MALLOC, capture_malloc_size,
                                             capture_malloc_pointer);
    insert_func_instrument_by_drwap(info, FUNC_NAME_CALLOC, capture_calloc_size,
                                             capture_malloc_pointer);
    insert_func_instrument_by_drwap(info, FUNC_NAME_REALLOC, capture_realloc_size,
                                             capture_malloc_pointer);
    insert_func_instrument_by_drwap(info, FUNC_NAME_FREE, capture_free, NULL);
}

static void
drcctlib_event_module_unload_analysis(void *drcontext, const module_data_t *info)
{
}

static inline void
init_global_bb_shadow_table()
{
    bb_shadow_t *thread_root_bb_shared_shadow = bb_shadow_create(1);
    thread_root_bb_shared_shadow->ip_shadow[0] = 0;
    strcpy(thread_root_bb_shared_shadow->disasm_shadow, "thread root bb");
    thread_root_bb_shared_shadow->state_shadow[0] = INSTR_STATE_THREAD_ROOT_VIRTUAL;
    hashtable_add(&global_bb_shadow_table,
                  (void *)(ptr_int_t)THREAD_ROOT_BB_SHARED_BB_KEY,
                  (void *)thread_root_bb_shared_shadow);

    bb_shadow_t *uninterest_bb_share_shadow = bb_shadow_create(1);
    uninterest_bb_share_shadow->ip_shadow[0] = 0;
    strcpy(uninterest_bb_share_shadow->disasm_shadow, "uninterested bb");
    uninterest_bb_share_shadow->state_shadow[0] = INSTR_STATE_UNINTEREST_FIRST;
    hashtable_add(&global_bb_shadow_table,
                  (void *)(ptr_int_t)UNINTERESTED_BB_SHARED_BB_KEY,
                  (void *)uninterest_bb_share_shadow);
}

static inline void
init_progress_root_ip_node()
{
    cct_ip_node_t *progress_root_ip =
        global_ip_node_buff + THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE;
    progress_root_ip->parent_bb_node = NULL;
    progress_root_ip->callee_splay_tree_root = NULL;
}

static inline void
init_global_buff()
{
    global_ip_node_buff =
        (cct_ip_node_t *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t),
                              PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (global_ip_node_buff == MAP_FAILED) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: MAP_FAILED global_ip_node_buff");
    } else {
        init_progress_root_ip_node();
    }

    global_string_pool =
        (char *)mmap(0, STRING_POOL_NODES_MAX * sizeof(char), PROT_WRITE | PROT_READ,
                     MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (global_string_pool == MAP_FAILED) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: MAP_FAILED global_string_pool");
    }

    global_bb_node_cache = new memory_cache_t<cct_bb_node_t>();
    global_splay_node_cache = new memory_cache_t<splay_node_t>();
    if (!global_bb_node_cache->init(CONTEXT_HANDLE_MAX/10, 1000, 10)) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: MAP_FAILED global_bb_node_cache");
    }
    if (!global_splay_node_cache->init(CONTEXT_HANDLE_MAX/10, 1000, 10)) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: MAP_FAILED global_splay_node_cache");
    }
}

static inline void
free_global_buff()
{
    if (munmap(global_ip_node_buff, CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t)) != 0
        || munmap(global_string_pool, STRING_POOL_NODES_MAX * sizeof(char)) != 0) {
        DRCCTLIB_PRINTF("free_global_buff munmap error");
    }

    delete global_bb_node_cache;
    delete global_splay_node_cache;
}

static inline void
create_global_locks()
{
    flags_lock = dr_recurlock_create();
    bb_shadow_lock = dr_mutex_create();
    bb_node_cache_lock = dr_mutex_create();
    splay_node_cache_lock = dr_mutex_create();
}

static inline void
destroy_global_locks()
{
    dr_recurlock_destroy(flags_lock);
    dr_mutex_destroy(bb_shadow_lock);
    dr_mutex_destroy(bb_node_cache_lock);
    dr_mutex_destroy(splay_node_cache_lock);
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
    dr_fprintf(log_file, "\nTotalCallPaths = %" PRIu32, global_ip_node_buff_idle_idx);
    // Peak resource usage
    dr_fprintf(log_file, "\nPeakRSS = %zu", get_peak_rss());
}

static per_thread_t *
pt_get_from_gcache_by_id(int id)
{
    pt_cache_t *cache = (pt_cache_t *)hashtable_lookup(&global_pt_cache_table,
                                                       (void *)(ptr_int_t)(id));
    if (cache->dead) {
        return cache->cache_data;
    } else {
        return cache->active_data;
    }
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
    cct_bb_node_t *bb = ctxt_hndl_to_ip_node(ctxt_hndl)->parent_bb_node;
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
    if (bb->key == UNINTERESTED_BB_SHARED_BB_KEY) {
        context_t *ctxt = ctxt_create(ctxt_hndl, 0, 0);
        sprintf(ctxt->func_name, "INSTRUCTION ARE NOT INSTRUMENTED.");
        sprintf(ctxt->file_path, " ");
        sprintf(ctxt->code_asm, " ");
        return ctxt;
    }

    bb_shadow_t *shadow = (bb_shadow_t *)hashtable_lookup(&global_bb_shadow_table,
                                                          (void *)(ptr_int_t)(bb->key));
    app_pc addr = shadow->ip_shadow[ctxt_hndl - bb->child_ctxt_start_idx];
    // DRCCTLIB_PRINTF("ctxt_hndl %d addr %lu bb->child_ctxt_start_idx %d bb->max_slots %d", ctxt_hndl, addr, bb->child_ctxt_start_idx, bb->max_slots); 
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
        sprintf(ctxt->file_path, "%s", data->full_path);
        sprintf(ctxt->code_asm, "%s", code);
        dr_free_module_data(data);
        return ctxt;
    } else {
        context_t *ctxt = ctxt_create(ctxt_hndl, 0, addr);
        sprintf(ctxt->func_name, "<noname>");
        sprintf(ctxt->file_path, "%s", data->full_path);
        sprintf(ctxt->code_asm, "%s", code);
        dr_free_module_data(data);
        return ctxt;
    }
}

bool
drcctlib_init(char flag)
{
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&init_count, 1);
    if (count > 1)
        return true;
    global_flags = flag;
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
    drreg_options_t ops = { sizeof(ops),
                            IF_ARM_CCTLIB_ELSE(5, 4)/*max slots needed*/,
                            false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drreg");
        return false;
    }

    disassemble_set_syntax(DR_DISASM_DRCCTLIB);

    init_global_buff();
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
    if((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0){
        global_shadow_memory = new ConcurrentShadowMemory<data_handle_t>();
        drmgr_register_module_load_event(drcctlib_event_module_load_analysis);
        drmgr_register_module_unload_event(drcctlib_event_module_unload_analysis);
    }
    


    hashtable_init(&global_bb_key_table, BB_TABLE_HASH_BITS, HASH_INTPTR, false);
    hashtable_init_ex(&global_bb_shadow_table, BB_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!strdup*/, false /*!synch*/, bb_shadow_free, NULL, NULL);
    init_global_bb_shadow_table();
    
    hashtable_init_ex(&global_pt_cache_table, PT_CACHE_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!strdup*/, false /*!synch*/, pt_cache_free, NULL, NULL);

    create_global_locks();

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1)
        return false;
    if (!drmgr_register_thread_init_event(drcctlib_event_thread_start))
        return false;
    if (!drmgr_register_thread_exit_event(drcctlib_event_thread_end))
        return false;

    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);

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
    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT))
        DR_ASSERT(false);
    print_stats();
    if (!drmgr_unregister_bb_app2app_event(drcctlib_event_bb_app2app) ||
        !drmgr_unregister_bb_instrumentation_event(drcctlib_event_bb_analysis) ||
        // !drmgr_unregister_bb_insertion_event(drcctlib_event_bb_insert) ||
        !drmgr_unregister_signal_event(drcctlib_event_signal) ||
        !drmgr_unregister_thread_init_event(drcctlib_event_thread_start) ||
        !drmgr_unregister_thread_exit_event(drcctlib_event_thread_end) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("failed to unregister in drcctlib_exit");
    }
    if((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0){
        drmgr_unregister_module_load_event(drcctlib_event_module_load_analysis);
        drmgr_unregister_module_unload_event(drcctlib_event_module_unload_analysis);
        delete global_shadow_memory;
    }

    hashtable_delete(&global_bb_key_table);
    hashtable_delete(&global_bb_shadow_table);
    hashtable_delete(&global_pt_cache_table);
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
    // free cct_ip_node and cct_bb_node
    free_global_buff();

    dr_close_file(log_file);
    // DRCCTLIB_PRINTF("====drcctlib_exit end");
}

DR_EXPORT
void
drcctlib_register_instr_filter(bool (*filter)(instr_t *))
{
    global_instr_filter= filter;
}

DR_EXPORT
void
drcctlib_register_client_cb(void (*func_instr_analysis)(void *, instr_instrument_msg_t *,
                                                        void *),
                            void *analysis_data, void (*func_insert_bb_start)(void *),
                            void *insert_data)
{
    client_cb.func_instr_analysis = func_instr_analysis;
    client_cb.analysis_data = analysis_data;
    client_cb.func_insert_bb_start = func_insert_bb_start;
    client_cb.insert_data = insert_data;
}

DR_EXPORT
void
drcctlib_config_log_file(file_t file)
{
    log_file = file;
}

DR_EXPORT bool
drcctlib_init_ex(bool (*filter)(instr_t *), file_t file,
                 void (*func1)(void *, instr_instrument_msg_t *, void *), void *data1,
                 void (*func2)(void *), void *data2, char flag)
{
    if (!drcctlib_init(flag)) {
        return false;
    }
    drcctlib_register_instr_filter(filter);
    drcctlib_config_log_file(file);
    drcctlib_register_client_cb(func1, data1, func2, data2);
    return true;
}

DR_EXPORT
file_t
drcctlib_get_log_file()
{
    return log_file;
}

DR_EXPORT
int
drcctlib_get_per_thread_date_id()
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    return (int)(pt->id);
}

DR_EXPORT
context_handle_t
drcctlib_get_context_handle()
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    return (context_handle_t)(pt->cur_ctxt_hndl);
}

DR_EXPORT
context_handle_t
drcctlib_get_bb_start_context_handle()
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    return (context_handle_t)(pt->cur_bb_child_ctxt_start_idx);
}

DR_EXPORT
void
drcctlib_get_context_handle_in_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                   reg_id_t store_reg)
{
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR2, store_reg);
}

DR_EXPORT
void
drcctlib_get_bb_start_context_handle_in_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                            reg_id_t store_reg)
{
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR1, store_reg);
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
void
drcctlib_print_ctxt_hndl_msg(context_handle_t ctxt_hndl, bool print_asm,
                             bool print_file_path)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_print_ctxt_hndl_msg: !ctxt_hndl_is_valid");
    }
    context_t *ctxt = ctxt_get_from_ctxt_hndl(ctxt_hndl);
    if (print_asm && print_file_path) {
        dr_fprintf(log_file, "%s(%d):\"(%p)%s\"[%s]\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip, ctxt->code_asm, ctxt->file_path);
    } else if (print_asm) {
        dr_fprintf(log_file, "%s(%d):\"(%p)%s\"\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip, ctxt->code_asm);
    } else if (print_file_path) {
        dr_fprintf(log_file, "%s(%d):\"(%p)\"[%s]\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip, ctxt->file_path);
    } else {
        dr_fprintf(log_file, "%s(%d):\"(%p)\"\n", ctxt->func_name, ctxt->line_no,
                   (uint64_t)ctxt->ip);
    }
}

DR_EXPORT
void
drcctlib_print_full_cct(context_handle_t ctxt_hndl, bool print_asm, bool print_file_path,
                        int max_depth)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_print_full_cct: !ctxt_hndl_is_valid");
    }
    int depth = 0;
    while (true) {
        drcctlib_print_ctxt_hndl_msg(ctxt_hndl, print_asm, print_file_path);
        if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
            break;
        }
        if (depth >= max_depth) {
            dr_fprintf(log_file, "Truncated call path (due to client deep call chain)\n");
            break;
        }
        if (depth >= MAX_CCT_PRINT_DEPTH) {
            dr_fprintf(log_file, "Truncated call path (due to deep call chain)\n");
            break;
        }

        ctxt_hndl = ctxt_hndl_to_ip_node(ctxt_hndl)->parent_bb_node->caller_ctxt_hndl;
        depth++;
    }
}

DR_EXPORT
context_t *
drcctlib_get_full_cct(context_handle_t ctxt_hndl, int max_depth)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_full_cct !ctxt_hndl_is_valid");
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
        if (depth >= max_depth) {
            context_t *ctxt = ctxt_create(ctxt_hndl, 0, 0);
            sprintf(ctxt->func_name,
                    "Truncated call path (due to client deep call chain)");
            sprintf(ctxt->file_path, " ");
            sprintf(ctxt->code_asm, " ");
            list_pre_ptr->pre_ctxt = ctxt;
            list_pre_ptr = ctxt;
            break;
        }
        if (depth >= MAX_CCT_PRINT_DEPTH) {
            context_t *ctxt = ctxt_create(ctxt_hndl, 0, 0);
            sprintf(ctxt->func_name,
                    "Truncated call path (due to drcctlib deep call chain)");
            sprintf(ctxt->file_path, " ");
            sprintf(ctxt->code_asm, " ");
            list_pre_ptr->pre_ctxt = ctxt;
            list_pre_ptr = ctxt;
            break;
        }

        ctxt_hndl = ctxt_hndl_to_ip_node(ctxt_hndl)->parent_bb_node->caller_ctxt_hndl;
        depth++;
    }
    return start;
}

DR_EXPORT
app_pc
drcctlib_get_pc(context_handle_t ctxt_hndl)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_pc: !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        DRCCTLIB_PRINTF("drcctlib_get_pc: THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE");
        return 0;
    }
    cct_bb_node_t *bb_node = ctxt_hndl_to_ip_node(ctxt_hndl)->parent_bb_node;
    if (bb_node->key == THREAD_ROOT_BB_SHARED_BB_KEY) {
        DRCCTLIB_PRINTF("drcctlib_get_pc: THREAD_ROOT_BB_SHARED_BB_KEY");
        return 0;
    }
    if (bb_node->key == UNINTERESTED_BB_SHARED_BB_KEY) {
        DRCCTLIB_PRINTF("drcctlib_get_pc: THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE");
        return 0;
    }
    slot_t slot = ctxt_hndl - bb_node->child_ctxt_start_idx;
    bb_shadow_t *bb_shadow = (bb_shadow_t *)hashtable_lookup(
        &global_bb_shadow_table, (void *)(ptr_int_t)(bb_node->key));
    app_pc pc = bb_shadow->ip_shadow[slot];
    return pc;
}

DR_EXPORT
context_handle_t
drcctlib_get_caller_handle(context_handle_t ctxt_hndl)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_get_caller_handle !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        DRCCTLIB_PRINTF("drcctlib_get_caller_handle TO INVALID_CONTEXT_HANDLE");
        return INVALID_CONTEXT_HANDLE;
    }
    return ctxt_hndl_to_ip_node(ctxt_hndl)->parent_bb_node->caller_ctxt_hndl;
}

DR_EXPORT
bool
have_same_caller_prefix(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl1) || !ctxt_hndl_is_valid(ctxt_hndl1)) {
        DRCCTLIB_EXIT_PROCESS("have_same_caller_prefix !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl1 == ctxt_hndl2)
        return true;
    if (ctxt_hndl1 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE ||
        ctxt_hndl2 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        return false;
    }
    context_handle_t t1 =
        ctxt_hndl_to_ip_node(ctxt_hndl1)->parent_bb_node->caller_ctxt_hndl;
    context_handle_t t2 =
        ctxt_hndl_to_ip_node(ctxt_hndl2)->parent_bb_node->caller_ctxt_hndl;
    return t1 == t2;
}

// API to get the handle for a data object
DR_EXPORT
data_handle_t
GetDataObjectHandle(void *drcontext, void *address)
{
    data_handle_t data_hndl;
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // if it is a stack location, set so and return
    if (address > pt->stack_end && address < pt->stack_base) {
        data_hndl.object_type = STACK_OBJECT;
        return data_hndl;
    }
    data_hndl = *(GetOrCreateShadowAddress<0>(*global_shadow_memory,
                                               (size_t)(uint64_t)address));
    return data_hndl;
}

DR_EXPORT
char *
GetStringFromStringPool(int index)
{
    return global_string_pool+ index;
}