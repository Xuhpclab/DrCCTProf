#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <sys/resource.h>

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

#include "libelf.h"


// for hpc formate
#include <vector>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>

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
#ifdef FOR_SPEC_TEST
#define ATOM_ADD_CTXT_HNDL(origin, val) dr_atomic_add64_return_sum(&origin, val)
#else
#define ATOM_ADD_CTXT_HNDL(origin, val) dr_atomic_add32_return_sum(&origin, val)
#endif
#define ATOM_ADD_THREAD_ID_MAX(origin) dr_atomic_add32_return_sum(&origin, 1)

#ifdef INTEL_CCTLIB
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT32
#    define OPND_CREATE_SLOT OPND_CREATE_INT32
#    define OPND_CREATE_STATE OPND_CREATE_INT32
#elif defined(ARM_CCTLIB)
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT
#    define OPND_CREATE_SLOT OPND_CREATE_INT
#    define OPND_CREATE_STATE OPND_CREATE_INT
#endif
#define OPND_CREATE_PT_CUR_SLOT OPND_CREATE_MEM32
#define OPND_CREATE_PT_CUR_STATE OPND_CREATE_MEM32

#define THREAD_ROOT_BB_SHARED_BB_KEY 0
#define UNINTERESTED_BB_SHARED_BB_KEY 1
#define UNSHARED_BB_KEY_START 2

// #define TEST_TREE_SIZE

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
#ifdef TEST_TREE_SIZE
    int32_t children_number;
    uint64_t global_search_times;
#endif
} cct_ip_node_t;



typedef struct _bb_instrument_msg_t {
    instr_instrument_msg_t *first;
    instr_instrument_msg_t *end;
    int32_t number;
    slot_t slot_max;
    bb_key_t bb_key;
    state_t bb_end_state;
} bb_instrument_msg_t;

#ifdef TEST_TREE_SIZE
void* test_lock;
static uint64_t real_node_number = 0;
#endif


struct hpcviewer_format_ip_node_t;
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

    aligned_ctxt_hndl_t cur_bb_child_ctxt_start_idx;
    state_t pre_instr_state;
    slot_t cur_slot;
    state_t cur_state;

    // DO_DATA_CENTRIC
    void *stack_base;
    void *stack_end;
    bool stack_unlimited;
    size_t dmem_alloc_size;
    context_handle_t dmem_alloc_ctxt_hndl;

    // HPCVIEWER_FORMAT
    hpcviewer_format_ip_node_t *tlsHPCRunCCTRoot;
    uint64_t nodeCount;

    IF_DRCCTLIB_DEBUG(file_t log_file;)
    
#ifdef TEST_TREE_SIZE
    uint64_t real_node_number;
#endif
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
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, enum_val) *(aligned_ctxt_hndl_t **)TLS_SLOT(tls_base, enum_val)
#define MINSERT instrlist_meta_preinsert

static int tls_idx;

static file_t log_file;
static client_cb_t client_cb; 


static char global_flags = DRCCTLIB_DEFAULT;

static bool (*global_instr_filter)(instr_t*) = DRCCTLIB_FILTER_ZERO_INSTR;

static cct_ip_node_t *global_ip_node_buff;
static context_handle_t global_ip_node_buff_idle_idx = CONTEXT_HANDLE_START;

static int global_thread_id_max = 0;

static void *bb_shadow_lock;
static void *bb_node_cache_lock;
static void *splay_node_cache_lock;
static memory_cache_t<cct_bb_node_t> *global_bb_node_cache;
static memory_cache_t<splay_node_t> *global_splay_node_cache;


#define FUNC_NAME_MMAP "mmap"
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


typedef struct _offline_module_data_t{
    int id;
    bool app;
    char path[MAXIMUM_PATH];
    app_pc start;
    app_pc end;
}offline_module_data_t;
#define OFFLINE_MODULE_DATA_TABLE_HASH_BITS 6
static hashtable_t global_module_data_table;
static void *module_data_lock;

static inline offline_module_data_t *
offline_module_data_create(const module_data_t *info);

static inline void
offline_module_data_free(void *data);


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
        (char *)dr_global_alloc(DISASM_CACHE_SIZE * num * sizeof(char));
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
                   DISASM_CACHE_SIZE * num * sizeof(char));
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
                                                              bb_node_cache_lock, 10000);
    pt->splay_node_cache = new tls_memory_cache_t<splay_node_t>(
        global_splay_node_cache, splay_node_cache_lock, 10000);
    pt->dummy_splay_node = pt->splay_node_cache->get_next_object();
    pt->next_splay_node = pt->splay_node_cache->get_next_object();

    cct_bb_node_t *root_bb_node =
        bb_node_create(pt->bb_node_cache, THREAD_ROOT_BB_SHARED_BB_KEY,
                       THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE, 1);

    pt->root_bb_node = root_bb_node;

    pt->cur_bb_node = root_bb_node;
    pt->pre_instr_state = INSTR_STATE_THREAD_ROOT_VIRTUAL;
    pt->cur_slot = 0;
    pt->cur_state = INSTR_STATE_CLIENT_INTEREST;

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);

    pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
    BUF_PTR(pt->cur_buf, INSTRACE_TLS_OFFS_BUF_PTR) =
        &(pt->cur_bb_child_ctxt_start_idx);

    if((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0){
        // Set stack sizes if data-centric is needed
        struct rlimit rlim;
        if (getrlimit(RLIMIT_STACK, &rlim)) {
            DRCCTLIB_EXIT_PROCESS("Failed to getrlimit()");
        }
        if (rlim.rlim_cur == RLIM_INFINITY) {
            pt->stack_unlimited = true;
            pt->stack_base = (void *)(ptr_int_t)0;
            pt->stack_end = (void *)(ptr_int_t)0;
        } else {
            pt->stack_unlimited = false;
            pt->stack_base =
            (void *)(ptr_int_t)reg_get_value(DR_REG_XSP, (dr_mcontext_t *)drcontext);
            pt->stack_end = (void *)((ptr_int_t)pt->stack_base - rlim.rlim_cur);
        }
        pt->dmem_alloc_size = 0;
        pt->dmem_alloc_ctxt_hndl = 0;
    }
    if((global_flags & DRCCTLIB_SAVE_HPCTOOLKIT_FILE) != 0){
        pt->nodeCount = 0;
        pt->tlsHPCRunCCTRoot = NULL;
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

#ifdef TEST_TREE_SIZE
        pt->real_node_number = 0;
#endif
}

static inline void
pt_cache_free(void *cache)
{
    pt_cache_t *pt_cache = (pt_cache_t *)cache;
    delete pt_cache->cache_data->bb_node_cache;
    delete pt_cache->cache_data->splay_node_cache;
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
bb_instrument_msg_create(bb_key_t bb_key, slot_t slot_max, state_t bb_end_state)
{
    bb_instrument_msg_t *bb_msg = (bb_instrument_msg_t *)dr_global_alloc(sizeof(bb_instrument_msg_t));
    bb_msg->first = bb_msg->end = NULL;
    bb_msg->number = 0;
    bb_msg->slot_max = slot_max;
    bb_msg->bb_key = bb_key;
    bb_msg->bb_end_state = bb_end_state;
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
instrument_before_bb_first_instr(bb_key_t new_key, slot_t num, state_t end_state)
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    IF_DRCCTLIB_DEBUG(dr_fprintf(pt->log_file, "pre bb key %d ->",
                                 pt->cur_bb_node->key);)
    context_handle_t new_caller_ctxt = 0;

    if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_THREAD_ROOT_VIRTUAL)) {
        new_caller_ctxt =
            pt->root_bb_node->child_ctxt_start_idx + THREAD_ROOT_SHARDED_CALLEE_INDEX;
    } else if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_CALL_DIRECT) ||
               instr_state_contain(pt->pre_instr_state, INSTR_STATE_CALL_IN_DIRECT)) {
        new_caller_ctxt = pt->cur_bb_node->child_ctxt_start_idx + pt->cur_bb_node->max_slots - 1;
    } else if (instr_state_contain(pt->pre_instr_state, INSTR_STATE_RETURN)) {
        if (pt->cur_bb_node->caller_ctxt_hndl !=
            pt->root_bb_node->child_ctxt_start_idx + THREAD_ROOT_SHARDED_CALLEE_INDEX) {
            new_caller_ctxt = ctxt_hndl_to_ip_node(pt->cur_bb_node->caller_ctxt_hndl)
                                  ->parent_bb_node->caller_ctxt_hndl;
        } else {
            new_caller_ctxt = pt->cur_bb_node->caller_ctxt_hndl;
        }
    } else {
        new_caller_ctxt = pt->cur_bb_node->caller_ctxt_hndl;
    }
    
#ifdef TEST_TREE_SIZE
    int32_t o_num = 0;
    splay_node_t *new_root = splay_tree_update_test(
        ctxt_hndl_to_ip_node(new_caller_ctxt)->callee_splay_tree_root,
        (splay_node_key_t)new_key, pt->dummy_splay_node, pt->next_splay_node, &o_num);
    ctxt_hndl_to_ip_node(new_caller_ctxt)->global_search_times += o_num;
#else
    splay_node_t *new_root = splay_tree_update(
        ctxt_hndl_to_ip_node(new_caller_ctxt)->callee_splay_tree_root,
        (splay_node_key_t)new_key, pt->dummy_splay_node, pt->next_splay_node);
#endif
    if (new_root->payload == NULL) {
        new_root->payload =
            (void *)bb_node_create(pt->bb_node_cache, new_key, new_caller_ctxt, num);
        pt->next_splay_node = pt->splay_node_cache->get_next_object();
#ifdef TEST_TREE_SIZE
        pt->real_node_number ++;
        ctxt_hndl_to_ip_node(new_caller_ctxt)->children_number ++;
#endif
    }
    ctxt_hndl_to_ip_node(new_caller_ctxt)->callee_splay_tree_root = new_root;
    pt->cur_bb_node = (cct_bb_node_t *)(new_root->payload);
    pt->cur_bb_child_ctxt_start_idx = pt->cur_bb_node->child_ctxt_start_idx;
    pt->pre_instr_state = end_state;
    if (client_cb.func_insert_bb_start != NULL) {
        (*client_cb.func_insert_bb_start)(client_cb.insert_data);
    }
    IF_DRCCTLIB_DEBUG(dr_fprintf(pt->log_file, "cur bb key %d \n", pt->cur_bb_node->key);)
}

static inline void
instrument_before_every_instr_meta_instr(void *drcontext, instr_instrument_msg_t *instrument_msg)
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
    
    opnd_t opnd_mem_pis = OPND_CREATE_PT_CUR_STATE(
            reg_tls, offsetof(per_thread_t, cur_state));
    opnd_t opnd_imm_pis = OPND_CREATE_STATE(state_flag);
    // pt->cur_state = state_flag;
#ifdef ARM_CCTLIB
    MINSERT(bb, instr,
            XINST_CREATE_load_int(drcontext, opnd_reg_store_imm, opnd_imm_pis));
    MINSERT(bb, instr,
            XINST_CREATE_store(drcontext, opnd_mem_pis, opnd_reg_store_imm));
#else
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_pis, opnd_imm_pis));
#endif


    opnd_t opnd_mem_cs =
            OPND_CREATE_PT_CUR_SLOT(reg_tls, offsetof(per_thread_t, cur_slot));
    opnd_t opnd_imm_cs = OPND_CREATE_SLOT(slot);
    // pt->cur_slot = slot;
#ifdef ARM_CCTLIB
    MINSERT(bb, instr,
            XINST_CREATE_load_int(drcontext, opnd_reg_store_imm, opnd_imm_cs));
    MINSERT(bb, instr,
            XINST_CREATE_store(drcontext, opnd_mem_cs, opnd_reg_store_imm));
#else
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_cs, opnd_imm_cs));
#endif

#ifdef ARM_CCTLIB
    if (drreg_unreserve_register(drcontext, bb, instr, reg_store_imm) !=
        DRREG_SUCCESS) {
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
instrument_before_every_instr_debug_clean_call(slot_t slot, state_t state)
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    pt->cur_slot = slot;
    pt->cur_state = state;
}
#endif

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
                drcontext, bb, instr, (void *)instrument_before_bb_first_instr, false, 3,
                OPND_CREATE_BB_KEY(bb_msg->bb_key), OPND_CREATE_SLOT(bb_msg->slot_max),
                OPND_CREATE_STATE(bb_msg->bb_end_state));
        } else {
            if((global_flags & DRCCTLIB_CACHE_EXCEPTION) != 0) {
                instrument_before_every_instr_meta_instr(drcontext, instrument_msg);
            }
            IF_DRCCTLIB_DEBUG(dr_insert_clean_call(
                                  drcontext, bb, instr,
                                  (void *)instrument_before_every_instr_debug_clean_call,
                                  false, 2, OPND_CREATE_SLOT(instrument_msg->slot), OPND_CREATE_STATE(instrument_msg->state));)
            instr_instrument_client_cb(drcontext, instrument_msg);
        }
#else
        if (instrument_msg->slot == 0) {
            dr_insert_clean_call(
                drcontext, bb, instr, (void *)instrument_before_bb_first_instr, false, 3,
                OPND_CREATE_BB_KEY(bb_msg->bb_key), OPND_CREATE_SLOT(bb_msg->slot_max),
                OPND_CREATE_STATE(bb_msg->bb_end_state));
        }
        if((global_flags & DRCCTLIB_CACHE_EXCEPTION) != 0) {
            instrument_before_every_instr_meta_instr(drcontext, instrument_msg);
        }
        IF_DRCCTLIB_DEBUG(
            dr_insert_clean_call(drcontext, bb, instr,
                                 (void *)instrument_before_every_instr_debug_clean_call,
                                 false, 2, OPND_CREATE_SLOT(instrument_msg->slot), OPND_CREATE_STATE(instrument_msg->state));)
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

#ifdef ARM_CCTLIB
    if(instr_is_exclusive_store(first_instr)) {
        
        *user_data = NULL;
        return DR_EMIT_DEFAULT;
    }
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
    state_t bb_end_state = 0;
    instr_state_init(instrlist_last_app(bb), &bb_end_state);
    bb_instrument_msg_t *bb_msg =
        bb_instrument_msg_create(bb_key, uninterested_bb ? 1 : interest_instr_num, bb_end_state);

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
#ifdef ARM_CCTLIB
                if (keep_insert_instrument) {
#endif
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
                    bb_instrument_msg_add(
                        bb_msg,
                        instr_instrument_msg_create(bb, instr, interest_start, slot,
                                                    instr_state_flag));
                    slot++;
#ifdef ARM_CCTLIB
                    bb_msg->slot_max = slot;
                }
                if (instr_is_exclusive_load(instr)) {
                    keep_insert_instrument = false;
                }
                if (instr_is_exclusive_store(instr)) {
                    keep_insert_instrument = true;
                }
#endif          
            }
        }
    }
    if (bb_msg->number == 0) {
        bb_instrument_msg_delete(bb_msg);
        *user_data = NULL;
    } else {
        *user_data = (void*)bb_msg;
    }
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
    // DRCCTLIB_PRINTF("thread %d init", id);
}

static void
drcctlib_event_thread_end(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    IF_DRCCTLIB_DEBUG(dr_close_file(pt->log_file);)
#ifdef TEST_TREE_SIZE
    dr_mutex_lock(test_lock);
    real_node_number += pt->real_node_number;
    dr_mutex_unlock(test_lock);
#endif
    pt_cache_t *pt_cache = (pt_cache_t *)hashtable_lookup(&global_pt_cache_table,
                                                          (void *)(ptr_int_t)(pt->id));
    pt_cache->cache_data = (per_thread_t *)dr_global_alloc(sizeof(per_thread_t));
    memcpy(pt_cache->cache_data, pt_cache->active_data, sizeof(per_thread_t));
    pt_cache->dead = true;
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
    // DRCCTLIB_PRINTF("thread %d end", pt_cache->cache_data->id);
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

    for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr;) {
        
        data_handle_t *status =
            global_shadow_memory->GetOrCreateShadowAddress((size_t)curAddr);
        int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)curAddr);

        for (int i = 0; (i < maxBytesInThisPage) && curAddr < endAddr;
             i++, curAddr ++) {
            status[i] = *initializer;
        }
    }
}

// static void
// capture_mmap_size(void *wrapcxt, void **user_data)
// {
//     // Remember the CCT node and the allocation size
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 1);
//     // DRCCTLIB_PRINTF("capture_mmap_size %lu", pt->dmem_alloc_size);
//     pt->dmem_alloc_ctxt_hndl =
//         pt->cur_bb_node->child_ctxt_start_idx;
// }

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
compute_static_var(const module_data_t *info)
{   
    // DRCCTLIB_PRINTF("compute_static_var %s", info->full_path);
    file_t fd = dr_open_file(info->full_path, DR_FILE_READ);
    uint64 file_size;
    if (fd == INVALID_FILE) {
        DRCCTLIB_PRINTF("------ unable to open %s", info->full_path);
        return;
    }
    if (!dr_file_size(fd, &file_size)) {
        DRCCTLIB_PRINTF("------ unable to get file size %s", info->full_path);
        return;
    }
    size_t map_size = file_size;
    void *map_base =
        dr_map_file(fd, &map_size, 0, NULL, DR_MEMPROT_READ, DR_MAP_PRIVATE);
    /* map_size can be larger than file_size */
    if (map_base== NULL || map_size < file_size) {
        DRCCTLIB_PRINTF("------ unable to map %s", info->full_path);
        return;
    }
    // DRCCTLIB_PRINTF("------ success map %s", info->full_path);
    // in memory
    Elf *elf = elf_memory((char *)map_base, map_size); // Initialize 'elf' pointer to our file descriptor
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
            // DRCCTLIB_PRINTF("STATIC_OBJECT %s %d", sym_name, (uint32_t)syms[i].st_size);
            init_shadow_memory_space((void *)((uint64_t)(info->start) + syms[i].st_value),
                                        (uint32_t)syms[i].st_size, &data_hndl);
        }
    }
    dr_unmap_file(map_base, map_size);
    dr_close_file(fd);
    // DRCCTLIB_PRINTF("finish compute_static_var %s", info->full_path);
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

#define ATOM_ADD_MODULE_KEY(origin) dr_atomic_add32_return_sum(&origin, 1)
#define MODULE_KEY_START 2
static inline int32_t
bb_get_module_key()
{
    static int32_t global_module_next_key = MODULE_KEY_START;
    int32_t key = ATOM_ADD_MODULE_KEY(global_module_next_key);
    return key - 1;
}

static void
drcctlib_event_module_load_analysis(void *drcontext, const module_data_t *info, bool loaded)
{
    if((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        // static analysis
        compute_static_var(info);
        // dynamic analysis
        // insert_func_instrument_by_drwap(info, FUNC_NAME_MMAP, capture_mmap_size,
        //                                             capture_malloc_pointer);
        insert_func_instrument_by_drwap(info, FUNC_NAME_MALLOC, capture_malloc_size,
                                                    capture_malloc_pointer);
        insert_func_instrument_by_drwap(info, FUNC_NAME_CALLOC, capture_calloc_size,
                                                    capture_malloc_pointer);
        insert_func_instrument_by_drwap(info, FUNC_NAME_REALLOC, capture_realloc_size,
                                                    capture_malloc_pointer);
        insert_func_instrument_by_drwap(info, FUNC_NAME_FREE, capture_free, NULL);
    }
    if((global_flags & DRCCTLIB_SAVE_HPCTOOLKIT_FILE) != 0) {
        dr_mutex_lock(module_data_lock);
        void* offline_data = hashtable_lookup(&global_module_data_table, (void *)info->start);
        if (offline_data == NULL) {
            offline_data = (void *)offline_module_data_create(info);
            hashtable_add(&global_module_data_table, (void *)(ptr_int_t)info->start, offline_data);
        }
        dr_mutex_unlock(module_data_lock);
    }
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
    global_ip_node_buff = (cct_ip_node_t *)dr_raw_mem_alloc(
        CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t),
        DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (global_ip_node_buff == NULL) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: dr_raw_mem_alloc fail global_ip_node_buff");
    } else {
        init_progress_root_ip_node();
    }
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        global_string_pool = (char *)dr_raw_mem_alloc(
            STRING_POOL_NODES_MAX * sizeof(char), 
            DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
        if (global_string_pool == NULL) {
            DRCCTLIB_EXIT_PROCESS("init_global_buff error: dr_raw_mem_alloc fail global_string_pool");
        }
    }

    global_bb_node_cache = new memory_cache_t<cct_bb_node_t>();
    global_splay_node_cache = new memory_cache_t<splay_node_t>();
    if (!global_bb_node_cache->init(CONTEXT_HANDLE_MAX/20, 1000, 20)) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: global_bb_node_cache");
    }
    if (!global_splay_node_cache->init(CONTEXT_HANDLE_MAX/20, 1000, 20)) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: global_splay_node_cache");
    }
}

static inline void
free_global_buff()
{
    dr_raw_mem_free(global_ip_node_buff, CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t));
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        dr_raw_mem_free(global_string_pool, STRING_POOL_NODES_MAX * sizeof(char));
    }

    delete global_bb_node_cache;
    delete global_splay_node_cache;
}

static inline void
create_global_locks()
{
    bb_shadow_lock = dr_mutex_create();
    module_data_lock = dr_mutex_create();
    bb_node_cache_lock = dr_mutex_create();
    splay_node_cache_lock = dr_mutex_create();
#ifdef TEST_TREE_SIZE
    test_lock = dr_mutex_create();
#endif    
}

static inline void
destroy_global_locks()
{
    dr_mutex_destroy(bb_shadow_lock);
    dr_mutex_destroy(module_data_lock);
    dr_mutex_destroy(bb_node_cache_lock);
    dr_mutex_destroy(splay_node_cache_lock);
#ifdef TEST_TREE_SIZE
    dr_mutex_destroy(test_lock);
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
    if(log_file != INVALID_FILE) {
        dr_fprintf(log_file, "\nTotalCallPaths = %" PRIu32, global_ip_node_buff_idle_idx);
        // Peak resource usage
        dr_fprintf(log_file, "\nPeakRSS = %zu", get_peak_rss());
    }
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
                            IF_ARM_CCTLIB_ELSE(3, 2)/*max slots needed*/,
                            false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drreg");
        return false;
    }

    disassemble_set_syntax(DR_DISASM_DRCCTLIB);

    
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
        if (elf_version(EV_CURRENT) == EV_NONE) {
            DRCCTLIB_PRINTF("INIT DATA CENTRIC FAIL: Elf Library is out of date!");
            global_flags -= DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE;
        } else {
            global_shadow_memory = new ConcurrentShadowMemory<data_handle_t>();
        }
    }
    if((global_flags & DRCCTLIB_SAVE_HPCTOOLKIT_FILE) != 0) {
        hashtable_init_ex(&global_module_data_table, OFFLINE_MODULE_DATA_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!strdup*/, false /*!synch*/, offline_module_data_free, NULL, NULL);
    }
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0 ||
        (global_flags & DRCCTLIB_SAVE_HPCTOOLKIT_FILE) != 0) {
        drmgr_register_module_load_event(drcctlib_event_module_load_analysis);
        drmgr_register_module_unload_event(drcctlib_event_module_unload_analysis);
    }
    init_global_buff();

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

    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)){
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_calloc fail");
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
#ifdef TEST_TREE_SIZE
    uint64_t global_search_time = 0;
    for(int32_t i = 0; i < global_ip_node_buff_idle_idx; i++) {
        global_search_time += ctxt_hndl_to_ip_node(i)->global_search_times;
    }
    DRCCTLIB_PRINTF("+++++++++++++++real_node_number %llu global_search_time %llu", real_node_number, global_search_time);
#endif
    
    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_PRINTF("WARNING: drcctlib dr_raw_tls_cfree fail");
    }
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
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0 ||
        (global_flags & DRCCTLIB_SAVE_HPCTOOLKIT_FILE) != 0) {
        drmgr_unregister_module_load_event(drcctlib_event_module_load_analysis);
        drmgr_unregister_module_unload_event(drcctlib_event_module_unload_analysis);
    }
    if ((global_flags & DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE) != 0) {
        delete global_shadow_memory;
    }
    if ((global_flags & DRCCTLIB_SAVE_HPCTOOLKIT_FILE) != 0) {
        hashtable_delete(&global_module_data_table);
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
drcctlib_get_per_thread_data_id()
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    return (int)(pt->id);
}

DR_EXPORT
context_handle_t
drcctlib_get_context_handle(int32_t slot)
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    return (context_handle_t)(pt->cur_bb_child_ctxt_start_idx + slot);
}

DR_EXPORT
context_handle_t
drcctlib_get_bb_start_context_handle()
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    return (context_handle_t)(pt->cur_bb_child_ctxt_start_idx);
}

#ifdef CCTLIB_64
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM64
#else
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM32
#endif

DR_EXPORT
void
drcctlib_get_context_handle_in_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                   int32_t slot, reg_id_t store_reg, reg_id_t addr_reg)
{
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, addr_reg);
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
    MINSERT(ilist, where, 
            XINST_CREATE_add(drcontext, opnd_create_reg(store_reg), 
                OPND_CREATE_SLOT(slot)));
#endif
    
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
drcctlib_print_ctxt_hndl_msg(file_t file, context_handle_t ctxt_hndl, bool print_asm,
                             bool print_file_path)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_print_ctxt_hndl_msg: !ctxt_hndl_is_valid");
    }

    if(file == INVALID_FILE) {
        file = log_file;
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
drcctlib_print_full_cct(file_t file, context_handle_t ctxt_hndl, bool print_asm, bool print_file_path,
                        int max_depth)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("drcctlib_print_full_cct: !ctxt_hndl_is_valid");
    }
    bool print_all = false;
    if(max_depth == 0) {
        print_all = true;
    }
    if(file == INVALID_FILE) {
        file = log_file;
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
    bool get_all = false;
    if(max_depth == 0) {
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

DR_EXPORT
bool
has_same_call_path(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2)
{
    if(ctxt_hndl1 == ctxt_hndl2) {
        return true;
    }
    if (ctxt_hndl1 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE ||
        ctxt_hndl2 == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        return false;
    }
    context_handle_t p1 =
        ctxt_hndl_to_ip_node(ctxt_hndl1)->parent_bb_node->caller_ctxt_hndl;
    context_handle_t p2 =
        ctxt_hndl_to_ip_node(ctxt_hndl2)->parent_bb_node->caller_ctxt_hndl;
    if(has_same_call_path(p1, p2)){
        app_pc pc1 = drcctlib_get_pc(ctxt_hndl1);
        app_pc pc2 = drcctlib_get_pc(ctxt_hndl2);
        if(pc1 == pc2) {
            return true;
        }
    }
    return false;
}

// API to get the handle for a data object
DR_EXPORT
data_handle_t
drcctlib_get_data_hndl(void *drcontext, void *address)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // if it is a stack location, set so and return
    if (pt->stack_unlimited && address > pt->stack_end && address < pt->stack_base) {
        data_handle_t data_hndl;
        data_hndl.object_type = STACK_OBJECT;
        return data_hndl;
    }
    data_handle_t *ptr =
        global_shadow_memory->GetOrCreateShadowAddress((size_t)(uint64_t)address);
    if(ptr != NULL) {
        return *ptr;
    } else {
        data_handle_t data_hndl;
        data_hndl.object_type = UNKNOWN_OBJECT;
        return data_hndl;
    }
}

DR_EXPORT
data_handle_t*
drcctlib_get_data_hndl_runtime(void *drcontext, void *address)
{
    data_handle_t *ptr = 
        global_shadow_memory->GetOrCreateShadowAddress((size_t)(uint64_t)address);
    return ptr;
}

DR_EXPORT
char *
drcctlib_get_str_from_strpool(int index)
{
    return global_string_pool+ index;
}

/* ==================================drcctlib ext for hpctoolkit===================================*/
static inline app_pc
get_ip_from_ctxt(context_handle_t ctxt)
{
    cct_bb_node_t *bb = ctxt_hndl_to_ip_node(ctxt)->parent_bb_node;
    bb_shadow_t *bb_shadow = (bb_shadow_t *)hashtable_lookup(
        &global_bb_shadow_table, (void *)(ptr_int_t)(bb->key));
    slot_t slot = ctxt - bb->child_ctxt_start_idx;
    return bb_shadow->ip_shadow[slot];
}

static inline app_pc
get_ip_from_ip_node(cct_ip_node_t* ip_node)
{
    context_handle_t ctxt = ip_node_to_ctxt_hndl(ip_node);
    cct_bb_node_t *bb = ip_node->parent_bb_node;
    bb_shadow_t *bb_shadow = (bb_shadow_t *)hashtable_lookup(&global_bb_shadow_table,
                                                          (void *)(ptr_int_t)(bb->key));
    slot_t slot = ctxt - bb->child_ctxt_start_idx;
    return bb_shadow->ip_shadow[slot];
}

static void
get_full_calling_ip_vector(context_handle_t ctxt_hndl, vector<app_pc> &list)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("get_full_calling_ip_vector !ctxt_hndl_is_valid");
    }
    context_handle_t cur_ctxt = ctxt_hndl;
    while (true) {
        cct_bb_node_t *parent_bb = ctxt_hndl_to_ip_node(cur_ctxt)->parent_bb_node;
        if(parent_bb->key == THREAD_ROOT_BB_SHARED_BB_KEY) {
            break;
        }
        slot_t slot = cur_ctxt - parent_bb->child_ctxt_start_idx;
        bb_shadow_t *shadow = (bb_shadow_t *)hashtable_lookup(&global_bb_shadow_table,
                                                          (void *)(ptr_int_t)(parent_bb->key));
        app_pc ip = shadow->ip_shadow[slot];
        list.push_back(ip);

        cur_ctxt = parent_bb->caller_ctxt_hndl;
    }
}

/* ==================================hpcviewer support===================================*/
/*
 * This support is added by Xiaonan Hu and tailored by Xu Liu at College of William and Mary.
 */
     
// necessary macros
#define HASH_PRIME 2001001003
#define HASH_GEN   4001
#define SPINLOCK_UNLOCKED_VALUE (0L)
#define SPINLOCK_LOCKED_VALUE (1L)
#define OSUtil_hostid_NULL (-1)
#define INITIALIZE_SPINLOCK(x) { .thelock = (x) }
#define SPINLOCK_UNLOCKED INITIALIZE_SPINLOCK(SPINLOCK_UNLOCKED_VALUE)
#define SPINLOCK_LOCKED INITIALIZE_SPINLOCK(SPINLOCK_LOCKED_VALUE)

#define HPCRUN_FMT_NV_prog       "program-name"
#define HPCRUN_FMT_NV_progPath   "program-path"
#define HPCRUN_FMT_NV_envPath    "env-path"
#define HPCRUN_FMT_NV_jobId      "job-id"
#define HPCRUN_FMT_NV_mpiRank    "mpi-id"
#define HPCRUN_FMT_NV_tid        "thread-id"
#define HPCRUN_FMT_NV_hostid     "host-id"
#define HPCRUN_FMT_NV_pid        "process-id"
#define HPCRUN_SAMPLE_PROB       "HPCRUN_PROCESS_FRACTION"
#define HPCRUN_FMT_NV_traceMinTime "trace-min-time"
#define HPCRUN_FMT_NV_traceMaxTime "trace-max-time"

#define FILENAME_TEMPLATE "%s/%s-%06u-%03d-%08lx-%u-%d.%s"
#define TEMPORARY "%s/%s-"
#define RANK 0

#define FILES_RANDOM_GEN 4
#define FILES_MAX_GEN 11
#define FILES_EARLY 0x1
#define FILES_LATE 0x2 
#define DEFAULT_PROB 0.1

// *** atomic-op-asm.h && atomic-op-gcc.h ***
#if defined (LL_BODY) && defined(SC_BODY)

#define read_modify_write(type, addr, expn, result) {  \
  type __new;    \
  do {           \
    result = (type) load_linked((unsigned long*)addr); \
    __new = expn;\
} while (!store_conditional((unsigned long*)addr, (unsigned long) __new)); \
}
#else

#define read_modify_write(type, addr, expn, result) {            \
  type __new;                                                    \
  do {                                                           \
    result = *addr;                                              \
    __new = expn;                                                \
  } while (compare_and_swap(addr, result, __new) != result);     \
}
#endif

#define compare_and_swap(addr, oldval, newval) \
    __sync_val_compare_and_swap(addr, oldval, newval)

// ***********************

#define MAX_METRICS (10)
#define MAX_LEN (128)
typedef struct _hpc_format_global_t {
    bool metric_cct;
    int metric_num;
    char metric_name_arry[MAX_METRICS][MAX_LEN];
    hpcviewer_format_ip_node_t *gHPCRunCCTRoot;
    uint64_t nodeCount;
    string dirName;
    string filename;
} hpc_format_global_t;
static hpc_format_global_t global_hpc_fmt_data;


static inline offline_module_data_t *
offline_module_data_create(const module_data_t *info){
    offline_module_data_t *off_module_data = (offline_module_data_t *)dr_global_alloc(sizeof(offline_module_data_t));
    sprintf(off_module_data->path, "%s", info->full_path);
    off_module_data->start = info->start;
    off_module_data->end = info->end;
    if(strcmp(dr_module_preferred_name(info), global_hpc_fmt_data.filename.c_str())== 0){
#ifdef ARM_CCTLIB
        off_module_data->start = 0;
#endif
        off_module_data->app = true;
        off_module_data->id = 1;
    } else {
        off_module_data->app = false;
        off_module_data->id = bb_get_module_key();
    }
    return off_module_data;
}

static inline void
offline_module_data_free(void *data){
    offline_module_data_t *mdata = (offline_module_data_t *)data;
    dr_global_free(mdata, sizeof(offline_module_data_t));
}



// create a new node type to substitute cct_ip_node_t and cct_bb_node_t
struct hpcviewer_format_ip_node_t {
    int32_t parentID;
    hpcviewer_format_ip_node_t* parentIPNode;

    int32_t ID;
    app_pc IPAddress;
    uint64_t *metricVal;
    
	vector<hpcviewer_format_ip_node_t *> childIPNodes;
};


typedef enum {
  MetricFlags_Ty_NULL = 0,
  MetricFlags_Ty_Raw,
  MetricFlags_Ty_Final,
  MetricFlags_Ty_Derived
} MetricFlags_Ty_t;


typedef enum {
  MetricFlags_ValTy_NULL = 0,
  MetricFlags_ValTy_Incl,
  MetricFlags_ValTy_Excl
} MetricFlags_ValTy_t;


typedef enum {
  MetricFlags_ValFmt_NULL = 0,
  MetricFlags_ValFmt_Int,
  MetricFlags_ValFmt_Real,
} MetricFlags_ValFmt_t;


typedef struct epoch_flags_bitfield {
  bool isLogicalUnwind : 1;
  uint64_t unused      : 63;
} epoch_flags_bitfield;


typedef union epoch_flags_t {
  epoch_flags_bitfield fields;
  uint64_t             bits; // for reading/writing
} epoch_flags_t;


typedef struct metric_desc_properties_t {
  unsigned time:1;
  unsigned cycles:1;
} metric_desc_properties_t;


typedef struct hpcrun_metricFlags_fields {
  MetricFlags_Ty_t      ty    : 8;
  MetricFlags_ValTy_t   valTy : 8;
  MetricFlags_ValFmt_t  valFmt: 8;
  uint8_t               unused0;
  uint16_t              partner;
  uint8_t  /*bool*/     show;
  uint8_t /*bool*/      showPercent;
  uint64_t              unused1;
} hpcrun_metricFlags_fields;


typedef union hpcrun_metricFlags_t {
  hpcrun_metricFlags_fields fields;
  uint8_t bits[2 * 8]; // for reading/writing
  uint64_t bits_big[2]; // for easy initialization
} hpcrun_metricFlags_t;

typedef struct metric_desc_t {
  char* name;
  char* description;
  hpcrun_metricFlags_t flags;
  uint64_t period;
  metric_desc_properties_t properties;
  char* formula;
  char* format;
  bool is_frequency_metric;
} metric_desc_t;


typedef struct spinlock_t {
  volatile long thelock;
} spinlock_t;


struct fileid {
  int done;
  long host;
  int gen;
};


extern const metric_desc_t metricDesc_NULL;

const metric_desc_t metricDesc_NULL = {
  NULL, // name
  NULL, // description
  MetricFlags_Ty_NULL,
  MetricFlags_ValTy_NULL,
  MetricFlags_ValFmt_NULL,
  0, // fields.unused0
  0, // fields.partner
  (uint8_t)true, // fields.show
  (uint8_t)true, // fields.showPercent
  0, // unused 1
  0, // period
  0, // properties.time
  0, // properties.cycles
  NULL,
  NULL,
};



extern const hpcrun_metricFlags_t hpcrun_metricFlags_NULL;

const hpcrun_metricFlags_t hpcrun_metricFlags_NULL = {
   MetricFlags_Ty_NULL,
   MetricFlags_ValTy_NULL,
   MetricFlags_ValFmt_NULL,
   0, // fields.unused0
   0, // fields.partner
   (uint8_t)true, // fields.show
   (uint8_t)true, // fields.showPercent
   0, // unused 1
};


static epoch_flags_t epoch_flags = {
  .bits = 0x0000000000000000
};

static const uint64_t default_measurement_granularity = 1;
static const uint32_t default_ra_to_callsite_distance = 1;

// ***************** file ************************
static spinlock_t files_lock = SPINLOCK_UNLOCKED;
static pid_t mypid = 0;
static struct fileid earlyid;
static struct fileid lateid;
static int log_done = 0;
static int log_rename_done = 0;
static int log_rename_ret = 0;
// ***********************************************
/*   for HPCViewer output format     */

static int32_t global_fmt_ip_node_start = 0;

// *************************************** format ****************************************
static const char HPCRUN_FMT_Magic[] = "HPCRUN-profile____";
static const int HPCRUN_FMT_MagicLen = (sizeof(HPCRUN_FMT_Magic)-1);
static const char HPCRUN_FMT_Endian[] = "b";
static const int HPCRUN_FMT_EndianLen = (sizeof(HPCRUN_FMT_Endian)-1);
static const char HPCRUN_ProfileFnmSfx[] = "hpcrun";
static const char HPCRUN_FMT_Version[] = "02.00";
static const char HPCRUN_FMT_VersionLen = (sizeof(HPCRUN_FMT_Version)-1);
static const char HPCRUN_FMT_EpochTag[] = "EPOCH___";
static const int HPCRUN_FMT_EpochTagLen = (sizeof(HPCRUN_FMT_EpochTag)-1);
const uint bufSZ = 32; // sufficient to hold a 64-bit integer in base 10
int hpcfmt_str_fwrite(const char* str, FILE* outfs);
int hpcrun_fmt_hdrwrite(FILE* fs);
int hpcrun_fmt_hdr_fwrite(FILE* fs, const char* arg1, const char* arg2);
int hpcrun_open_profile_file(int thread, const char* fileName);
static int hpcrun_open_file(int thread, const char * suffix, int flags, const char* fileName);
int hpcrun_fmt_loadmap_fwrite(FILE* fs);
int hpcrun_fmt_epochHdr_fwrite(FILE* fs, epoch_flags_t flags,
                               uint64_t measurementGranularity, uint32_t raToCallsiteOfst);
static void hpcrun_files_init();
uint OSUtil_pid();
const char* OSUtil_jobid();
long OSUtil_hostid();
void hpcrun_set_metric_info_w_fn(int metric_id, const char* name,
                            MetricFlags_ValFmt_t valFmt, size_t period, FILE* fs);
size_t hpcio_ben_fwrite(uint64_t val, int n, FILE *fs);
size_t hpcio_beX_fwrite(uint8_t val, size_t size, FILE* fs);

// ******************************************************************************************

// ****************Merge splay trees **************************************************
void
tranverseIPs(hpcviewer_format_ip_node_t *curIPNode, splay_node_t *splay_node,
             uint64_t *nodeCount);
hpcviewer_format_ip_node_t *
constructIPNodeFromIP(hpcviewer_format_ip_node_t *parentIP, app_pc address,
                      uint64_t *nodeCount);
hpcviewer_format_ip_node_t *
findSameIP(vector<hpcviewer_format_ip_node_t *> *nodes, cct_ip_node_t *node);
hpcviewer_format_ip_node_t *
findSameIPbyIP(vector<hpcviewer_format_ip_node_t *> nodes, app_pc address);
void
mergeIP(hpcviewer_format_ip_node_t *prev, cct_ip_node_t *cur, uint64_t *nodeCount);
int32_t
get_fmt_ip_node_new_id();
// ************************************************************************************

// ****************Print merged splay tree*********************************************
void IPNode_fwrite(hpcviewer_format_ip_node_t* node, FILE* fs);
void tranverseNewCCT(vector<hpcviewer_format_ip_node_t*> *nodes, FILE* fs);
// ************************************************************************************

static int unsigned long
fetch_and_store(volatile long *addr, long newval)
{
    long result;
    read_modify_write(long, addr, newval, result);
    return result;
}

static inline void
spinlock_unlock(spinlock_t *l)
{
    l->thelock = SPINLOCK_UNLOCKED_VALUE;
}

static inline void
spinlock_lock(spinlock_t *l)
{
    /* test-and-test-and-set lock*/
    for (;;) {
        while (l->thelock != SPINLOCK_UNLOCKED_VALUE)
            ;

        if (fetch_and_store(&l->thelock, SPINLOCK_LOCKED_VALUE) ==
            SPINLOCK_UNLOCKED_VALUE) {
            break;
        }
    }
}

uint
OSUtil_pid()
{
    pid_t pid = getpid();
    return (uint)pid;
}

const char *
OSUtil_jobid()
{
    char *jid = NULL;

    // Cobalt
    jid = getenv("COBALT_JOB_ID");
    if (jid)
        return jid;

    // PBS
    jid = getenv("PBS_JOB_ID");
    if (jid)
        return jid;

    // SLURM
    jid = getenv("SLURM_JOB_ID");
    if (jid)
        return jid;

    // Sun Grid Engine
    jid = getenv("JOB_ID");
    if (jid)
        return jid;

    return jid;
}

long
OSUtil_hostid()
{
    // static long hostid = OSUtil_hostid_NULL;
    // if (hostid == OSUtil_hostid_NULL) {
    // //     DRCCTLIB_PRINTF("if (hostid == OSUtil_hostid_NULL) {");
    // //     // gethostid returns a 32-bit id. treat it as unsigned to prevent useless sign
    // //     // extension
    //     hostid = (uint32_t)gethostid();
    // //     DRCCTLIB_PRINTF("hostid = (uint32_t)gethostid();");
    // }
    // SYS_osf_gethostid();
    
    return 0xbad;
}

size_t
hpcio_ben_fwrite(uint64_t val, int n, FILE *fs)
{
    size_t num_write = 0;
    for (int shift = 8 * (n - 1); shift >= 0; shift -= 8) {
        int c = fputc(((val >> shift) & 0xff), fs);
        if (c == EOF) {
            break;
        }
        num_write++;
    }
    return num_write;
}

size_t
hpcio_beX_fwrite(uint8_t *val, size_t size, FILE *fs)
{
    size_t num_write = 0;
    for (uint i = 0; i < size; ++i) {
        int c = fputc(val[i], fs);
        if (c == EOF)
            break;
        num_write++;
    }
    return num_write;
}

int
hpcio_fclose(FILE *fs)
{
    if (fs && fclose(fs) == EOF) {
        return 1;
    }
    return 0;
}

static inline int
hpcfmt_int2_fwrite(uint16_t val, FILE *outfs)
{
    if (sizeof(uint16_t) != hpcio_ben_fwrite(val, 2, outfs)) {
        return 0;
    }
    return 1;
}

static inline int
hpcfmt_int4_fwrite(uint32_t val, FILE *outfs)
{
    if (sizeof(uint32_t) != hpcio_ben_fwrite(val, 4, outfs)) {
        return 0;
    }
    return 1;
}

static inline int
hpcfmt_int8_fwrite(uint64_t val, FILE *outfs)
{
    if (sizeof(uint64_t) != hpcio_ben_fwrite(val, 8, outfs)) {
        return 0;
    }
    return 1;
}

static inline int
hpcfmt_intX_fwrite(uint8_t *val, size_t size, FILE *outfs)
{
    if (size != hpcio_beX_fwrite(val, size, outfs)) {
        return 0;
    }
    return 1;
}

int
hpcfmt_str_fwrite(const char *str, FILE *outfs)
{
    unsigned int i;
    uint32_t len = (str) ? strlen(str) : 0;
    hpcfmt_int4_fwrite(len, outfs);

    for (i = 0; i < len; i++) {
        int c = fputc(str[i], outfs);

        if (c == EOF)
            return 0;
    }

    return 1;
}

static void
hpcrun_files_init(void)
{
    pid_t cur_pid = getpid();
    if (mypid != cur_pid) {
        mypid = cur_pid;
        earlyid.done = 0;
        earlyid.host = OSUtil_hostid();
        earlyid.gen = 0;
        lateid = earlyid;
        log_done = 0;
        log_rename_done = 0;
        log_rename_ret = 0;
    }
}

// Replace "id" with the next unique id if possible. Normally, (hostid, pid, gen)
// works after one or two iteration. To be extra robust (eg, hostid is not unique),
// at some point, give up and pick a random hostid.
// Returns: 0 on success, else -1 on failure.
static int
hpcrun_files_next_id(struct fileid *id)
{
    struct timeval tv;
    int fd;

    if (id->done || id->gen >= FILES_MAX_GEN) {
        // failure, out of options
        return -1;
    }

    id->gen++;
    if (id->gen >= FILES_RANDOM_GEN) {
        // give up and use a random host id
        fd = open("/dev/urandom", O_RDONLY);
        dr_printf("Inside hpcrun_files_next_id fd = %d\n", fd);
        if (fd >= 0) {
            ssize_t read_size = read(fd, &id->host, sizeof(id->host));
            if(read_size == -1) {
                dr_printf("hpcrun_files_next_id read_size == -1\n");
            }
            close(fd);
        }
        gettimeofday(&tv, NULL);
        id->host += (tv.tv_sec << 20) + tv.tv_usec;
        id->host &= 0x00ffffffff;
    }
    return 0;
}

static int
hpcrun_open_file(int thread, const char *suffix, int flags, const char *fileName)
{
    char name[MAXIMUM_PATH];
    struct fileid *id;
    int fd, ret;

    id = (flags & FILES_EARLY) ? &earlyid : &lateid;
    for (;;) {
        errno = 0;
        ret = snprintf(name, MAXIMUM_PATH, FILENAME_TEMPLATE, global_hpc_fmt_data.dirName.c_str(), fileName, RANK,
                       thread, id->host, mypid, id->gen, suffix);

        if (ret >= MAXIMUM_PATH) {
            fd = -1;
            errno = ENAMETOOLONG;
            break;
        }

        fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0644);

        if (fd >= 0) {
            // sucess
            break;
        }

        if (errno != EEXIST || hpcrun_files_next_id(id) != 0) {
            // failure, out of options
            fd = -1;
            break;
        }
    }

    id->done = 1;

    if (flags & FILES_EARLY) {
        // late id starts where early id is chosen
        lateid = earlyid;
        lateid.done = 0;
    }

    if (fd < 0) {
        dr_printf("cctlib_hpcrun: unable to open %s file: '%s': %s", suffix, name,
               strerror(errno));
    }

    return fd;
}

int
hpcrun_open_profile_file(int thread, const char *fileName)
{
    int ret;
    spinlock_lock(&files_lock);
    hpcrun_files_init();
    ret = hpcrun_open_file(thread, HPCRUN_ProfileFnmSfx, FILES_LATE, fileName);
    spinlock_unlock(&files_lock);
    return ret;
}

// Write out the format for metric table. Needs updates
void
hpcrun_set_metric_info_w_fn(int metric_id, const char* name, size_t period, FILE* fs)
{
  // Write out the number of metric table in the program 
  metric_desc_t mdesc = metricDesc_NULL;
  mdesc.flags = hpcrun_metricFlags_NULL;

  for (int i = 0; i < 16; i++) {
     mdesc.flags.bits[i] = (uint8_t) 0x00;
  }

  mdesc.name = (char*) name;
  mdesc.description = (char*) name; // TODO
  mdesc.period = period;
  mdesc.flags.fields.ty        = MetricFlags_Ty_Raw;
  MetricFlags_ValFmt_t valFmt  = (MetricFlags_ValFmt_t) 1;
  mdesc.flags.fields.valFmt    = valFmt;
  mdesc.flags.fields.show      = true;
  mdesc.flags.fields.showPercent  = true; 
  mdesc.formula = NULL;
  mdesc.format = NULL;
  mdesc.is_frequency_metric = 0;

  hpcfmt_str_fwrite(mdesc.name, fs);
  hpcfmt_str_fwrite(mdesc.description, fs);
  hpcfmt_intX_fwrite(mdesc.flags.bits, sizeof(mdesc.flags), fs); // Write metric flags bits for reading/writing
  hpcfmt_int8_fwrite(mdesc.period, fs);
  hpcfmt_str_fwrite(mdesc.formula, fs);
  hpcfmt_str_fwrite(mdesc.format, fs);
  hpcfmt_int2_fwrite(mdesc.is_frequency_metric, fs);
  
  // write auxaliary description to the table.
  // These values are only related to perf, not applicable to cctlib, so set all to 0
  hpcfmt_int2_fwrite(0, fs);
  hpcfmt_int8_fwrite(0, fs);
  hpcfmt_int8_fwrite(0, fs);
}

void 
hpcrun_fmt_module_data_fwrite(void *payload, void *user_data)
{
    offline_module_data_t** print_vector = (offline_module_data_t**)user_data;
    offline_module_data_t* module_data = (offline_module_data_t *)payload;
    print_vector[module_data->id - 1] = module_data;
}

int
hpcrun_fmt_loadmap_fwrite(FILE *fs)
{
    // Write loadmap size
    hpcfmt_int4_fwrite((uint32_t)global_module_data_table.entries, fs); // Write loadmap size
    offline_module_data_t** print_vector = (offline_module_data_t **)dr_global_alloc(global_module_data_table.entries * sizeof(offline_module_data_t*));
    hashtable_apply_to_all_payloads_user_data(&global_module_data_table, hpcrun_fmt_module_data_fwrite, (void *)print_vector);

    for(uint32_t i = 0; i < global_module_data_table.entries; i ++) {
        hpcfmt_int2_fwrite(print_vector[i]->id, fs); // Write loadmap id
        hpcfmt_str_fwrite(print_vector[i]->path, fs); // Write loadmap name
        hpcfmt_int8_fwrite((uint64_t)0, fs);
    }
    dr_global_free(print_vector, global_module_data_table.entries * sizeof(offline_module_data_t*));
    return 0;
}

int
hpcrun_fmt_hdrwrite(FILE *fs)
{
    fwrite(HPCRUN_FMT_Magic, 1, HPCRUN_FMT_MagicLen, fs);
    fwrite(HPCRUN_FMT_Version, 1, HPCRUN_FMT_VersionLen, fs);
    fwrite(HPCRUN_FMT_Endian, 1, HPCRUN_FMT_EndianLen, fs);
    return 1;
}

int
hpcrun_fmt_epochHdr_fwrite(FILE *fs, epoch_flags_t flags, uint64_t measurementGranularity,
                           uint32_t raToCallsiteOfst)
{
    fwrite(HPCRUN_FMT_EpochTag, 1, HPCRUN_FMT_EpochTagLen, fs);
    hpcfmt_int8_fwrite(flags.bits, fs);
    hpcfmt_int8_fwrite(measurementGranularity, fs);
    hpcfmt_int4_fwrite(raToCallsiteOfst, fs);
    hpcfmt_int4_fwrite((uint32_t)1, fs);
    hpcrun_fmt_hdr_fwrite(fs, "TODO:epoch-name", "TODO:epoch-value");
    return 1;
}

int
hpcrun_fmt_hdr_fwrite(FILE *fs, const char *arg1, const char *arg2)
{
    hpcfmt_str_fwrite(arg1, fs);
    hpcfmt_str_fwrite(arg2, fs);
    return 1;
}



int32_t
get_fmt_ip_node_new_id()
{
    int32_t next_fmt_ip_node_id =
        dr_atomic_add32_return_sum(&global_fmt_ip_node_start, 2);
    return next_fmt_ip_node_id;
}

// Construct hpcviewer_format_ip_node_t
hpcviewer_format_ip_node_t *
constructIPNodeFromIP(hpcviewer_format_ip_node_t *parentIP, app_pc address,
                      uint64_t *nodeCount)
{
    hpcviewer_format_ip_node_t *curIP = new hpcviewer_format_ip_node_t();
    curIP->childIPNodes.clear();
    curIP->parentIPNode = parentIP;
    curIP->IPAddress = address;
    if(parentIP != NULL) {
        curIP->parentID = parentIP->ID;
    } else {
        curIP->parentID = 0;
    }
    curIP->ID = get_fmt_ip_node_new_id();
    if(global_hpc_fmt_data.metric_num > 0) {
        curIP->metricVal = new uint64_t[global_hpc_fmt_data.metric_num];
        for (int i = 0; i < global_hpc_fmt_data.metric_num; i++)
            curIP->metricVal[i] = 0;
    }
    if(parentIP != NULL) {
        parentIP->childIPNodes.push_back(curIP);
    }
    (*nodeCount)++;
    return curIP;
}

// Check to see whether another cct_ip_node_t has the same address under the same parent
hpcviewer_format_ip_node_t *
findSameIP(vector<hpcviewer_format_ip_node_t *>* nodes, cct_ip_node_t *node)
{
    app_pc address = get_ip_from_ip_node(node);
    for (size_t i = 0; i < (*nodes).size(); i++) {
        if ((*nodes).at(i)->IPAddress == address)
            return (*nodes).at(i);
    }
    return NULL;
}

hpcviewer_format_ip_node_t *
findSameIPbyIP(vector<hpcviewer_format_ip_node_t *> nodes, app_pc address)
{
    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes.at(i)->IPAddress == address)
            return nodes.at(i);
    }
    return NULL;
}

// Merging the children of two nodes
void
mergeIP(hpcviewer_format_ip_node_t *prev, cct_ip_node_t *cur, uint64_t *nodeCount)
{
    if (cur->callee_splay_tree_root) {
        tranverseIPs(prev, cur->callee_splay_tree_root, nodeCount);
    }
    return;
}

// Inorder tranversal of the previous splay tree and create the new tree
void
tranverseIPs(hpcviewer_format_ip_node_t *curIPNode, splay_node_t *splay_node,
             uint64_t *nodeCount)
{
    if (NULL == splay_node)
        return;

    cct_bb_node_t *bb_node = (cct_bb_node_t *)splay_node->payload;

    tranverseIPs(curIPNode, splay_node->left, nodeCount);

    for (slot_t i = 0; i < bb_node->max_slots; i++) {
        hpcviewer_format_ip_node_t *sameIP = findSameIP(
            &(curIPNode->childIPNodes),
            ctxt_hndl_to_ip_node(bb_node->child_ctxt_start_idx + i));
        if (sameIP) {
            mergeIP(sameIP,
                    ctxt_hndl_to_ip_node(bb_node->child_ctxt_start_idx + i),
                    nodeCount);
        } else {
            cct_ip_node_t *ip_node = ctxt_hndl_to_ip_node(bb_node->child_ctxt_start_idx + i);
            app_pc addr = get_ip_from_ip_node(ip_node);
            hpcviewer_format_ip_node_t * new_fmt_node = constructIPNodeFromIP(curIPNode, addr, nodeCount);
            // curIPNode->childIPNodes.push_back(new_fmt_node);
            if (ip_node->callee_splay_tree_root) {
                if(global_hpc_fmt_data.metric_cct){
                    new_fmt_node->metricVal[0] = 0;
                }
                tranverseIPs(new_fmt_node, ip_node->callee_splay_tree_root, nodeCount);
            } else {
                new_fmt_node->ID = -new_fmt_node->ID;
                if(global_hpc_fmt_data.metric_cct){
                    new_fmt_node->metricVal[0] = 1;
                }
            }
        }
    }
    tranverseIPs(curIPNode, splay_node->right, nodeCount);
    return;
}

// Write out each IP's id, parent id, loadmodule id (1) and address
void
IPNode_fwrite(hpcviewer_format_ip_node_t *node, FILE *fs)
{
    if (node == NULL)
        return;
    hpcfmt_int4_fwrite(node->ID, fs);
    hpcfmt_int4_fwrite(node->parentID, fs);

    // adjust the IPaddress to point to return address of the callsite (internal nodes)
    // for hpcrun requirement
    
    
    if (node->IPAddress == 0) {
        hpcfmt_int2_fwrite(0, fs);
        hpcfmt_int8_fwrite((uint64_t)node->IPAddress, fs);
    } else {
        if (node->ID > 0)
            node->IPAddress++;
        module_data_t *info = dr_lookup_module(node->IPAddress);
        offline_module_data_t *off_module_data = (offline_module_data_t *)hashtable_lookup(
            &global_module_data_table, (void *)info->start);
        hpcfmt_int2_fwrite(off_module_data->id, fs); // Set loadmodule id to 1
        // normalize the IP offset to the beginning of the load module and write out
        hpcfmt_int8_fwrite((uint64_t)(node->IPAddress - off_module_data->start), fs);
        dr_free_module_data(info);
    }

    // this uses .metric field in the hpcviewer_format_ip_node_t, which means we have per
    // cct_ip_node_t metric for this case, by default, we only have one metric
    for (int i = 0; i < global_hpc_fmt_data.metric_num; i++)
        hpcfmt_int8_fwrite(node->metricVal[i], fs);
    return;
}

// Tranverse and print the calling context tree (nodes first)
void
tranverseNewCCT(vector<hpcviewer_format_ip_node_t *> *nodes, FILE *fs)
{

    if ((*nodes).size() == 0)
        return;
    size_t i;

    for (i = 0; i < (*nodes).size(); i++) {
        IPNode_fwrite((*nodes).at(i), fs);
    }
    for (i = 0; i < (*nodes).size(); i++) {

        if ((*nodes).at(i)->childIPNodes.size() != 0) {
            tranverseNewCCT(&((*nodes).at(i)->childIPNodes), fs);
        }
    }
    return;
}

void
hpcrun_insert_path(hpcviewer_format_ip_node_t *root, HPCRunCCT_t *runNode,
                   uint64_t *nodeCount)
{
    if (runNode->ctxt_hndl_list.size() == 0) {
        return;
    }
    hpcviewer_format_ip_node_t *cur = root;
    for(uint32_t i = 0; i < runNode->ctxt_hndl_list.size(); i++){
        context_handle_t cur_hndl = runNode->ctxt_hndl_list[i];
        if(cur_hndl == 0) {
            DRCCTLIB_PRINTF("USE ERROR: HPCRunCCT_t has invalid context_handle_t");
            break;
        }
        vector<app_pc> cur_pc_list;
        get_full_calling_ip_vector(runNode->ctxt_hndl_list[i], cur_pc_list);
        for (int32_t i = cur_pc_list.size() - 1; i >= 0; i--) {
            hpcviewer_format_ip_node_t *tmp = findSameIPbyIP(cur->childIPNodes, cur_pc_list[i]);
            if (!tmp) {
                hpcviewer_format_ip_node_t *nIP =
                    constructIPNodeFromIP(cur, cur_pc_list[i], nodeCount);
                cur = nIP;
            } else {
                cur = tmp;
            }
        }
    }
    for(uint32_t i = 0; i < runNode->metric_list.size(); i++) {
        cur->metricVal[i] += runNode->metric_list[i];
    }
}

void
reset_leaf_node_id(hpcviewer_format_ip_node_t *root)
{
    if(root->childIPNodes.size() == 0) {
        root->ID = - root->ID;
    } else {
        for (uint32_t i = 0; i < root->childIPNodes.size(); i++) {
            reset_leaf_node_id(root->childIPNodes[i]);
        }
    }
}

// Initialize binary file and write hpcrun header
FILE *
lazy_open_data_file(int tID)
{
    const char *fileCharName = global_hpc_fmt_data.filename.c_str();
    int fd = hpcrun_open_profile_file(tID, fileCharName);
    FILE *fs = fdopen(fd, "w");
    
    if (fs == NULL)
        return NULL;
    const char *jobIdStr = OSUtil_jobid();

    if (!jobIdStr)
        jobIdStr = "";

    char mpiRankStr[bufSZ];
    mpiRankStr[0] = '0';
    snprintf(mpiRankStr, bufSZ, "%d", 0);
    char tidStr[bufSZ];
    snprintf(tidStr, bufSZ, "%d", tID);
    char hostidStr[bufSZ];
    snprintf(hostidStr, bufSZ, "%lx", OSUtil_hostid());
    char pidStr[bufSZ];
    snprintf(pidStr, bufSZ, "%u", OSUtil_pid());
    char traceMinTimeStr[bufSZ];
    snprintf(traceMinTimeStr, bufSZ, "%" PRIu64, (unsigned long int)0);
    char traceMaxTimeStr[bufSZ];
    snprintf(traceMaxTimeStr, bufSZ, "%" PRIu64, (unsigned long int)0);
    // ======  file hdr  =====
    hpcrun_fmt_hdrwrite(fs);
    static int global_arg_len = 9;
    hpcfmt_int4_fwrite(global_arg_len, fs);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_prog, fileCharName);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_progPath, global_hpc_fmt_data.filename.c_str());
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_envPath, getenv("PATH"));
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_jobId, jobIdStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_tid, tidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_hostid, hostidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_pid, pidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_traceMinTime, traceMinTimeStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_traceMaxTime, traceMaxTimeStr);
    hpcrun_fmt_epochHdr_fwrite(fs, epoch_flags, default_measurement_granularity,
                               default_ra_to_callsite_distance);
    // log the number of metrics
    hpcfmt_int4_fwrite((uint32_t)global_hpc_fmt_data.metric_num, fs);
    // log each metric
    for (int i = 0; i < global_hpc_fmt_data.metric_num; i++)
        hpcrun_set_metric_info_w_fn(i, global_hpc_fmt_data.metric_name_arry[i], 1, fs);
    hpcrun_fmt_loadmap_fwrite(fs);
    return fs;
}


/*======APIs to support hpcviewer format======*/
/*
 * Initialize the formatting preparation
 * (called by the clients)
 * TODO: initialize metric table, provide custom metric merge functions
 */
DR_EXPORT
void
init_hpcrun_format(const char *app_name, bool metric_cct)
{
    global_hpc_fmt_data.filename = app_name;
    // Create the measurement directory
    global_hpc_fmt_data.dirName = "hpctoolkit-" + global_hpc_fmt_data.filename + "-measurements";
    mkdir(global_hpc_fmt_data.dirName.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    // the current metric cursor is set to 1
    global_hpc_fmt_data.metric_num = 0;
    global_hpc_fmt_data.metric_cct = metric_cct;
    if(metric_cct) {
        hpcrun_create_metric("CCT");
    }
}

/*
 * API to create new metric
 */
DR_EXPORT
int
hpcrun_create_metric(const char *name)
{
    int t = global_hpc_fmt_data.metric_num;
    strcpy(global_hpc_fmt_data.metric_name_arry[global_hpc_fmt_data.metric_num++], name);
    return t;
}

/*
 * Write the calling context tree of 'threadid' thread
 * (Called from clientele program)
 */
DR_EXPORT
int
write_thread_all_cct_hpcrun_format(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    FILE *fs = lazy_open_data_file(pt->id);
    if (!fs)
        return -1;
    cct_bb_node_t *root_bb_node = pt->root_bb_node;
    
    vector<hpcviewer_format_ip_node_t *> fmt_ip_node_vector;
    for (slot_t i = 0; i < root_bb_node->max_slots; i++) {
        cct_ip_node_t *ip_node = ctxt_hndl_to_ip_node(root_bb_node->child_ctxt_start_idx + i);
        hpcviewer_format_ip_node_t *fmt_ip_node =
            constructIPNodeFromIP(NULL, (app_pc)0, &pt->nodeCount);
        fmt_ip_node_vector.push_back(fmt_ip_node);
        if (ip_node->callee_splay_tree_root) {
            if(global_hpc_fmt_data.metric_cct){
                fmt_ip_node->metricVal[0] = 0;
            }
            tranverseIPs(fmt_ip_node, ip_node->callee_splay_tree_root, &pt->nodeCount);
        } else {
            fmt_ip_node->ID = -fmt_ip_node->ID;
            if(global_hpc_fmt_data.metric_cct){
                fmt_ip_node->metricVal[0] = 1;
            }
        }
    }
    hpcfmt_int8_fwrite(pt->nodeCount, fs);
    tranverseNewCCT(&fmt_ip_node_vector, fs);
    hpcio_fclose(fs);
    return 0;
}

// This API is used to output a hpcrun CCT with selected call paths
DR_EXPORT
int
build_thread_custom_cct_hpurun_format(vector<HPCRunCCT_t *> &run_cct_list, void *drcontext)
{

    // build the hpcrun-style CCT
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // initialize the root node (dummy node)
    if (!pt->tlsHPCRunCCTRoot) {
        pt->tlsHPCRunCCTRoot = new hpcviewer_format_ip_node_t();
        pt->tlsHPCRunCCTRoot->childIPNodes.clear();
        pt->tlsHPCRunCCTRoot->IPAddress = 0;
        pt->tlsHPCRunCCTRoot->ID = get_fmt_ip_node_new_id();
        if(global_hpc_fmt_data.metric_num > 0) {
            pt->tlsHPCRunCCTRoot->metricVal = new uint64_t[global_hpc_fmt_data.metric_num];
            for (int i = 0; i < global_hpc_fmt_data.metric_num; i++)
                pt->tlsHPCRunCCTRoot->metricVal[i] = 0;
        }
        pt->nodeCount = 1;
    }

    hpcviewer_format_ip_node_t *root = pt->tlsHPCRunCCTRoot;
    vector<HPCRunCCT_t *>::iterator it;
    for (it = run_cct_list.begin(); it != run_cct_list.end(); ++it) {
        hpcrun_insert_path(root, *it, &pt->nodeCount);
    }
    reset_leaf_node_id(pt->tlsHPCRunCCTRoot);
    return 0;
}

// output the CCT
DR_EXPORT
int
write_thread_custom_cct_hpurun_format(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    FILE *fs = lazy_open_data_file(pt->id);
    if (!fs)
        return -1;

    hpcviewer_format_ip_node_t * fmt_root_ip = pt->tlsHPCRunCCTRoot;

    vector<hpcviewer_format_ip_node_t *> fmt_ip_node_vector;
    for (uint32_t i = 0; i < fmt_root_ip->childIPNodes.size(); i++) {
        fmt_ip_node_vector.push_back(fmt_root_ip->childIPNodes[i]);
    }

    hpcfmt_int8_fwrite(pt->nodeCount, fs);
    IPNode_fwrite(fmt_root_ip, fs);
    tranverseNewCCT(&fmt_ip_node_vector, fs);
    hpcio_fclose(fs);
    return 0;
}

// This API is used to output a hpcrun CCT with selected call paths
DR_EXPORT
int
build_progress_custom_cct_hpurun_format(vector<HPCRunCCT_t *> &run_cct_list)
{
    // initialize the root node (dummy node)
    global_hpc_fmt_data.gHPCRunCCTRoot = new hpcviewer_format_ip_node_t();
    global_hpc_fmt_data.gHPCRunCCTRoot->childIPNodes.clear();
    global_hpc_fmt_data.gHPCRunCCTRoot->IPAddress = 0;
    global_hpc_fmt_data.gHPCRunCCTRoot->ID = get_fmt_ip_node_new_id();
    if(global_hpc_fmt_data.metric_num > 0) {
        global_hpc_fmt_data.gHPCRunCCTRoot->metricVal = new uint64_t[global_hpc_fmt_data.metric_num];
        for (int i = 0; i < global_hpc_fmt_data.metric_num; i++)
            global_hpc_fmt_data.gHPCRunCCTRoot->metricVal[i] = 0;
    }
    global_hpc_fmt_data.nodeCount = 1;

    hpcviewer_format_ip_node_t *root = global_hpc_fmt_data.gHPCRunCCTRoot;
    vector<HPCRunCCT_t *>::iterator it;
    for (it = run_cct_list.begin(); it != run_cct_list.end(); ++it) {
        hpcrun_insert_path(root, *it, &global_hpc_fmt_data.nodeCount);
    }
    reset_leaf_node_id(global_hpc_fmt_data.gHPCRunCCTRoot);
    return 0;
}

// output the CCT
DR_EXPORT
int
write_progress_custom_cct_hpurun_format()
{
    FILE *fs = lazy_open_data_file(0);
    if (!fs)
        return -1;
    hpcviewer_format_ip_node_t * fmt_root_ip = global_hpc_fmt_data.gHPCRunCCTRoot;
    vector<hpcviewer_format_ip_node_t *> fmt_ip_node_vector;
    for (uint32_t i = 0; i < fmt_root_ip->childIPNodes.size(); i++) {
        fmt_ip_node_vector.push_back(fmt_root_ip->childIPNodes[i]);
    }
    
    hpcfmt_int8_fwrite(global_hpc_fmt_data.nodeCount, fs);
    IPNode_fwrite(fmt_root_ip, fs);
    tranverseNewCCT(&fmt_ip_node_vector, fs);
    hpcio_fclose(fs);
    return 0;
}

// ************************************************************