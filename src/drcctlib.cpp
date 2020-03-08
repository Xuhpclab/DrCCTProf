// #include <fcntl.h>
// #include <gelf.h>
#include <inttypes.h>
// #include <libelf.h>
// #include <limits.h>
// #include <setjmp.h>
// #include <signal.h>
// #include <stdarg.h>
#include <string.h>
// #include <unistd.h>
// #include <unwind.h>

#include <sys/resource.h>
#include <sys/mman.h>
// #include <sys/time.h> 

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"
#include "hashtable.h"

#include "drcctlib_filter_func_list.h"
#include "drcctlib_global_share.h"
#include "drcctlib.h"
#include "splay_tree.h"
#include "shadow_memory.h"

#ifdef ARM	
#    define DR_DISASM_DRCCTLIB DR_DISASM_ARM	
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
#define ATOM_ADD_STRING_POOL_INDEX(origin, val) dr_atomic_add32_return_sum(&origin, val)


#ifdef X86
#define OPND_CREATE_PT_ADDR OPND_CREATE_INTPTR
#define OPND_CREATE_BB_KEY OPND_CREATE_INT32
#define OPND_CREATE_SLOT OPND_CREATE_INT32
#define OPND_CREATE_INSTR_STATE_FLAG OPND_CREATE_INT32
#elif defined(ARM)
#define OPND_CREATE_PT_ADDR OPND_CREATE_INT
#define OPND_CREATE_BB_KEY OPND_CREATE_INT
#define OPND_CREATE_SLOT OPND_CREATE_INT
#define OPND_CREATE_INSTR_STATE_FLAG OPND_CREATE_INT
#endif
#define OPND_CREATE_PT_CUR_SLOT OPND_CREATE_MEM32
#define OPND_CREATE_PT_STATE_FLAG OPND_CREATE_MEM32



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

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                      \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[drcctlib(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                    \
    dr_exit_process(-1)

enum {
    INSTR_STATE_CLIENT_INTEREST = 0x01,
    INSTR_STATE_CALL_DIRECT = 0x02,
    INSTR_STATE_CALL_IN_DIRECT = 0x04,
    INSTR_STATE_RETURN = 0x08,
    INSTR_STATE_UNINTEREST_FIRST = 0X10,
    INSTR_STATE_THREAD_ROOT_VIRTUAL = 0x20,
    INSTR_STATE_EVENT_SIGNAL = 0x40,
    INSTR_STATE_EVENT_EXCEPTION = 0x80,
#ifdef ARM
    INSTR_STATE_BB_START_NOP = 0X100
#endif
};

typedef struct _client_cb_t {
    void (*func)(void *, instrlist_t *, instr_t *, void *);
    void *data;
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
    splay_tree_t *callee_splay_tree;
} cct_ip_node_t;

typedef struct _instr_instrument_msg_t {
    instr_t *instr;
    slot_t slot;
    state_t state;
    struct _instr_instrument_msg_t *next;
} instr_instrument_msg_t;

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
    slot_t cur_slot;
    // for next
    state_t pre_bb_end_state;

    // // for exception
    // cct_bb_node_t *exception_hndl_bb_node;
    // context_handle_t exception_hndl_ctxt_hndl;
    // app_pc exception_hndl_pc;
    // bool in_exception;

    // hashtable_t *long_jmp_buff_tb;
    // void *long_jmp_hold_buff;

    // void *stack_base;
    // void *stack_end;
    // // DO_DATA_CENTRIC
    // size_t dmem_alloc_size;
    // context_handle_t dmem_alloc_ctxt_hndl;
} per_thread_t;

typedef struct _pt_cache_t {
    bool dead;
    per_thread_t *active_data;
    per_thread_t *cache_data;
} pt_cache_t;

static hashtable_t global_bb_key_table;
static hashtable_t global_bb_shadow_table;
static hashtable_t global_pt_cache_table;

static int init_count = 0;
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
static int64_t *gloabl_hndl_call_num;

static int global_thread_id_max = 0;

// static char *global_string_pool;
// static int global_string_pool_idle_idx = 0;
// static ConcurrentShadowMemory<DataHandle_t> g_DataCentricShadowMemory;

#define BB_TABLE_HASH_BITS 10
// #define PT_LONGJMP_BUFF_TABLE_HASH_BITS 4
#define PT_CACHE_TABLE_HASH_BITS 6

// #define X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite)
//     (callsite - 5)
// #define X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite)
//     (callsite - 2)

// #define MODULE_NAME_INSTRUMENT_JMP "libc.so"
// #define FUNC_NAME_ARCH_LONGJMP "__longjmp"
// #define FUNC_NAME_SETJMP "_setjmp"
// #define FUNC_NAME_LONGJMP FUNC_NAME_ARCH_LONGJMP
// #define FUNC_NAME_SIGSETJMP "sigsetjmp"
// #define FUNC_NAME_SIGLONGJMP FUNC_NAME_ARCH_LONGJMP

// #define MODULE_NAME_INSTRUMENT_EXCEPTION "libgcc_s.so"
// #define FUNC_NAME_UNWIND_SETIP "_Unwind_SetIP"
// #define FUNC_NAME_UNWIND_RAISEEXCEPTION "_Unwind_RaiseException"
// #define FUNC_NAME_UNWIND_RESUME "_Unwind_Resume"
// #define FUNC_NAME_UNWIND_FORCEUNWIND "_Unwind_ForcedUnwind"
// #define FUNC_NAME_UNWIND_RESUME_OR_RETHROW "_Unwind_Resume_or_Rethrow"

// #define FUNC_NAME_MALLOC "malloc"
// #define FUNC_NAME_CALLOC "calloc"
// #define FUNC_NAME_REALLOC "realloc"
// #define FUNC_NAME_FREE "free"

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

// static inline bool
// bb_is_fragment_in_funcs(instr_t *start, const char* mode_name, int num_func, ...)
// {
//     module_data_t *mdata;
//     app_pc start_addr = instr_get_app_pc(start);
//     mdata = dr_lookup_module(start_addr);
//     if(mdata == NULL || strstr(dr_module_preferred_name(mdata), mode_name) == NULL) {
//         return false;
//     }
//     drsym_error_t symres;
//     drsym_info_t sym;
//     char name[MAXIMUM_SYMNAME];
//     char file[MAXIMUM_PATH];
//     sym.struct_size = sizeof(sym);
//     sym.name = name;
//     sym.name_size = MAXIMUM_SYMNAME;
//     sym.file = file;
//     sym.file_size = MAXIMUM_PATH;
//     symres = drsym_lookup_address(mdata->full_path, start_addr - mdata->start, &sym,
//                                   DRSYM_DEFAULT_FLAGS);
//     if (symres != DRSYM_SUCCESS && symres != DRSYM_ERROR_LINE_NOT_AVAILABLE) {
//         return false;
//     }
//     bool res = false;
//     va_list func_name_list;
//     va_start(func_name_list, num_func);
//     for (int i = 0; i < num_func; i++) {
//         res =
//             res || (strcmp(sym.name, va_arg(func_name_list, const char *)) == 0);
//     }
//     va_end(func_name_list);
//     return res;
// }

// static inline  bool
// bb_is_fragment_in_module(instr_t *start, const char* mode_name)
// {
//     module_data_t *mdata;
//     app_pc start_addr = instr_get_app_pc(start);
//     mdata = dr_lookup_module(start_addr);
//     if(mdata == NULL || strstr(dr_module_preferred_name(mdata), mode_name) == NULL) {
//         return false;
//     }
//     return true;
// }

// static bool
// has_same_func(app_pc pc1, app_pc pc2)
// {
//     module_data_t *mdata1, *mdata2;
//     mdata1 = dr_lookup_module(pc1);
//     mdata2 = dr_lookup_module(pc2);
//     if(strcmp(dr_module_preferred_name(mdata1), dr_module_preferred_name(mdata1))!=0){
//         return false;
//     }
//     drsym_error_t symres1, symres2;
//     drsym_info_t sym1, sym2;
//     char name1[MAXIMUM_SYMNAME];
//     char name2[MAXIMUM_SYMNAME];
//     char file1[MAXIMUM_PATH];
//     char file2[MAXIMUM_PATH];
//     sym1.struct_size = sizeof(sym1);
//     sym1.name = name1;
//     sym1.name_size = MAXIMUM_SYMNAME;
//     sym1.file = file1;
//     sym1.file_size = MAXIMUM_PATH;
//     symres1 = drsym_lookup_address(mdata1->full_path, pc1 - mdata1->start, &sym1,
//                                   DRSYM_DEFAULT_FLAGS);
//     sym2.struct_size = sizeof(sym2);
//     sym2.name = name2;
//     sym2.name_size = MAXIMUM_SYMNAME;
//     sym2.file = file2;
//     sym2.file_size = MAXIMUM_PATH;
//     symres2 = drsym_lookup_address(mdata2->full_path, pc2 - mdata2->start, &sym2,
//                                   DRSYM_DEFAULT_FLAGS);
//     if ((symres1 != DRSYM_SUCCESS && symres1 != DRSYM_ERROR_LINE_NOT_AVAILABLE) ||
//         (symres2 != DRSYM_SUCCESS && symres2 != DRSYM_ERROR_LINE_NOT_AVAILABLE))
//     {
//         return false;
//     }
//     if(strcmp(sym1.name, sym2.name) != 0)
//     {
//         return false;
//     }
//     return true;
// }

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

static inline void
bb_node_free(void *node)
{
    dr_global_free((cct_bb_node_t *)node, sizeof(cct_bb_node_t));
}

static inline cct_bb_node_t *
bb_node_create(bb_key_t key, context_handle_t caller_ctxt_hndl, slot_t num)
{
    cct_bb_node_t *new_node = (cct_bb_node_t *)dr_global_alloc(sizeof(cct_bb_node_t));
    new_node->caller_ctxt_hndl = caller_ctxt_hndl;
    new_node->key = key;
    new_node->child_ctxt_start_idx = cur_child_ctxt_start_idx(num);
    new_node->max_slots = num;
    cct_ip_node_t *children = ctxt_hndl_to_ip_node(new_node->child_ctxt_start_idx);
    for (slot_t i = 0; i < num; ++i) {
        children[i].parent_bb_node = new_node;
        children[i].callee_splay_tree = splay_tree_create(bb_node_free);
    }
    return new_node;
}

static inline void
pt_init(void *drcontext, per_thread_t *const pt, int id)
{
    pt->id = id;

    cct_bb_node_t *root_bb_node = bb_node_create(
        THREAD_ROOT_BB_SHARED_BB_KEY, THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE, 1);

    pt->root_bb_node = root_bb_node;

    pt->cur_bb_node = root_bb_node;
    pt->cur_slot = 0;
    pt->pre_bb_end_state = INSTR_STATE_THREAD_ROOT_VIRTUAL;

    // pt->exception_hndl_ctxt_hndl = 0;
    // pt->exception_hndl_bb_node = NULL;
    // pt->exception_hndl_pc = 0;
    // pt->in_exception = false;

    // pt->long_jmp_buff_tb = (hashtable_t *)dr_thread_alloc(drcontext,
    // sizeof(hashtable_t)); hashtable_init(pt->long_jmp_buff_tb,
    // PT_LONGJMP_BUFF_TABLE_HASH_BITS, HASH_INTPTR, false); pt->long_jmp_hold_buff =
    // NULL;

    // Set stack sizes if data-centric is needed
    // void * s = (void *)(ptr_int_t)reg_get_value(DR_REG_RSP, (dr_mcontext_t
    // *)drcontext); pt->stack_base = (void *)s; struct rlimit rlim;

    // if (getrlimit(RLIMIT_STACK, &rlim)) {
    //     DRCCTLIB_PRINTF("Failed to getrlimit()");
    //     DRCCTLIB_EXIT_PROCESS(-1);
    // }

    // if (rlim.rlim_cur == RLIM_INFINITY) {
    //     DRCCTLIB_PRINTF("Need a finite stack size. Dont use unlimited.");
    //     DRCCTLIB_EXIT_PROCESS(-1);
    // }

    // pt->stack_end = (void *)((ptr_int_t)s - rlim.rlim_cur);
    // pt->dmem_alloc_size = 0;
    // pt->dmem_alloc_ctxt_hndl = 0;


}

static inline void
pt_cache_free(void *cache)
{
    pt_cache_t *pt_cache = (pt_cache_t *)cache;
    dr_global_free(pt_cache->cache_data, sizeof(per_thread_t));
    dr_global_free(cache, sizeof(pt_cache_t));
}
// static inline app_pc
// moudle_get_function_entry(const module_data_t *info, const char* func_name,
//                           bool check_internal_func)
// {
//     app_pc functionEntry;
//     if (check_internal_func) {
//         size_t offs;
//         if (drsym_lookup_symbol(info->full_path, func_name, &offs,
//                                 DRSYM_DEMANGLE) == DRSYM_SUCCESS) {
//             functionEntry = offs + info->start;
//         } else {
//             functionEntry = NULL;
//         }
//     } else {
//         functionEntry = (app_pc)dr_get_proc_address(info->handle, func_name);
//     }
//     return functionEntry;
// }

// static void
// pt_update_excetion_info(per_thread_t *pt, app_pc rtn_ip)
// {
//     slot_t ip_slot = 0;
//     cct_bb_node_t *bb_node = pt->cur_bb_node;
//     app_pc direct_call_ip = X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(rtn_ip);
//     app_pc in_direct_call_ip = X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(rtn_ip);

//     while (bb_node != pt->root_bb_node) {
//         bb_shadow_t *bb_shadow = (bb_shadow_t *)hashtable_lookup(
//             &global_bb_shadow_table, (void *)(ptr_int_t)(bb_node->key));
//         for (slot_t i = 0; i < bb_node->max_slots; i++) {
//             app_pc addr = bb_shadow->ip_shadow[i];
//             char flag = bb_shadow->state_shadow[i];
//             if (addr == direct_call_ip &&
//                 instr_state_contain(flag, INSTR_STATE_CALL_DIRECT)) {
//                 ip_slot = i;
//                 pt->exception_hndl_bb_node = bb_node;
//                 pt->exception_hndl_ctxt_hndl =
//                     pt->exception_hndl_bb_node->child_ctxt_start_idx + ip_slot;
//                 pt->exception_hndl_pc = addr;
//                 pt->in_exception = true;
//                 return;
//             }
//             if (addr == in_direct_call_ip &&
//                 instr_state_contain(flag, INSTR_STATE_CALL_IN_DIRECT)) {
//                 ip_slot = i;
//                 pt->exception_hndl_bb_node = bb_node;
//                 pt->exception_hndl_ctxt_hndl =
//                     pt->exception_hndl_bb_node->child_ctxt_start_idx + ip_slot;
//                 pt->exception_hndl_pc = addr;
//                 pt->in_exception = true;

//                 return;
//             }
//         }
//         bb_node = ctxt_hndl_to_ip_node(bb_node->caller_ctxt_hndl)->parent_bb_node;
//     }
//     DRCCTLIB_PRINTF("pt_update_excetion_info error: bb_node == pt->root_bb_node");
// }
static int32_t bb_entry_num = 0;
static void
instrument_before_bb_first_i(bb_key_t new_key, slot_t num)
{
    bb_entry_num++;
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
#ifdef DRCCTLIB_DEBUG
    DRCCTLIB_PRINTF("[r] pre key %d, slot_max %d, cur_slot %d, pre_bb_end_state %d", pt->cur_bb_node->key, pt->cur_bb_node->max_slots, pt->cur_slot, pt->pre_bb_end_state);
    DRCCTLIB_PRINTF("[r] cur key %d, slot_max %d", new_key, num);
#endif
    context_handle_t new_caller_ctxt = 0;
    if (instr_state_contain(pt->pre_bb_end_state, INSTR_STATE_THREAD_ROOT_VIRTUAL)) {
        new_caller_ctxt =
            pt->root_bb_node->child_ctxt_start_idx + THREAD_ROOT_SHARDED_CALLEE_INDEX;
    } else if (instr_state_contain(pt->pre_bb_end_state, INSTR_STATE_CALL_DIRECT) ||
               instr_state_contain(pt->pre_bb_end_state, INSTR_STATE_CALL_IN_DIRECT)) {
        new_caller_ctxt = pt->cur_bb_node->child_ctxt_start_idx + pt->cur_slot;
    } else if (instr_state_contain(pt->pre_bb_end_state, INSTR_STATE_RETURN)) {
        new_caller_ctxt = ctxt_hndl_to_ip_node(pt->cur_bb_node->caller_ctxt_hndl)
                              ->parent_bb_node->caller_ctxt_hndl;
    } else {
        if(pt->cur_slot >= pt->cur_bb_node->max_slots){
            cct_bb_node_t *pre_bb =  pt->cur_bb_node;
            DRCCTLIB_EXIT_PROCESS(" > pre bb key %d caller_ctxt_hndl %d", pre_bb->key, pre_bb->caller_ctxt_hndl);
        }
        new_caller_ctxt = pt->cur_bb_node->caller_ctxt_hndl;
    }
#ifndef ARM
    for (slot_t i = pt->cur_slot + 1; i < pt->cur_bb_node->max_slots; i++) {
        (*(gloabl_hndl_call_num + pt->cur_bb_node->child_ctxt_start_idx + i))--;
    }
#endif

    splay_node_t *new_root =
        splay_tree_add_and_update(ctxt_hndl_to_ip_node(new_caller_ctxt)->callee_splay_tree,
                                  (splay_node_key_t)new_key);
    if (new_root->payload == NULL) {
        new_root->payload = (void *)bb_node_create(new_key, new_caller_ctxt, num);
    }
    pt->cur_bb_node = (cct_bb_node_t *)(new_root->payload);
    pt->pre_bb_end_state = 0;
    pt->cur_slot = 0;
#ifndef ARM
    for(slot_t i = 0; i < num; i++){
        (*(gloabl_hndl_call_num + pt->cur_bb_node->child_ctxt_start_idx + i))++;
    }
#endif
}
#define ARM_USE_CLEAN_CALL
#if defined(ARM) && defined(ARM_USE_CLEAN_CALL)
static void
instrument_update_slot_and_state(slot_t slot, state_t state_flag)
{
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    pt->cur_slot = slot;
    pt->pre_bb_end_state = state_flag;
    // (*(gloabl_hndl_call_num + pt->cur_bb_node->child_ctxt_start_idx + slot))++;
}
#endif

static inline void
instrument_before_every_bb_i(void *drcontext, instrlist_t *bb, instr_t *instr, slot_t slot,
                           state_t state_flag)
{
#ifdef X86
    if (dr_using_all_private_caches()) {
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        /* private caches - we can use an absolute address */
        instrlist_meta_preinsert(
            bb, instr,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_ABSMEM(((byte *)&pt) + offsetof(per_thread_t, cur_slot),
                                   OPSZ_4),
                OPND_CREATE_SLOT(slot)));
        instrlist_meta_preinsert(
            bb, instr,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_ABSMEM(
                    ((byte *)&pt) + offsetof(per_thread_t, pre_bb_end_state), OPSZ_4),
                OPND_CREATE_SLOT(state_flag)));
    } else {
        /* shared caches - we must indirect via thread local storage */
        reg_id_t scratch;
        if (drreg_reserve_register(drcontext, bb, instr, NULL, &scratch) !=
            DRREG_SUCCESS) {
            DRCCTLIB_EXIT_PROCESS(
                "instrument_before_every_bb_i drreg_reserve_register != DRREG_SUCCESS");
        }
        drmgr_insert_read_tls_field(drcontext, tls_idx, bb, instr, scratch);
        instrlist_meta_preinsert(
            bb, instr,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_PT_CUR_SLOT(scratch, offsetof(per_thread_t, cur_slot)),
                OPND_CREATE_SLOT(slot)));
        instrlist_meta_preinsert(
            bb, instr,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_PT_STATE_FLAG(
                                   scratch, offsetof(per_thread_t, pre_bb_end_state)),
                               OPND_CREATE_SLOT(state_flag)));
        if (drreg_unreserve_register(drcontext, bb, instr, scratch) != DRREG_SUCCESS) {
            DRCCTLIB_EXIT_PROCESS(
                "instrument_before_every_bb_i drreg_unreserve_register != DRREG_SUCCESS");
        }
    }
#elif defined(ARM)
#    ifdef ARM_USE_CLEAN_CALL
    dr_insert_clean_call(drcontext, bb, instr, (void *)instrument_update_slot_and_state,
                         false, 2, OPND_CREATE_SLOT(slot),
                         OPND_CREATE_INSTR_STATE_FLAG(state_flag));
#    else
    opnd_t opnd1, opnd2, opnd3;
    reg_id_t reg1, reg2;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, instr, NULL, &reg2) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "instrument_before_every_bb_i drreg_reserve_register != DRREG_SUCCESS");
    }
    drmgr_insert_read_tls_field(drcontext, tls_idx, bb, instr, reg1);

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_PT_CUR_SLOT(reg1, offsetof(per_thread_t, cur_slot));
    opnd3 = OPND_CREATE_SLOT(slot);
    instrlist_meta_preinsert(bb, instr, XINST_CREATE_load_int(drcontext, opnd1, opnd3));
    instrlist_meta_preinsert(bb, instr, XINST_CREATE_store(drcontext, opnd2, opnd1));

    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_PT_STATE_FLAG(reg1, offsetof(per_thread_t, pre_bb_end_state));
    opnd3 = OPND_CREATE_INSTR_STATE_FLAG(state_flag);
    instrlist_meta_preinsert(bb, instr, XINST_CREATE_load_int(drcontext, opnd1, opnd3));
    instrlist_meta_preinsert(bb, instr, XINST_CREATE_store(drcontext, opnd2, opnd1));

    if (drreg_unreserve_register(drcontext, bb, instr, reg1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, instr, reg2) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "instrument_before_every_bb_i drreg_unreserve_register != DRREG_SUCCESS");
    }
#    endif
#endif
}

static inline void
instr_instrument_client_cb(void *drcontext, instrlist_t *bb, instr_t *instr,
                           char instr_state_flag)
{
    if (instr_state_contain(instr_state_flag, INSTR_STATE_CLIENT_INTEREST) &&
        client_cb.func != NULL) {
        (*client_cb.func)(drcontext, bb, instr, client_cb.data);
    }
}

static inline instr_instrument_msg_t *
instr_instrument_msg_create(instr_t *instr, slot_t slot, state_t state)
{
    instr_instrument_msg_t *msg =
        (instr_instrument_msg_t *)dr_global_alloc(
            sizeof(instr_instrument_msg_t));
    msg->instr = instr;
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

static dr_emit_flags_t
drcctlib_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                         bool for_trace, bool translating, void *user_data)
{
    bb_instrument_msg_t * bb_msg = (bb_instrument_msg_t *)user_data;
    if(bb_msg == NULL){
        return DR_EMIT_DEFAULT; 
    }
    if(instr == next_instrument_instr(bb_msg)){
        instr_instrument_msg_t* cur = bb_instrument_msg_pop(bb_msg);
#ifdef ARM
#ifdef DRCCTLIB_DEBUG
        DRCCTLIB_PRINTF("[i] cur key %d, slot_max %d, cur_slot %d, pre_bb_end_state %d", bb_msg->bb_key, bb_msg->slot_max, cur->slot, cur->state);
#endif
        if(cur->state == INSTR_STATE_BB_START_NOP) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)instrument_before_bb_first_i,
                         false, 2, OPND_CREATE_BB_KEY(bb_msg->bb_key), OPND_CREATE_SLOT(bb_msg->slot_max));
        } else {
            instrument_before_every_bb_i(drcontext, bb, instr, cur->slot, cur->state);
            instr_instrument_client_cb(drcontext, bb, instr, cur->state);
        }
#else
        if(cur->slot == 0){
            dr_insert_clean_call(drcontext, bb, instr, (void *)instrument_before_bb_first_i,
                         false, 2, OPND_CREATE_BB_KEY(bb_msg->bb_key), OPND_CREATE_SLOT(bb_msg->slot_max));
        }
        instrument_before_every_bb_i(drcontext, bb, instr, cur->slot, cur->state);
        instr_instrument_client_cb(drcontext, bb, instr, cur->state);
#endif
        instr_instrument_msg_delete(cur);
        
        if(bb_msg->number == 0) {
            bb_instrument_msg_delete(bb_msg);
        }
    }
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
drcctlib_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data)
{
#ifdef ARM
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
            uninit_shadow = true;
            hashtable_add(&global_bb_shadow_table, (void *)(ptr_int_t)bb_key,
                          (void *)bb_shadow);
        }
        dr_mutex_unlock(bb_shadow_lock);
    }
    bb_instrument_msg_t *bb_msg =
        bb_instrument_msg_create(bb_key, uninterested_bb ? 1 : interest_instr_num);
#ifdef ARM
    bb_instrument_msg_add(
            bb_msg,
            instr_instrument_msg_create(first_nop_instr, 0, INSTR_STATE_BB_START_NOP));
#endif
    if(uninterested_bb){
        bb_instrument_msg_add(bb_msg, instr_instrument_msg_create(first_instr, 0, INSTR_STATE_UNINTEREST_FIRST));
    } else {
        slot_t slot = 0;
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
                }
                bb_instrument_msg_add(bb_msg, instr_instrument_msg_create(instr, slot, instr_state_flag));
                slot++;
            }
        }
    }

    *user_data = (void*)bb_msg;
    return DR_EMIT_DEFAULT;
}


static dr_emit_flags_t
drcctlib_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
#ifdef ARM
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
#ifdef DRCCTLIB_DEBUG
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    DRCCTLIB_PRINTF("drcctlib_event_signal %d(thread %d)\n", siginfo->sig, pt->id);
#endif
    // pt->pre_bb_end_state = INSTR_STATE_EVENT_SIGNAL;
    return DR_SIGNAL_DELIVER;
}

static void
drcctlib_event_thread_start(void *drcontext)
{

    int id = ATOM_ADD_THREAD_ID_MAX(global_thread_id_max);
    id--;

    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if(pt == NULL){
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
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

    // DRCCTLIB_PRINTF("thread %d end", pt->id);
    // hashtable_delete(pt->long_jmp_buff_tb);
    pt_cache_t *pt_cache = (pt_cache_t *)hashtable_lookup(&global_pt_cache_table,
                                                          (void *)(ptr_int_t)(pt->id));
    pt_cache->cache_data = (per_thread_t *)dr_global_alloc(sizeof(per_thread_t));
    memcpy(pt_cache->cache_data, pt_cache->active_data, sizeof(per_thread_t));
    pt_cache->dead = true;
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
    DRCCTLIB_PRINTF("thread %d end", pt_cache->cache_data->id);
}

// static inline bool
// drcctlib_insert_func_instrument_by_drwap(const module_data_t *info, const char
// *func_name,
//                                 void (*pre_func_cb)(void *wrapcxt,
//                                                     INOUT void **user_data),
//                                 void (*post_func_cb)(void *wrapcxt, void *user_data))
// {
//     app_pc func_entry = moudle_get_function_entry(info, func_name, false);
//     if (func_entry != NULL) {
//         return drwrap_wrap(func_entry, pre_func_cb, post_func_cb);
//     } else {
//         return false;
//     }
// }

// static void
// instrument_before_setjmp_f(void *wrapcxt, void **user_data)
// {
//     void* bufAddr = drwrap_get_arg(wrapcxt, 0);
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field((void
//     *)drwrap_get_drcontext(wrapcxt), tls_idx); hashtable_add(pt->long_jmp_buff_tb,
//     bufAddr, (void*)ctxt_hndl_to_ip_node(pt->cur_bb_node->caller_ctxt_hndl));
// }

// static void
// instrument_before_longjmp_f(void *wrapcxt, void **user_data)
// {
//     DRCCTLIB_PRINTF("instrument_before_longjmp_f\n");
//     void*  bufAddr = drwrap_get_arg(wrapcxt, 0);
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field((void
//     *)drwrap_get_drcontext(wrapcxt), tls_idx); pt->long_jmp_hold_buff = bufAddr;
// }

// static void
// instrument_after_long_jmp(void *wrapcxt, void *user_data)
// {
//     DRCCTLIB_PRINTF("instrument_after_long_jmp");
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field((void
//     *)drwrap_get_drcontext(wrapcxt), tls_idx); if(pt->long_jmp_hold_buff == NULL) {
//         DRCCTLIB_PRINTF("instrument_after_finish_jmp error");
//         DRCCTLIB_EXIT_PROCESS(-1);
//     }
//     // cct_ip_node_t *node = (cct_ip_node_t *)hashtable_lookup(pt->long_jmp_buff_tb,
//     pt->long_jmp_hold_buff);
//     // pt->cur_ctxt_hndl = ip_node_to_ctxt_hndl(node);
//     // pt_update_cur_bb(pt, node->parent_bb_node);
//     // pt->long_jmp_hold_buff = NULL;
// }

// static void
// instrument_before_unwind_set_ip_f(void *wrapcxt, void **user_data)
// {
//     // per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//     //     (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     // struct _Unwind_Context *exception_caller_ctxt =
//     //     (struct _Unwind_Context *)drwrap_get_arg(wrapcxt, 0);
//     // _Unwind_Ptr exception_caller_rtn_ip =
//     c_use__Unwind_GetIP(exception_caller_ctxt);
//     // DRCCTLIB_PRINTF("exception_caller_rtn_ip (%" PRIu64
//     ")",(app_pc)exception_caller_rtn_ip);
//     // Walk the CCT chain staring from pt->cur_bb_node looking for the
//     // nearest one that has targeIp in the range.
//     // Record the caller that can handle the exception.
//     // pt_update_excetion_info(pt, (app_pc)exception_caller_rtn_ip);
// }

// static inline int
// drcctlib_get_next_string_pool_idx(char *name)
// {
//     int len = strlen(name) + 1;
//     int next_idx = ATOM_ADD_STRING_POOL_INDEX(global_string_pool_idle_idx, len);
//     if(next_idx >= CONTEXT_HANDLE_MAX) {
//         DRCCTLIB_PRINTF("Preallocated String Pool exhausted. CCTLib couldn't fit your "
//                    "application in its memory. Try a smaller program.");
//         DRCCTLIB_EXIT_PROCESS(-1);
//     }
//     strncpy(global_string_pool+ next_idx - len, name, len);
//     return next_idx - len;
// }

// // DO_DATA_CENTRIC
// static void
// InitShadowSpaceForDataCentric(void *addr, uint32_t accessLen, DataHandle_t
// *initializer)
// {
//     // cerr << "InitShadowSpaceForDataCentric" << endl;
//     uint64_t endAddr = (uint64_t)addr + accessLen;
//     uint32_t numInited = 0;

//     for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr;
//          curAddr += SHADOW_PAGE_SIZE) {
// #if __cplusplus > 199711L
//         DataHandle_t *status =
//             GetOrCreateShadowAddress<0>(g_DataCentricShadowMemory, (size_t)curAddr);
// #else
//         DataHandle_t *status =
//             GetOrCreateShadowAddress_0(g_DataCentricShadowMemory, (size_t)curAddr);
// #endif
//         int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)addr);

//         for (int i = 0; (i < maxBytesInThisPage) && numInited < accessLen;
//              numInited++, i++) {
//             status[i] = *initializer;
//         }
//     }
// }

// static void
// CaptureMallocSize(void *wrapcxt, void **user_data)
// {
//     // Remember the CCT node and the allocation size
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 0);
//     pt->dmem_alloc_ctxt_hndl =
//         pt->cur_bb_node->child_ctxt_start_idx;
// }

// static void
// CaptureMallocPointer(void *wrapcxt, void *user_data)
// {
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     void *ptr = drwrap_get_retval(wrapcxt);
//     DataHandle_t data_hndl;
//     data_hndl.objectType = DYNAMIC_OBJECT;
//     data_hndl.pathHandle = pt->dmem_alloc_ctxt_hndl;
//     InitShadowSpaceForDataCentric(ptr, pt->dmem_alloc_size,
//                                   &data_hndl);
// }

// static void
// CaptureCallocSize(void *wrapcxt, void **user_data)
// {
//     // Remember the CCT node and the allocation size
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     pt->dmem_alloc_size =
//         (size_t)drwrap_get_arg(wrapcxt, 0) * (size_t)drwrap_get_arg(wrapcxt, 1);
//     pt->dmem_alloc_ctxt_hndl =
//         pt->cur_bb_node->child_ctxt_start_idx;
// }

// static void
// CaptureReallocSize(void *wrapcxt, void **user_data)
// {
//     // Remember the CCT node and the allocation size
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 1);
//     pt->dmem_alloc_ctxt_hndl =
//         pt->cur_bb_node->child_ctxt_start_idx;
// }

// static void
// CaptureFree(void *wrapcxt, void **user_data)
// {
// }

// static void
// instrument_after_unwind_resume_f(void *wrapcxt, void *user_data)
// {
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     pt_update_cur_bb_and_ip(pt, pt->exception_hndl_bb_node,
//                      pt->exception_hndl_ctxt_hndl);
// }

// static void
// instrument_after_exception_unwind_f(void *wrapcxt, void *user_data)
// {
//     DRCCTLIB_PRINTF("instrument_after_exception_unwind_f\n");
//     if (wrapcxt == NULL)
//     {
//         DRCCTLIB_PRINTF("instrument_after_exception_unwind_f wrapcxt == NULL\n");
//     }
//     // void * retval = drwrap_get_retval(wrapcxt);
//     // int returncode = (int)(ptr_int_t)retval;
//     // if the return value is _URC_INSTALL_CONTEXT then we will reset the shadow
//     // stack, else NOP Commented ... caller ensures it is inserted only at the
//     // end. if(retVal != _URC_INSTALL_CONTEXT)
//     //    return;
//     // if (returncode == _Unwind_Reason_Code::_URC_INSTALL_CONTEXT) {
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     pt_update_cur_bb_and_ip(pt, pt->exception_hndl_bb_node,
//                             pt->exception_hndl_ctxt_hndl);
//     // }
//     DRCCTLIB_PRINTF("Finish SetCurBBNodeAfterExceptionIfContextIsInstalled\n");
// }

// static void
// drcctlib_event_module_analysis(void *drcontext, const module_data_t *info, bool loaded)
// {

//     if (strstr(dr_module_preferred_name(info), MODULE_NAME_INSTRUMENT_JMP)) {
//         drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_SETJMP,
//         instrument_before_setjmp_f, NULL);
//         drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_LONGJMP,
//         instrument_before_longjmp_f, instrument_after_long_jmp);
//         drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_SIGSETJMP,
//         instrument_before_setjmp_f, NULL);
//         drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_SIGLONGJMP,
//         instrument_before_longjmp_f, instrument_after_long_jmp);
//     }
//     if (strstr(dr_module_preferred_name(info), MODULE_NAME_INSTRUMENT_EXCEPTION)) {

//         drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_SETIP,
//         instrument_before_unwind_set_ip_f, NULL);
//         // drcctlib_insert_func_instrument_by_drwap(info,
//         FUNC_NAME_UNWIND_RAISEEXCEPTION, NULL, instrument_after_exception_unwind_f);
//         // drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_RESUME,
//         NULL, instrument_after_exception_unwind_f);
//         // drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_FORCEUNWIND,
//         NULL, instrument_after_exception_unwind_f);
//         // drcctlib_insert_func_instrument_by_drwap(info,
//         FUNC_NAME_UNWIND_RESUME_OR_RETHROW, NULL, instrument_after_exception_unwind_f);
//     }

//     drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_MALLOC, CaptureMallocSize,
//     CaptureMallocPointer); drcctlib_insert_func_instrument_by_drwap(info,
//     FUNC_NAME_CALLOC, CaptureCallocSize, CaptureMallocPointer);
//     drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_REALLOC,
//     CaptureReallocSize, CaptureMallocPointer);
//     drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_FREE, CaptureFree, NULL);
// }

static inline void
init_progress_root_ip_node()
{
    cct_ip_node_t *progress_root_ip =
        global_ip_node_buff + THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE;
    progress_root_ip->parent_bb_node = NULL;
    progress_root_ip->callee_splay_tree = splay_tree_create(bb_node_free);
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
    gloabl_hndl_call_num =
        (int64_t *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(int64_t),
                              PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (gloabl_hndl_call_num == MAP_FAILED) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: MAP_FAILED gloabl_hndl_call_num");
    }
    // global_string_pool = (char *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(char), PROT_WRITE
    // | PROT_READ,
    //     MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // if(global_string_pool == MAP_FAILED) {
    //     DRCCTLIB_PRINTF("init_global_buff error: MAP_FAILED global_string_pool");
    //     DRCCTLIB_EXIT_PROCESS(-1);
    // }
    // else {
    //     global_string_pool_idle_idx = 1;
    // }
}

static inline void init_global_bb_shadow_table()
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
free_global_buff()
{
    for (context_handle_t i = 0; i < global_ip_node_buff_idle_idx; i++) {
        splay_tree_free(global_ip_node_buff[i].callee_splay_tree);
    }
    if (munmap(global_ip_node_buff, CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t)) != 0) {
        // || munmap(global_string_pool, CONTEXT_HANDLE_MAX * sizeof(char)) != 0) {
        DRCCTLIB_PRINTF("free_global_buff munmap error");
    }
    if (munmap(gloabl_hndl_call_num, CONTEXT_HANDLE_MAX * sizeof(int64_t)) != 0) {
        // || munmap(global_string_pool, CONTEXT_HANDLE_MAX * sizeof(char)) != 0) {
        DRCCTLIB_PRINTF("free_global_buff munmap error");
    }
}



static inline void
create_global_locks()
{
    flags_lock = dr_recurlock_create();
    bb_shadow_lock = dr_mutex_create();
}

static inline void
destroy_global_locks()
{
    dr_recurlock_destroy(flags_lock);
    dr_mutex_destroy(bb_shadow_lock);
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
    dr_fprintf(log_file, "\nbb_entry_num %d", bb_entry_num);
    dr_fprintf(log_file, "\nTotalCallPaths = %" PRIu64, global_ip_node_buff_idle_idx);
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

// compute static variables
// each image has a splay tree to include all static variables
// that reside in the image. All images are linked as a link list
// static void
// ComputeStaticVar(char *filename, const module_data_t *info)
// {
//     // cerr << "ComputeStaticVar" << endl;
//     Elf *elf; /* Our Elf pointer for libelf */

//     Elf_Scn *scn = NULL;    /* Section Descriptor */
//     Elf_Data *edata = NULL; /* Data Descriptor */
//     GElf_Sym sym;           /* Symbol */
//     GElf_Shdr shdr;         /* Section Header */

//     int i, symbol_count;
//     int fd = open(filename, O_RDONLY);

//     if (elf_version(EV_CURRENT) == EV_NONE) {
//         DRCCTLIB_PRINTF("WARNING Elf Library is out of date!");
//     }

//     // in memory
//     elf = elf_begin(fd, ELF_C_READ,
//                     NULL); // Initialize 'elf' pointer to our file descriptor

//     // Iterate each section until symtab section for object symbols
//     while ((scn = elf_nextscn(elf, scn)) != NULL) {
//         gelf_getshdr(scn, &shdr);

//         if (shdr.sh_type == SHT_SYMTAB) {
//             edata = elf_getdata(scn, edata);
//             symbol_count = shdr.sh_size / shdr.sh_entsize;

//             for (i = 0; i < symbol_count; i++) {
//                 if (gelf_getsym(edata, i, &sym) == NULL) {
//                     DRCCTLIB_PRINTF("gelf_getsym return NULL");
//                     DRCCTLIB_PRINTF("%s", elf_errmsg(elf_errno()));
//                     DRCCTLIB_EXIT_PROCESS(-1);
//                 }

//                 if ((sym.st_size == 0) ||
//                     (ELF32_ST_TYPE(sym.st_info) != STT_OBJECT)) { // not a variable
//                     continue;
//                 }

//                 DataHandle_t dataHandle;
//                 dataHandle.objectType = STATIC_OBJECT;
//                 char *symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
//                 dataHandle.symName = symname ?
//                 drcctlib_get_next_string_pool_idx(symname) : 0; DRCCTLIB_PRINTF("%s",
//                 dataHandle.symName); InitShadowSpaceForDataCentric(
//                     (void *)((uint64_t)(info->start) + sym.st_value),
//                     (uint32_t)sym.st_size, &dataHandle);
//             }
//         }
//     }
// }

// static void
// ComputeVarBounds(void *drcontext, const module_data_t *info, bool loaded)
// {
//     char filename[PATH_MAX];
//     char *result = realpath(info->full_path, filename);

//     if (result == NULL) {
//         DRCCTLIB_PRINTF("%s ---- failed to resolve path", info->full_path);
//     }
//     ComputeStaticVar(filename, info);
// }

// static void
// DeleteStaticVar(void *drcontext, const module_data_t *info)
// {
// }

DR_EXPORT
bool
drcctlib_init(void)
{
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&init_count, 1);
    if (count > 1)
        return true;
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
    drreg_options_t ops = { sizeof(ops), 3 /*max slots needed*/, false };
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
    hashtable_init(&global_bb_key_table, BB_TABLE_HASH_BITS, HASH_INTPTR, false);
    hashtable_init_ex(&global_bb_shadow_table, BB_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!strdup*/, false /*!synch*/, bb_shadow_free, NULL, NULL);
    init_global_bb_shadow_table();
    hashtable_init_ex(&global_pt_cache_table, PT_CACHE_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!strdup*/, false /*!synch*/, pt_cache_free, NULL, NULL);
    create_global_locks();

    // drmgr_register_module_load_event(drcctlib_event_module_analysis);

    // This will perform hpc_var_bounds functionality on each image load
    // drmgr_register_module_load_event(ComputeVarBounds);
    // delete image from the list at the unloading callback
    // drmgr_register_module_unload_event(DeleteStaticVar);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1)
        return false;
    if (!drmgr_register_thread_init_event(drcctlib_event_thread_start))
        return false;
    if (!drmgr_register_thread_exit_event(drcctlib_event_thread_end))
        return false;

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
    print_stats();
    if (!drmgr_unregister_bb_app2app_event(drcctlib_event_bb_app2app) ||
        !drmgr_unregister_bb_instrumentation_event(drcctlib_event_bb_analysis) ||
        // !drmgr_unregister_bb_insertion_event(drcctlib_event_bb_insert) ||
        // !drmgr_unregister_module_load_event(drcctlib_event_module_analysis) ||
        !drmgr_unregister_signal_event(drcctlib_event_signal) ||
        !drmgr_unregister_thread_init_event(drcctlib_event_thread_start) ||
        !drmgr_unregister_thread_exit_event(drcctlib_event_thread_end) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("failed to unregister in drcctlib_exit");
    }

    // drmgr_unregister_module_load_event(ComputeVarBounds);
    // drmgr_unregister_module_unload_event(DeleteStaticVar);

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
drcctlib_register_client_cb(void (*func)(void *, instrlist_t *, instr_t *, void *),
                            void *data)
{
    client_cb.func = func;
    client_cb.data = data;
}

DR_EXPORT
bool
drcctlib_set_global_flags(char flags)
{
    char old_flags;
    bool res;
    dr_recurlock_lock(flags_lock);
    old_flags = global_flags;
    global_flags |= flags;
    res = (global_flags != old_flags);
    dr_recurlock_unlock(flags_lock);
    return res;
}

DR_EXPORT
void
drcctlib_config_log_file(file_t file)
{
    log_file = file;
}

DR_EXPORT bool
drcctlib_init_ex(bool (*filter)(instr_t *), file_t file,
                 void (*func)(void *, instrlist_t *, instr_t *, void *), void *data)
{
    if (!drcctlib_init()) {
        return false;
    }
    drcctlib_register_instr_filter(filter);
    drcctlib_config_log_file(file);
    drcctlib_register_client_cb(func, data);
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
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    return pt->cur_bb_node->child_ctxt_start_idx + pt->cur_slot;
}

DR_EXPORT
context_handle_t
drcctlib_get_global_context_handle_num()
{
    return global_ip_node_buff_idle_idx;
}

DR_EXPORT
int64_t *
drcctlib_get_global_gloabl_hndl_call_num_buff()
{
    return gloabl_hndl_call_num;
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


#ifdef DRCCTLIB_DEBUG

DR_EXPORT
bool
test_is_app_ctxt_hndl(context_handle_t ctxt_hndl)
{
    if (!ctxt_hndl_is_valid(ctxt_hndl)) {
        DRCCTLIB_EXIT_PROCESS("test_is_app_ctxt_hndl !ctxt_hndl_is_valid");
    }
    if (ctxt_hndl == THREAD_ROOT_SHARDED_CALLER_CONTEXT_HANDLE) {
        return false;
    }
    cct_bb_node_t *bb = ctxt_hndl_to_ip_node(ctxt_hndl)->parent_bb_node;
    if (bb->key == THREAD_ROOT_BB_SHARED_BB_KEY ||
        bb->key == UNINTERESTED_BB_SHARED_BB_KEY) {
        return false;
    }
    bb_shadow_t *shadow = (bb_shadow_t *)hashtable_lookup(&global_bb_shadow_table,
                                                          (void *)(ptr_int_t)(bb->key));
    app_pc addr = shadow->ip_shadow[ctxt_hndl - bb->child_ctxt_start_idx];
    module_data_t *data = dr_lookup_module(addr);
    const char *app_path = "/home/dolanwm/Github/drcctlib/appsamples/build/sample";
    return strcmp(data->full_path, app_path) == 0;
}

DR_EXPORT
void
test_print_app_ctxt_hndl_msg(context_handle_t ctxt_hndl)
{
    if (test_is_app_ctxt_hndl(ctxt_hndl)) {
        drcctlib_print_ctxt_hndl_msg(ctxt_hndl, false, false);
    }
}

DR_EXPORT
void
test_print_app_ctxt_hndl_cct(context_handle_t ctxt_hndl)
{
    if (test_is_app_ctxt_hndl(ctxt_hndl)) {
        drcctlib_print_full_cct(ctxt_hndl, false, false, MAX_CCT_PRINT_DEPTH);
    }
}

#endif







// API to get the handle for a data object
// DR_EXPORT
// DataHandle_t
// GetDataObjectHandle(void *drcontext, void *address)
// {
//     DataHandle_t dataHandle;
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
//     // if it is a stack location, set so and return
//     if (address > pt->stack_end && address < pt->stack_base) {
//         dataHandle.objectType = STACK_OBJECT;
//         return dataHandle;
//     }
// #if __cplusplus > 199711L
//     dataHandle = *(GetOrCreateShadowAddress<0>(g_DataCentricShadowMemory,
//                                                (size_t)(uint64_t)address));
// #else
//     dataHandle = *(
//         GetOrCreateShadowAddress_0(g_DataCentricShadowMemory,
//         (size_t)(uint64_t)address));
// #endif
//     return dataHandle;
// }

// DR_EXPORT
// char *
// GetStringFromStringPool(int index)
// {
//     return global_string_pool+ index;
// }