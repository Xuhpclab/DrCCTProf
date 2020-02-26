#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <unwind.h>

#include <sys/resource.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"
#include "hashtable.h"

#include "drcctlib_debug.h"
#include "drcctlib.h"
#include "splay_tree.h"
#include "drcctlib_if.h"
#include "shadow_memory.h"


typedef struct _instr_instrument_cb_str_t {
    drcctlib_instr_instrument_cb_t callback;
    void *data;
} instr_instrument_cb_str_t;

typedef struct _bb_shadow_t {
    app_pc *ip_shadow;
    char *state_shadow;
    char *disasm_shadow;
    bool is_in_exception_moudle;
    slot_t slot_num;
} bb_shadow_t;

typedef hashtable_t instr_asm_shadow_t;
typedef char *instr_asm_t;

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
}cct_ip_node_t;

// TLS(thread local storage)
typedef struct _per_thread_t {
    pt_id_t id;
    // for current handle
    context_handle_t cur_ctxt_hndl;
    cct_bb_node_t *cur_bb_node;
    slot_t cur_slot_idx;
    // for root
    context_handle_t root_ctxt_hndl;
    cct_bb_node_t *root_bb_node;
    // for parent_thread
    context_handle_t parent_thread_ctxt_hndl;
    cct_bb_node_t *parent_thread_bb_node;
    // for exception
    context_handle_t exception_hndl_ctxt_hndle;
    cct_bb_node_t *exception_hndl_bb_node;
    app_pc exception_hndl_pc;
    bool in_exception;

    bool inited_call;

    hashtable_t *long_jmp_buff_tb;
    void *long_jmp_hold_buff;

    void *stack_base;
    void *stack_end;
    // DO_DATA_CENTRIC
    size_t dmem_alloc_size;
    context_handle_t dmem_alloc_ctxt_hndl;

} per_thread_t;


typedef struct _pt_cache_t
{
    bool dead;
    per_thread_t *active_data;
    per_thread_t *cache_data;
} pt_cache_t;


// typedef struct _global_data_t
// {
//     instr_instrument_cb_str_t instr_instrument_pre_cb_str;
//     instr_instrument_cb_str_t instr_instrument_post_cb_str;

//     cct_ip_node_t *ip_node_buff;
//     context_handle_t ip_node_buff_idle_idx = 1;

//     // static hashtable_t global_threadDataMap;
//     void *thread_manager_lock;
//     /* protected by thread_manager_lock */
//     pt_id_t thread_id_max = 1;
//     pt_id_t thread_create_count = 0;
//     pt_id_t thread_capture_count = 0;
//     cct_bb_node_t *cur_thread_create_bb_node = NULL;
//     context_handle_t cur_thread_create_ctxt_hndl = 0;
// } global_data_t;

// static global_data_t drcctlib_gdata;

static int drcctlib_init_count = 0;
/* TLS.  OK to be callback-shared: just more nesting. */
static int tls_idx;

static instr_instrument_cb_str_t global_instr_instrument_pre_cb_str;
static instr_instrument_cb_str_t global_instr_instrument_post_cb_str;

static void *flags_lock;
/* protected by flags_lock */
static drcctlib_global_flags_t global_flags = DRCCTLIB_DEFAULT;

static drcctlib_interest_filter_t global_interest_filter = (drcctlib_interest_filter_t)DRCCTLIB_FILTER_ZERO_INSTR;

static cct_ip_node_t *global_ip_node_buff;
static context_handle_t global_ip_node_buff_idle_idx;

static hashtable_t global_bb_shadow_table;

// static hashtable_t global_threadDataMap;
static void *thread_manager_lock;
/* protected by thread_manager_lock */
static pt_id_t global_thread_id_max = 0;
static pt_id_t global_thread_create_count = 0;
static pt_id_t global_thread_capture_count = 0;
static cct_bb_node_t *cur_thread_create_bb_node = NULL;
static context_handle_t cur_thread_create_ctxt_hndl = 0;

static file_t global_logfile;

static hashtable_t global_pt_cache_map;

static char *global_string_pool;
static int global_string_pool_idle_idx;
static ConcurrentShadowMemory<DataHandle_t> g_DataCentricShadowMemory;


#define BB_TABLE_HASH_BITS 10
#define BB_SUB_TABLE_HASH_BITS 6
#define PT_LONGJMP_BUFF_TABLE_HASH_BITS 4
#define PT_CACHE_TABLE_HASH_BITS 6

#define X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite) \
    (callsite - 5)
#define X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite) \
    (callsite - 2)

#define FUNC_NAME_PTHREAD_CREATE "pthread_create"

#define MODULE_NAME_INSTRUMENT_JMP "libc.so"
#define FUNC_NAME_ARCH_LONGJMP "__longjmp"
#define FUNC_NAME_SETJMP "_setjmp"
#define FUNC_NAME_LONGJMP FUNC_NAME_ARCH_LONGJMP
#define FUNC_NAME_SIGSETJMP "sigsetjmp"
#define FUNC_NAME_SIGLONGJMP FUNC_NAME_ARCH_LONGJMP

#define MODULE_NAME_INSTRUMENT_EXCEPTION "libgcc_s.so"
#define FUNC_NAME_UNWIND_SETIP "_Unwind_SetIP"
#define FUNC_NAME_UNWIND_RAISEEXCEPTION "_Unwind_RaiseException"
#define FUNC_NAME_UNWIND_RESUME "_Unwind_Resume"
#define FUNC_NAME_UNWIND_FORCEUNWIND "_Unwind_ForcedUnwind"
#define FUNC_NAME_UNWIND_RESUME_OR_RETHROW "_Unwind_Resume_or_Rethrow"

#define FUNC_NAME_MALLOC "malloc"
#define FUNC_NAME_CALLOC "calloc"
#define FUNC_NAME_REALLOC "realloc"
#define FUNC_NAME_FREE "free"

#define MAX_CCT_PRINT_DEPTH 5


//ctxt ipnode
static inline context_handle_t
drcctlib_ip_to_ctxt(cct_ip_node_t *ip)
{
    return ((context_handle_t)((ip) ? ((ip)-global_ip_node_buff) : 0));
}

static inline cct_ip_node_t *
drcctlib_ctxt_to_ip(context_handle_t ctxt)
{
    return global_ip_node_buff + ctxt;
}

DR_EXPORT
bool
drcctlib_ctxt_is_valid(context_handle_t ctxt)
{
    return ctxt != 0;
}

static inline context_handle_t
drcctlib_next_child_ctxt_start_idx(slot_t num)
{
    context_handle_t next_idx = ATOM_ADD_CTXT_HNDL(global_ip_node_buff_idle_idx, num);
    if(next_idx >= CONTEXT_HANDLE_MAX) {
        dr_printf("\nPreallocated IPNodes exhausted. CCTLib couldn't fit your "
                   "application in its memory. Try a smaller program.\n");
        dr_exit_process(-1);
    }

    return next_idx - num;
}

// instr state flag
static inline bool
instr_state_contain(char instr_state_flag, int identy_state_num, ...)
{
    bool res = true;
    va_list identy_state_list;
    va_start(identy_state_list, identy_state_num);
    for (int i = 0; i < identy_state_num; i++) {
        res =
            res && ((instr_state_flag & va_arg(identy_state_list, drcctlib_instr_state_flag_t)) > 0);
    }
    va_end(identy_state_list);
    return res;
}

static inline bool
instr_need_instrument_check_f(char instr_state_flag)
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
    if(global_interest_filter(instr)){
        return true;
    }
    return false;
}

static inline void
instr_state_init(instr_t *instr, char *instr_state_flag_ptr)
{
    if (global_interest_filter(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | DRCCTLIB_INSTR_STATE_USER_INTEREST;
    }
    if (instr_is_call_direct(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | DRCCTLIB_INSTR_STATE_CALL_DIRECT;
    }
    else if (instr_is_call_indirect(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | DRCCTLIB_INSTR_STATE_CALL_IN_DIRECT;
    }
    else if (instr_is_return(instr)) {
        *instr_state_flag_ptr = *instr_state_flag_ptr | DRCCTLIB_INSTR_STATE_RETURN;
    }
}


static inline slot_t
bb_get_num_interest_instr(instr_t *bb_first, instr_t *bb_last_next)
{
    slot_t num = 0;
    for (instr_t *instr = bb_first; instr != bb_last_next;
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
    static bb_key_t global_bb_next_key = 0;
    bb_key_t key = ATOM_GET_NEXT_BB_KEY(global_bb_next_key);
    key = key - 1;
    if (key == BB_KEY_MAX) {
        dr_printf("MAX basic blocks created! Exiting..\n");
        dr_exit_process(-1);
    }
    // dr_printf("bb_get_new_key %d\n", key);
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


static bool
has_same_func(app_pc pc1, app_pc pc2)
{
    module_data_t *mdata1, *mdata2;
    mdata1 = dr_lookup_module(pc1);
    mdata2 = dr_lookup_module(pc2);
    if(strcmp(dr_module_preferred_name(mdata1), dr_module_preferred_name(mdata1))!=0){
        return false;
    }
    drsym_error_t symres1, symres2;
    drsym_info_t sym1, sym2;
    char name1[MAXIMUM_SYMNAME];
    char name2[MAXIMUM_SYMNAME];
    char file1[MAXIMUM_PATH];
    char file2[MAXIMUM_PATH];
    sym1.struct_size = sizeof(sym1);
    sym1.name = name1;
    sym1.name_size = MAXIMUM_SYMNAME;
    sym1.file = file1;
    sym1.file_size = MAXIMUM_PATH;
    symres1 = drsym_lookup_address(mdata1->full_path, pc1 - mdata1->start, &sym1,
                                  DRSYM_DEFAULT_FLAGS);
    sym2.struct_size = sizeof(sym2);
    sym2.name = name2;
    sym2.name_size = MAXIMUM_SYMNAME;
    sym2.file = file2;
    sym2.file_size = MAXIMUM_PATH;
    symres2 = drsym_lookup_address(mdata2->full_path, pc2 - mdata2->start, &sym2,
                                  DRSYM_DEFAULT_FLAGS);
    if ((symres1 != DRSYM_SUCCESS && symres1 != DRSYM_ERROR_LINE_NOT_AVAILABLE) ||
        (symres2 != DRSYM_SUCCESS && symres2 != DRSYM_ERROR_LINE_NOT_AVAILABLE))
    {
        return false;
    }
    if(strcmp(sym1.name, sym2.name) != 0) 
    {
        return false;
    }
    return true;
}

static inline bb_shadow_t* 
bb_shadow_create(slot_t num, bool is_in_exception_moudle)
{
    bb_shadow_t* bb_shadow = (bb_shadow_t *)dr_global_alloc(sizeof(bb_shadow_t));
    bb_shadow->slot_num = num;
    bb_shadow->ip_shadow = (app_pc *)dr_global_alloc(num * sizeof(app_pc));
    bb_shadow->state_shadow = (char *)dr_global_alloc(num * sizeof(char));
    bb_shadow->disasm_shadow = (char *)dr_global_alloc(DISASM_CACHE_SIZE * num * sizeof(char*));
    bb_shadow->is_in_exception_moudle = is_in_exception_moudle;
    return bb_shadow;
}

static inline void
bb_shadow_free(void *shadow)
{
    bb_shadow_t *bb_shadow = (bb_shadow_t *)shadow;
    slot_t num = bb_shadow->slot_num;
    dr_global_free((void *)bb_shadow->ip_shadow, num * sizeof(app_pc));
    dr_global_free((void *)bb_shadow->state_shadow, num * sizeof(char));
    dr_global_free((void *)bb_shadow->disasm_shadow, DISASM_CACHE_SIZE * num * sizeof(char *));
    dr_global_free(shadow, sizeof(bb_shadow_t));
}

static inline void
cct_bb_node_free(void *node)
{
    dr_global_free((cct_bb_node_t *)node, sizeof(cct_bb_node_t));
}

static inline cct_bb_node_t *
cct_bb_node_create(per_thread_t *pt, bb_key_t key, slot_t num)
{
    cct_bb_node_t *new_node = (cct_bb_node_t *)dr_global_alloc(sizeof(cct_bb_node_t));
    new_node->caller_ctxt_hndl = pt->cur_ctxt_hndl;
    new_node->key = key;
    if (num <= 0) {
        num = 1;
    }
    new_node->child_ctxt_start_idx = drcctlib_next_child_ctxt_start_idx(num);
    new_node->max_slots = num;
    cct_ip_node_t *child = drcctlib_ctxt_to_ip(new_node->child_ctxt_start_idx);
    for (slot_t i = 0; i < num; ++i) {
        child[i].parent_bb_node = new_node;
        child[i].callee_splay_tree = splay_tree_create(cct_bb_node_free);
    }
    
    return new_node;
}

static inline void
pt_init(void *drcontext, per_thread_t *const pt, pt_id_t id)
{
    cct_bb_node_t *bb_node = (cct_bb_node_t *)dr_global_alloc(sizeof(cct_bb_node_t));
    bb_node->key = -1;
    bb_node->caller_ctxt_hndl = 0;
    bb_node->max_slots = 1;
    bb_node->child_ctxt_start_idx = drcctlib_next_child_ctxt_start_idx(1);
    cct_ip_node_t *ipNode = drcctlib_ctxt_to_ip(bb_node->child_ctxt_start_idx);
    ipNode->parent_bb_node = bb_node;
    ipNode->callee_splay_tree = splay_tree_create(cct_bb_node_free);

    pt->id = id;

    pt->cur_ctxt_hndl = bb_node->child_ctxt_start_idx;
    pt->cur_bb_node = bb_node;
    pt->cur_slot_idx = 0;
    
    pt->root_ctxt_hndl = bb_node->child_ctxt_start_idx;
    pt->root_bb_node = bb_node;

    pt->parent_thread_ctxt_hndl = 0;
    pt->parent_thread_bb_node = NULL;

    pt->exception_hndl_ctxt_hndle = 0;
    pt->exception_hndl_bb_node = NULL;
    pt->exception_hndl_pc = 0;
    pt->in_exception = false;

    pt->inited_call = true;

    pt->long_jmp_buff_tb = (hashtable_t *)dr_thread_alloc(drcontext, sizeof(hashtable_t));
    hashtable_init(pt->long_jmp_buff_tb, PT_LONGJMP_BUFF_TABLE_HASH_BITS, HASH_INTPTR, false);
    pt->long_jmp_hold_buff = NULL;

    // Set stack sizes if data-centric is needed
    void * s = (void *)(ptr_int_t)reg_get_value(DR_REG_RSP, (dr_mcontext_t *)drcontext);
    pt->stack_base = (void *)s;
    struct rlimit rlim;

    if (getrlimit(RLIMIT_STACK, &rlim)) {
        dr_printf("\n Failed to getrlimit()\n");
        dr_exit_process(-1);
    }

    if (rlim.rlim_cur == RLIM_INFINITY) {
        dr_printf("\n Need a finite stack size. Dont use unlimited.\n");
        dr_exit_process(-1);
    }

    pt->stack_end = (void *)((ptr_int_t)s - rlim.rlim_cur);
    pt->dmem_alloc_size = 0;
    pt->dmem_alloc_ctxt_hndl = 0;
}

static inline void
pt_cache_free(void *cache)
{
    pt_cache_t *pt_cache = (pt_cache_t *)cache;
    dr_global_free(pt_cache->cache_data, sizeof(per_thread_t));
    dr_global_free(cache, sizeof(pt_cache_t));
}

static inline void
pt_update_cur_bb_and_ip(per_thread_t *pt, cct_bb_node_t *bb_node,
                        context_handle_t ctxt_hndle)
{
    pt->cur_bb_node = bb_node;
    pt->cur_ctxt_hndl = ctxt_hndle;
}

static inline void
pt_update_cur_bb(per_thread_t *pt, cct_bb_node_t *bb_node)
{
    pt->cur_bb_node = bb_node;
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

static void
pt_update_excetion_info(per_thread_t *pt, app_pc rtn_ip)
{
    slot_t ip_slot = 0;
    cct_bb_node_t *bb_node = pt->cur_bb_node;
    app_pc direct_call_ip = X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(rtn_ip);
    app_pc in_direct_call_ip = X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(rtn_ip);

    while (bb_node != pt->root_bb_node) {
        bb_shadow_t *bb_shadow = (bb_shadow_t *)hashtable_lookup(
            &global_bb_shadow_table, (void *)(ptr_int_t)(bb_node->key));
        for (slot_t i = 0; i < bb_node->max_slots; i++) {
            app_pc addr = bb_shadow->ip_shadow[i];
            char flag = bb_shadow->state_shadow[i];
            if (addr == direct_call_ip &&
                instr_state_contain(flag, 1, DRCCTLIB_INSTR_STATE_CALL_DIRECT)) {
                ip_slot = i;
                pt->exception_hndl_bb_node = bb_node;
                pt->exception_hndl_ctxt_hndle =
                    pt->exception_hndl_bb_node->child_ctxt_start_idx + ip_slot;
                pt->exception_hndl_pc = addr;
                pt->in_exception = true;
                return;
            }
            if (addr == in_direct_call_ip &&
                instr_state_contain(flag, 1, DRCCTLIB_INSTR_STATE_CALL_IN_DIRECT)) {
                ip_slot = i;
                pt->exception_hndl_bb_node = bb_node;
                pt->exception_hndl_ctxt_hndle =
                    pt->exception_hndl_bb_node->child_ctxt_start_idx + ip_slot;
                pt->exception_hndl_pc = addr;
                pt->in_exception = true;

                return;
            }
        }
        bb_node = drcctlib_ctxt_to_ip(bb_node->caller_ctxt_hndl)->parent_bb_node;
    }
    dr_printf("pt_update_excetion_info error: bb_node == pt->root_bb_node\n");
}






DR_EXPORT
drcctlib_instr_instrument_t *
instr_instrument_create(instr_t *instr, void *callee,
                        drcctlib_instr_instrument_pri_t priority, int num_args, ...)
{
    drcctlib_instr_instrument_t *instrument =
        (drcctlib_instr_instrument_t *)dr_global_alloc(
            sizeof(drcctlib_instr_instrument_t));
    instrument->instr = instr;
    instrument->priority = priority;
    instrument->callee = callee;
    instrument->num_args = num_args;
    instrument->args_array = (opnd_t *)dr_global_alloc(sizeof(opnd_t) * num_args);
    va_list args_list;
    va_start(args_list, num_args);
    for (int i = 0; i < num_args; i++) {
        instrument->args_array[i] = va_arg(args_list, opnd_t);
    }
    va_end(args_list);
    return instrument;
}

static inline void
instr_instrument_delete(drcctlib_instr_instrument_t *instrument)
{
    if (instrument == NULL) {
        return;
    }
    dr_global_free(instrument->args_array, sizeof(opnd_t) * instrument->num_args);
    dr_global_free(instrument, sizeof(drcctlib_instr_instrument_t));
}

static inline drcctlib_instr_instrument_list_t *
instr_instrument_list_create(bb_key_t bb_key)
{
    drcctlib_instr_instrument_list_t *list = (drcctlib_instr_instrument_list_t *)dr_global_alloc(sizeof(drcctlib_instr_instrument_list_t));
    list->bb_key = bb_key;
    list->instrument_num = 0;
    list->first = list->last = list->next_insert = NULL;
    return list;
}

static inline void
instr_instrument_list_add(drcctlib_instr_instrument_list_t *list,
                          drcctlib_instr_instrument_t *ninstrument)
{
    
    drcctlib_instr_instrument_t *riter = list->last;
    while (riter != NULL)
    {
        if(riter->instr != ninstrument->instr ||
            (riter->instr == ninstrument->instr && riter->priority < ninstrument->priority))
        {
            break;
        }
        riter = riter->pre;
    }
    if(riter == NULL){
        if(list->instrument_num == 0) {
            list->first = ninstrument;
            list->last = ninstrument;
            ninstrument->pre = NULL;
            ninstrument->next = NULL;
        }
        else{
            ninstrument->next = list->first;
            ninstrument->pre = NULL;
            list->first->pre = ninstrument;
            list->first = ninstrument;
        }
    } else {
        ninstrument->next = riter->next;
        if (riter->next != NULL) {
            riter->next->pre = ninstrument;
        }
        ninstrument->pre = riter;
        riter->next = ninstrument;
        if (riter == list->last) {
            list->last = ninstrument;
        }
    }
    list->instrument_num++;
}

static inline void
instr_instrument_list_delete(drcctlib_instr_instrument_list_t *list)
{
    if (list == NULL) {
        return;
    }
    for (drcctlib_instr_instrument_t *iter = list->first; iter != NULL; ) {
        drcctlib_instr_instrument_t * next = iter->next;
        instr_instrument_delete(iter);
        iter = next;
    }
    list->first = NULL;
    list->last = NULL;
    list->next_insert = NULL;
    dr_global_free(list, sizeof(drcctlib_instr_instrument_list_t));
}

static void
instrument_before_every_i(slot_t slot)
{
    // dr_printf("instrument_before_every_i \n");
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    pt->cur_slot_idx = slot;
}

static void
instrument_before_bb_first_i(bb_key_t new_key, slot_t num)
{
    // dr_printf("new_key %d\n", new_key);
    // dr_fprintf(global_logfile, "instrument_before_bb_first_i %d\n", new_key);
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (!pt->inited_call) {
        pt->cur_ctxt_hndl = pt->cur_bb_node->caller_ctxt_hndl;
    } else {
        pt->inited_call = false;
    }
    splay_node_t* new_root = splay_tree_add_and_update(drcctlib_ctxt_to_ip(pt->cur_ctxt_hndl)->callee_splay_tree,
                              (splay_node_key_t)new_key);
    if(new_root->payload == NULL){
        new_root->payload = (void*)cct_bb_node_create(pt, new_key, num);
    }
    cct_bb_node_t *cur_bb_node = (cct_bb_node_t *)new_root->payload;
    pt_update_cur_bb_and_ip(pt, cur_bb_node, cur_bb_node->child_ctxt_start_idx);
}

static void
instrument_before_call_i(slot_t slot)
{
    // dr_printf("instrument_before_call_i \n");
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    pt->inited_call = true;
    pt->cur_ctxt_hndl = pt->cur_bb_node->child_ctxt_start_idx + slot;
}

static void
instrument_before_return_i()
{
    // dr_printf("instrument_before_return_i \n");
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // If we reach the root trace, then fake the call
    if (pt->cur_bb_node->caller_ctxt_hndl == pt->root_ctxt_hndl) {
        pt->inited_call = true;
    }
    pt->cur_ctxt_hndl = pt->cur_bb_node->caller_ctxt_hndl;
    pt_update_cur_bb(pt, drcctlib_ctxt_to_ip(pt->cur_ctxt_hndl)->parent_bb_node);
}

static void
instrument_end_before_every_i(app_pc pc)
{
    // dr_printf("instrument_end_before_every_i \n");
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if(pt->in_exception){
        if(has_same_func(pc, pt->exception_hndl_pc)) {
            dr_fprintf(global_logfile, "instrument_end_before_every_i\n");
            pt_update_cur_bb_and_ip(pt, pt->exception_hndl_bb_node, pt->exception_hndl_ctxt_hndle);
            pt->in_exception=false; 
        }
    }
}

static inline void
instr_instrument_pre_cb(drcctlib_instr_instrument_list_t *instrument_list, instr_t *instr,
                        char instr_state_flag, slot_t slot)
{
    instr_instrument_list_add(
        instrument_list,
        instr_instrument_create(instr, (void *)instrument_before_every_i,
                                DRCCTLIB_INSTR_INSTRUMENT_CCT_PRE, 1,
                                OPND_CREATE_SLOT(slot)));
    if (instr_state_contain(instr_state_flag, 1, DRCCTLIB_INSTR_STATE_USER_INTEREST) &&
        global_instr_instrument_pre_cb_str.callback != NULL) {
        (*global_instr_instrument_pre_cb_str.callback)(
            instrument_list, instr, slot, DRCCTLIB_INSTR_INSTRUMENT_USER_PRE,
            global_instr_instrument_pre_cb_str.data);
    }
}

static inline void
instr_instrument_post_cb(drcctlib_instr_instrument_list_t *instrument_list,
                         instr_t *instr, char instr_state_flag, slot_t slot)
{
    if (instr_state_contain(instr_state_flag, 1, DRCCTLIB_INSTR_STATE_RETURN)) {
        slot = 0;
    }
    if (instr_state_contain(instr_state_flag, 1, DRCCTLIB_INSTR_STATE_USER_INTEREST) &&
        global_instr_instrument_post_cb_str.callback != NULL) {
        (*global_instr_instrument_post_cb_str.callback)(
            instrument_list, instr, slot, DRCCTLIB_INSTR_INSTRUMENT_USER_POST,
            global_instr_instrument_post_cb_str.data);
    }
}

static inline void
instr_instrument(drcctlib_instr_instrument_list_t *instrument_list, instr_t *instr,
                 char instr_state_flag, slot_t slot)
{
    if (instr_state_contain(instr_state_flag, 1, DRCCTLIB_INSTR_STATE_CALL_DIRECT)) {
        instr_instrument_list_add(
            instrument_list,
            instr_instrument_create(instr, (void *)instrument_before_call_i,
                                     DRCCTLIB_INSTR_INSTRUMENT_CCT_CALL, 1,
                                     OPND_CREATE_SLOT(slot)));
    } else if (instr_state_contain(instr_state_flag, 1,
                                   DRCCTLIB_INSTR_STATE_CALL_IN_DIRECT)) {
        instr_instrument_list_add(
            instrument_list,
            instr_instrument_create(instr, (void *)instrument_before_call_i,
                                     DRCCTLIB_INSTR_INSTRUMENT_CCT_CALL, 1,
                                     OPND_CREATE_SLOT(slot)));
    } else if (instr_state_contain(instr_state_flag, 1, DRCCTLIB_INSTR_STATE_RETURN)) {
        instr_instrument_list_add(
            instrument_list,
            instr_instrument_create(instr, (void *)instrument_before_return_i,
                                     DRCCTLIB_INSTR_INSTRUMENT_CCT_CALL, 0));
    }
}


static inline void
drcctlib_insert_clean_call_before_instr(void *drcontext, instrlist_t *ilist,
                                        instr_t *where, void *callee, bool save_fpstate,
                                        int num_args, opnd_t *args_array)
{
    switch (num_args) {
    case 0: dr_insert_clean_call(drcontext, ilist, where, callee, save_fpstate, 0); break;
    case 1:
        dr_insert_clean_call(drcontext, ilist, where, callee, save_fpstate, 1,
                             args_array[0]);
        break;
    case 2:
        dr_insert_clean_call(drcontext, ilist, where, callee, save_fpstate, 2,
                             args_array[0], args_array[1]);
        break;
    case 3:
        dr_insert_clean_call(drcontext, ilist, where, callee, save_fpstate, 3,
                             args_array[0], args_array[1], args_array[2]);
        break;
    default:
        dr_printf("drcctlib_insert_clean_call_before_instr max support callee has 3 args \n");
        dr_exit_process(-1);
        break;
    }
}

static dr_emit_flags_t
drcctlib_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                           bool for_trace, bool translating, void *user_data)
{
    // if(for_trace || translating) 
    // {
    //     return DR_EMIT_DEFAULT;
    // }
    // per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // dr_printf("drcctlib_event_bb_insert(thread %d)\n", pt->id);
    drcctlib_instr_instrument_list_t * list = (drcctlib_instr_instrument_list_t *)user_data;
    if(list == NULL){
        return DR_EMIT_DEFAULT;
    }
    while (list->next_insert != NULL && list->next_insert->instr == instr)
    {
        drcctlib_insert_clean_call_before_instr(drcontext, bb, instr, list->next_insert->callee,
                                 false, list->next_insert->num_args, list->next_insert->args_array);
        list->next_insert = list->next_insert->next;
        if(list->next_insert == NULL){
            instr_instrument_list_delete(list);
            break;
        }
    }
    // dr_printf("f drcctlib_event_bb_insert(thread %d)\n", pt->id);
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
drcctlib_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data)
{
    // if (for_trace || translating) {
    //     return DR_EMIT_DEFAULT;
    // }
    // per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // dr_printf("drcctlib_event_bb_analysis (thread %d)\n", pt->id);
    // bool checkReturnIns = bb_is_fragment_in_funcs(
    //     start, "libgcc_s.so", 4, FUNC_NAME_UNWIND_RESUME, FUNC_NAME_UNWIND_RAISEEXCEPTION, FUNC_NAME_UNWIND_FORCEUNWIND,
    //     FUNC_NAME_UNWIND_RESUME_OR_RETHROW);
    instr_t *first_instr = instrlist_first_app(bb);
    instr_t *last_instr_next = instr_get_next_app(instrlist_last_app(bb));

    // dr_printf("drcctlib_event_bb_analysis 0(thread %d)\n", pt->id);
    slot_t slot_max = bb_get_num_interest_instr(first_instr, last_instr_next);
    // dr_printf("drcctlib_event_bb_analysis 1(thread %d)\n", pt->id);
    bb_key_t bb_key = bb_get_new_key();
    // dr_printf("drcctlib_event_bb_analysis 2(thread %d)\n", pt->id);
    slot_t slot = 0;
    // bool is_in_exception_module = bb_is_fragment_in_module(first_instr, MODULE_NAME_INSTRUMENT_EXCEPTION);
    
    bb_shadow_t* bb_shadow = bb_shadow_create(slot_max == 0? 1 : slot_max, false);
    hashtable_add(&global_bb_shadow_table, (void*)(ptr_int_t)bb_key, bb_shadow);

    // dr_printf("drcctlib_event_bb_analysis 3(thread %d)\n", pt->id);
    drcctlib_instr_instrument_list_t *instrument_list = instr_instrument_list_create(bb_key);
    instr_instrument_list_add(
        instrument_list,
        instr_instrument_create(first_instr, (void *)instrument_before_bb_first_i,
                                DRCCTLIB_INSTR_INSTRUMENT_CCT_BB_ENTRY, 2,
                                OPND_CREATE_BB_KEY(bb_key),
                                OPND_CREATE_SLOT(slot_max)));
    if(slot_max == 0){
        instr_disassemble_to_buffer(
                drcontext, first_instr, bb_shadow->disasm_shadow,
                DISASM_CACHE_SIZE);
        app_pc pc = instr_get_app_pc(first_instr);
        bb_shadow->ip_shadow[0] = pc;
        bb_shadow->state_shadow[0] = 0;
    }
    // dr_printf("drcctlib_event_bb_analysis 4(thread %d)\n", pt->id);
    for (instr_t *instr = first_instr; instr != last_instr_next;
         instr = instr_get_next_app(instr)) {
        char instr_state_flag = 0;
        instr_state_init(instr, &instr_state_flag);
        if (instr_need_instrument_check_f(instr_state_flag)) {
            instr_disassemble_to_buffer(
                drcontext, instr, bb_shadow->disasm_shadow + slot * DISASM_CACHE_SIZE,
                DISASM_CACHE_SIZE);
            app_pc pc = instr_get_app_pc(instr);
            bb_shadow->ip_shadow[slot] = pc;
            bb_shadow->state_shadow[slot] = instr_state_flag;
            // dr_printf("drcctlib_event_bb_analysis 5(thread %d)\n", pt->id);
            instr_instrument_pre_cb(instrument_list, instr, instr_state_flag, slot);
            instr_instrument(instrument_list, instr, instr_state_flag, slot);
            instr_instrument_post_cb(instrument_list, instr, instr_state_flag, slot);
            instr_instrument_list_add(
                instrument_list,
                instr_instrument_create(instr, (void *)instrument_end_before_every_i,
                                        DRCCTLIB_INSTR_INSTRUMENT_CCT_BB_ENTRY-1, 1,
                                        OPND_CREATE_DRCCTLIB_KEY(pc)));

            slot++;
        }
    }
    // dr_printf("drcctlib_event_bb_analysis 5(thread %d)\n", pt->id);
    instrument_list->next_insert = instrument_list->first;
    *user_data = (void*)instrument_list;
    // dr_printf("finish drcctlib_event_bb_analysis(thread %d)\n", pt->id);
    return DR_EMIT_DEFAULT;
}

static dr_signal_action_t
drcctlib_event_signal(void *drcontext, dr_siginfo_t *siginfo)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_printf("drcctlib_event_signal %d(thread %d)\n", siginfo->sig, pt->id);
    pt->inited_call = true;
    return DR_SIGNAL_DELIVER;
}

static void
drcctlib_event_thread_start(void *drcontext)
{
    
    pt_id_t id = ATOM_ADD_THREAD_ID_MAX(global_thread_id_max);
    id--;
    dr_printf("++++++++ drcctlib_event_thread_start (threadId %d)\n", id);

    per_thread_t * pt = (per_thread_t*)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(pt != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt_init(drcontext, pt, id);
    pt_cache_t *pt_cache = (pt_cache_t *)dr_global_alloc(sizeof(pt_cache_t));
    pt_cache->active_data = pt;
    pt_cache->cache_data = NULL;
    pt_cache->dead = false;
    hashtable_add(&global_pt_cache_map, (void*)(ptr_int_t)id, pt_cache);

    dr_mutex_lock(thread_manager_lock);
    if (global_thread_create_count != global_thread_capture_count) {
        // Base thread, no parent
    } else {
        // This will be always 0 for flat profiles
        pt->parent_thread_ctxt_hndl = cur_thread_create_ctxt_hndl;
        pt->parent_thread_bb_node = (cct_bb_node_t *)cur_thread_create_bb_node;
        pt->root_bb_node->caller_ctxt_hndl = cur_thread_create_ctxt_hndl;
        global_thread_capture_count++;
    }
    dr_mutex_unlock(thread_manager_lock);

    dr_printf("++++++++ finish drcctlib_event_thread_start (threadId %d)\n", id);
}

static void
drcctlib_event_thread_end(void *drcontext)
{
    dr_printf("++++++++ drcctlib_event_thread_end\n");
    per_thread_t *pt =
        (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    hashtable_delete(pt->long_jmp_buff_tb);
    pt_cache_t *pt_cache = (pt_cache_t *)hashtable_lookup(&global_pt_cache_map, (void*)(ptr_int_t)(pt->id));
    pt_cache->cache_data = (per_thread_t *)dr_global_alloc(sizeof(per_thread_t));
    memcpy(pt_cache->cache_data, pt_cache->active_data, sizeof(per_thread_t));
    pt_cache->dead = true;
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
    dr_printf("++++++++ f drcctlib_event_thread_end\n");
}

static inline bool
drcctlib_insert_func_instrument_by_drwap(const module_data_t *info, const char *func_name,
                                void (*pre_func_cb)(void *wrapcxt,
                                                    INOUT void **user_data),
                                void (*post_func_cb)(void *wrapcxt, void *user_data))
{
    app_pc func_entry = moudle_get_function_entry(info, func_name, false);
    if (func_entry != NULL) {
        // dr_printf("drwrap_wrap %s\n", func_name);
        return drwrap_wrap(func_entry, pre_func_cb, post_func_cb);
    } else {
        return false;
    }
}

static void
instrument_after_thread_create_f(void *wrapcxt, void *user_data)
{
    // dr_mutex_lock(thread_manager_lock);
    // per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field((void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    // cur_thread_create_bb_node = pt->cur_bb_node;
    // cur_thread_create_ctxt_hndl = pt->cur_ctxt_hndl;
    // global_thread_create_count++;
    // dr_mutex_unlock(thread_manager_lock);
}

static void
instrument_before_setjmp_f(void *wrapcxt, void **user_data)
{
    dr_printf("instrument_before_setjmp_f\n");
    void* bufAddr = drwrap_get_arg(wrapcxt, 0);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field((void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    hashtable_add(pt->long_jmp_buff_tb, bufAddr, (void*)drcctlib_ctxt_to_ip(pt->cur_bb_node->caller_ctxt_hndl));
    dr_printf("f instrument_before_setjmp_f\n");
}

static void
instrument_before_longjmp_f(void *wrapcxt, void **user_data)
{
    dr_printf("instrument_before_longjmp_f\n");
    void*  bufAddr = drwrap_get_arg(wrapcxt, 0);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field((void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    pt->long_jmp_hold_buff = bufAddr;
}

static void
instrument_after_long_jmp(void *wrapcxt, void *user_data)
{
    dr_printf("instrument_after_long_jmp\n");
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field((void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    if(pt->long_jmp_hold_buff == NULL) {
        dr_printf("instrument_after_finish_jmp error\n");
        dr_exit_process(-1);
    }
    cct_ip_node_t *node = (cct_ip_node_t *)hashtable_lookup(pt->long_jmp_buff_tb, pt->long_jmp_hold_buff);
    pt->cur_ctxt_hndl = drcctlib_ip_to_ctxt(node);
    pt_update_cur_bb(pt, node->parent_bb_node);
    pt->long_jmp_hold_buff = NULL; 
}



static void
instrument_before_unwind_set_ip_f(void *wrapcxt, void **user_data)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    struct _Unwind_Context *exception_caller_ctxt =
        (struct _Unwind_Context *)drwrap_get_arg(wrapcxt, 0);
    _Unwind_Ptr exception_caller_rtn_ip = c_use__Unwind_GetIP(exception_caller_ctxt);
    dr_printf("exception_caller_rtn_ip (%" PRIu64 ")",(app_pc)exception_caller_rtn_ip);
    // Walk the CCT chain staring from pt->cur_bb_node looking for the
    // nearest one that has targeIp in the range.
    // Record the caller that can handle the exception.
    pt_update_excetion_info(pt, (app_pc)exception_caller_rtn_ip);
}

static inline int
drcctlib_get_next_string_pool_idx(char *name)
{
    int len = strlen(name) + 1;
    int next_idx = ATOM_ADD_STRING_POOL_INDEX(global_string_pool_idle_idx, len);
    if(next_idx >= CONTEXT_HANDLE_MAX) {
        dr_printf("\nPreallocated String Pool exhausted. CCTLib couldn't fit your "
                   "application in its memory. Try a smaller program.\n");
        dr_exit_process(-1);
    }
    strncpy(global_string_pool+ next_idx - len, name, len);
    return next_idx - len;
}

// DO_DATA_CENTRIC
static void
InitShadowSpaceForDataCentric(void *addr, uint32_t accessLen, DataHandle_t *initializer)
{
    // cerr << "InitShadowSpaceForDataCentric" << endl;
    uint64_t endAddr = (uint64_t)addr + accessLen;
    uint32_t numInited = 0;

    for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr;
         curAddr += SHADOW_PAGE_SIZE) {
#if __cplusplus > 199711L
        DataHandle_t *status =
            GetOrCreateShadowAddress<0>(g_DataCentricShadowMemory, (size_t)curAddr);
#else
        DataHandle_t *status =
            GetOrCreateShadowAddress_0(g_DataCentricShadowMemory, (size_t)curAddr);
#endif
        int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)addr);

        for (int i = 0; (i < maxBytesInThisPage) && numInited < accessLen;
             numInited++, i++) {
            status[i] = *initializer;
        }
    }
}



static void
CaptureMallocSize(void *wrapcxt, void **user_data)
{
    // dr_printf("CaptureMallocSize");
    // Remember the CCT node and the allocation size
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 0);
    pt->dmem_alloc_ctxt_hndl =
        pt->cur_bb_node->child_ctxt_start_idx;
}

static void
CaptureMallocPointer(void *wrapcxt, void *user_data)
{
    // dr_printf("CaptureMallocPointer");
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    void *ptr = drwrap_get_retval(wrapcxt);
    DataHandle_t data_hndl;
    data_hndl.objectType = DYNAMIC_OBJECT;
    data_hndl.pathHandle = pt->dmem_alloc_ctxt_hndl;
    InitShadowSpaceForDataCentric(ptr, pt->dmem_alloc_size,
                                  &data_hndl);
}

static void
CaptureCallocSize(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    pt->dmem_alloc_size =
        (size_t)drwrap_get_arg(wrapcxt, 0) * (size_t)drwrap_get_arg(wrapcxt, 1);
    pt->dmem_alloc_ctxt_hndl =
        pt->cur_bb_node->child_ctxt_start_idx;
}

static void
CaptureReallocSize(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
        (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
    pt->dmem_alloc_size = (size_t)drwrap_get_arg(wrapcxt, 1);
    pt->dmem_alloc_ctxt_hndl =
        pt->cur_bb_node->child_ctxt_start_idx;
}

static void
CaptureFree(void *wrapcxt, void **user_data)
{
}

// static void
// instrument_after_unwind_resume_f(void *wrapcxt, void *user_data)
// {
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(
//         (void *)drwrap_get_drcontext(wrapcxt), tls_idx);
//     pt_update_cur_bb_and_ip(pt, pt->exception_hndl_bb_node,
//                      pt->exception_hndl_ctxt_hndle);
// }

// static void
// instrument_after_exception_unwind_f(void *wrapcxt, void *user_data)
// {
//     dr_printf("instrument_after_exception_unwind_f\n");
//     if (wrapcxt == NULL)
//     {
//         dr_printf("instrument_after_exception_unwind_f wrapcxt == NULL\n");
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
//                             pt->exception_hndl_ctxt_hndle);
//     // }
//     dr_printf("Finish SetCurBBNodeAfterExceptionIfContextIsInstalled\n");
// }
// static char global_excetption_module[MAXIMUM_PATH] = "";
static void
drcctlib_event_module_analysis(void *drcontext, const module_data_t *info, bool loaded)
{
    // dr_printf("drcctlib_event_module_analysis %s\n", info->full_path);

    drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_PTHREAD_CREATE, NULL, instrument_after_thread_create_f);

    if (strstr(dr_module_preferred_name(info), MODULE_NAME_INSTRUMENT_JMP)) {
        drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_SETJMP, instrument_before_setjmp_f, NULL);
        drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_LONGJMP, instrument_before_longjmp_f, instrument_after_long_jmp);
        drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_SIGSETJMP, instrument_before_setjmp_f, NULL);
        drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_SIGLONGJMP, instrument_before_longjmp_f, instrument_after_long_jmp);
    }
    if (strstr(dr_module_preferred_name(info), MODULE_NAME_INSTRUMENT_EXCEPTION)) {

        drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_SETIP, instrument_before_unwind_set_ip_f, NULL);
        // drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_RAISEEXCEPTION, NULL, instrument_after_exception_unwind_f);
        // drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_RESUME, NULL, instrument_after_exception_unwind_f);
        // drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_FORCEUNWIND, NULL, instrument_after_exception_unwind_f);
        // drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_UNWIND_RESUME_OR_RETHROW, NULL, instrument_after_exception_unwind_f);
    }

    drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_MALLOC, CaptureMallocSize, CaptureMallocPointer);
    drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_CALLOC, CaptureCallocSize, CaptureMallocPointer);
    drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_REALLOC, CaptureReallocSize, CaptureMallocPointer);
    drcctlib_insert_func_instrument_by_drwap(info, FUNC_NAME_FREE, CaptureFree, NULL);

    // dr_printf("finish drcctlib_event_module_analysis\n");
}

static inline void
drcctlib_init_global_buff()
{
    global_ip_node_buff =
        (cct_ip_node_t *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t),
                              PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(global_ip_node_buff == MAP_FAILED) {
        dr_printf("drcctlib_init_global_buff error: MAP_FAILED global_ip_node_buff\n");
        dr_exit_process(-1);
    }
    else {
        global_ip_node_buff_idle_idx = 1;
        // dr_printf("drcctlib_init_global_buff success\n");
    }
    global_string_pool = (char *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(char), PROT_WRITE | PROT_READ,
        MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if(global_string_pool == MAP_FAILED) {
        dr_printf("drcctlib_init_global_buff error: MAP_FAILED global_string_pool\n");
        dr_exit_process(-1);
    }
    else {
        global_ip_node_buff_idle_idx = 1;
        // dr_printf("drcctlib_init_global_buff success\n");
    }

}

static inline void
drcctlib_free_global_buff()
{
    for (int i = 1; i < global_ip_node_buff_idle_idx; i++) {
        splay_tree_free(global_ip_node_buff[i].callee_splay_tree);
    }
    if (munmap(global_ip_node_buff, CONTEXT_HANDLE_MAX * sizeof(cct_ip_node_t)) != 0
    || munmap(global_string_pool, CONTEXT_HANDLE_MAX * sizeof(char)) != 0) {
        dr_printf("drcctlib_free_global_buff munmap error\n");
        dr_exit_process(-1);
    }
}

static inline void
drcctlib_lock_create()
{
    flags_lock = dr_recurlock_create();
    thread_manager_lock = dr_mutex_create();
}

static inline void
drcctlib_lock_destroy()
{
    dr_recurlock_destroy(flags_lock);
    dr_mutex_destroy(thread_manager_lock);
}

static size_t
drcctlib_get_peak_rss()
{
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    return (size_t)(rusage.ru_maxrss);
}

static void
drcctlib_print_stats()
{
    dr_fprintf(global_logfile, "\nTotalCallPaths = %" PRIu64,
               global_ip_node_buff_idle_idx);
    // Peak resource usage
    dr_fprintf(global_logfile, "\nPeakRSS = %zu", drcctlib_get_peak_rss());
}





// compute static variables
// each image has a splay tree to include all static variables
// that reside in the image. All images are linked as a link list
static void
ComputeStaticVar(char *filename, const module_data_t *info)
{
    // cerr << "ComputeStaticVar" << endl;
    Elf *elf; /* Our Elf pointer for libelf */

    Elf_Scn *scn = NULL;    /* Section Descriptor */
    Elf_Data *edata = NULL; /* Data Descriptor */
    GElf_Sym sym;           /* Symbol */
    GElf_Shdr shdr;         /* Section Header */

    int i, symbol_count;
    int fd = open(filename, O_RDONLY);

    if (elf_version(EV_CURRENT) == EV_NONE) {
        dr_printf("WARNING Elf Library is out of date!\n");
    }

    // in memory
    elf = elf_begin(fd, ELF_C_READ,
                    NULL); // Initialize 'elf' pointer to our file descriptor

    // Iterate each section until symtab section for object symbols
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_SYMTAB) {
            edata = elf_getdata(scn, edata);
            symbol_count = shdr.sh_size / shdr.sh_entsize;

            for (i = 0; i < symbol_count; i++) {
                if (gelf_getsym(edata, i, &sym) == NULL) {
                    dr_printf("gelf_getsym return NULL\n");
                    dr_printf("%s\n", elf_errmsg(elf_errno()));
                    dr_exit_process(-1);
                }

                if ((sym.st_size == 0) ||
                    (ELF32_ST_TYPE(sym.st_info) != STT_OBJECT)) { // not a variable
                    continue;
                }

                DataHandle_t dataHandle;
                dataHandle.objectType = STATIC_OBJECT;
                char *symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
                dataHandle.symName = symname ? drcctlib_get_next_string_pool_idx(symname) : 0;
                dr_printf("%s\n", dataHandle.symName);
                InitShadowSpaceForDataCentric(
                    (void *)((uint64_t)(info->start) + sym.st_value),
                    (uint32_t)sym.st_size, &dataHandle);
            }
        }
    }
}

static void
ComputeVarBounds(void *drcontext, const module_data_t *info, bool loaded)
{
    // cerr << "ComputeVarBounds" << endl;
    char filename[PATH_MAX];
    char *result = realpath(info->full_path, filename);

    if (result == NULL) {
        dr_printf("%s ---- failed to resolve path \n", info->full_path);
    }
    ComputeStaticVar(filename, info);
}

static void
DeleteStaticVar(void *drcontext, const module_data_t *info)
{
}


DR_EXPORT
bool
drcctlib_init(void)
{
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&drcctlib_init_count, 1);
    if (count > 1)
        return true;
    
    if (!drmgr_init()) {
        dr_printf("WARNING: drcctlib unable to initialize drmgr\n");
        return false;
    }
    if (!drutil_init()) {
        dr_printf("WARNING: drcctlib unable to initialize drutil\n");
        return false;
    }
    if (!drwrap_init() || !drwrap_set_global_flags(DRWRAP_SAFE_READ_ARGS)) {
        dr_printf("WARNING: drcctlib unable to initialize drwrap\n");
        return false;
    }
    if (drsym_init(0) != DRSYM_SUCCESS) {
        dr_printf("WARNING: drcctlib unable to initialize drsym\n");
        return false;
    }
    disassemble_set_syntax(DR_DISASM_DRCCTLIB);

    drcctlib_init_global_buff();

    drmgr_register_signal_event(drcctlib_event_signal);

    if (!drmgr_register_bb_instrumentation_event(drcctlib_event_bb_analysis,
                                                 drcctlib_event_bb_insert, NULL)) {
        dr_printf("WARNING: drcctlib fail to register bb instrumentation event\n");                                             
        return false;
    }

    hashtable_init_ex(&global_bb_shadow_table, BB_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!strdup*/, false /*!synch*/, bb_shadow_free, NULL,
                      NULL);
    hashtable_init_ex(&global_pt_cache_map, PT_CACHE_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!strdup*/, false /*!synch*/, pt_cache_free, NULL,
                      NULL);
    drcctlib_lock_create();

    drmgr_register_module_load_event(drcctlib_event_module_analysis);

    // This will perform hpc_var_bounds functionality on each image load
    drmgr_register_module_load_event(ComputeVarBounds);
    // delete image from the list at the unloading callback
    drmgr_register_module_unload_event(DeleteStaticVar);

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
    dr_printf("drcctlib_exit =========\n");
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&drcctlib_init_count, -1);
    if (count != 0)
        return;
    drcctlib_print_stats();
    if (!drmgr_unregister_bb_instrumentation_event(drcctlib_event_bb_analysis) ||
        // !drmgr_unregister_bb_insertion_event(drcctlib_event_bb_insert) ||
        !drmgr_unregister_module_load_event(drcctlib_event_module_analysis) ||
        !drmgr_unregister_signal_event(drcctlib_event_signal) ||
        !drmgr_unregister_thread_init_event(drcctlib_event_thread_start) ||
        !drmgr_unregister_thread_exit_event(drcctlib_event_thread_end) ||
        !drmgr_unregister_tls_field(tls_idx))
        {
            dr_printf("failed to unregister in drcctlib_exit\n");
            dr_exit_process(-1);
        }
    
    drmgr_unregister_module_load_event(ComputeVarBounds);
    drmgr_unregister_module_unload_event(DeleteStaticVar);


    hashtable_delete(&global_bb_shadow_table);
    hashtable_delete(&global_pt_cache_map);
    drcctlib_lock_destroy();

    drmgr_exit();
    drutil_exit();
    drwrap_exit();
    if (drsym_exit() != DRSYM_SUCCESS) {
        dr_printf("failed to clean up symbol library\n");
        dr_exit_process(-1);
    }
    // free cct_ip_node and cct_bb_node
    drcctlib_free_global_buff();

    dr_close_file(global_logfile);
    dr_printf("finish drcctlib_exit =========\n");
}

DR_EXPORT
void
drcctlib_set_instr_instrument_filter(drcctlib_interest_filter_t interest_filter)
{
    global_interest_filter = interest_filter;
}

DR_EXPORT
void
drcctlib_set_instr_instrument_cb(drcctlib_instr_instrument_cb_t pre_cb, void *pre_data,
                                 drcctlib_instr_instrument_cb_t post_cb, void *post_data)
{
    global_instr_instrument_pre_cb_str.callback = pre_cb;
    global_instr_instrument_pre_cb_str.data = pre_data;
    global_instr_instrument_post_cb_str.callback = post_cb;
    global_instr_instrument_post_cb_str.data = post_data;
}

DR_EXPORT
bool
drcctlib_set_global_flags(drcctlib_global_flags_t flags)
{
    drcctlib_global_flags_t old_flags;
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
drcctlib_config_logfile(file_t file)
{
    global_logfile = file;
}

DR_EXPORT
file_t
drcctlib_get_log_file()
{
    return global_logfile;
}


DR_EXPORT bool
drcctlib_init_ex(drcctlib_interest_filter_t filter, file_t file,
                drcctlib_instr_instrument_cb_t post_cb, void *post_cb_data)
{
    if (!drcctlib_init()) {
        return false;
    }
    drcctlib_set_instr_instrument_filter(filter);
    drcctlib_config_logfile(file);
    drcctlib_set_instr_instrument_cb(NULL, NULL, post_cb, post_cb_data);
    return true;
}




static per_thread_t *
pt_get_from_gcache_by_id(pt_id_t id)
{
    pt_cache_t *cache = (pt_cache_t *)hashtable_lookup(&global_pt_cache_map, (void*)(ptr_int_t)(id));
    if (cache->dead) {
        return cache->cache_data;
    } else {
        return cache->active_data;
    }
}

static pt_id_t
bb_is_thread_root(cct_bb_node_t *bb)
{
    for (pt_id_t id = 0; id < global_thread_id_max; id++) {
        per_thread_t *pt = pt_get_from_gcache_by_id(id);
        if (pt->root_bb_node == bb){
            return id;
        }
    }
    return -1;
}

static inline context_t *
ctxt_create(context_handle_t ctxt_hndl, int line_no, app_pc ip)
{
    context_t* ctxt = (context_t*)dr_global_alloc(sizeof(context_t));
    ctxt->ctxt_hndl = ctxt_hndl;
    ctxt->line_no = line_no;
    ctxt->ip = ip;
    ctxt->pre_ctxt = NULL;
    return ctxt;
}

static inline context_t*
ctxt_get_from_ctxt_hndl(context_handle_t handle)
{
    cct_ip_node_t * ip = drcctlib_ctxt_to_ip(handle);
    cct_bb_node_t *bb = ip->parent_bb_node;
    pt_id_t id = -1;
    if ((id = bb_is_thread_root(bb)) != -1){
        context_t *ctxt = ctxt_create(handle, 0, 0);
        sprintf(ctxt->func_name, "THREAD[%d]_ROOT_CTXT", id);
        sprintf(ctxt->file_path, " ");
        sprintf(ctxt->code_asm, " ");
        return ctxt;
    }
    bb_shadow_t *shadow = (bb_shadow_t *)hashtable_lookup(&global_bb_shadow_table, (void*)(ptr_int_t)(bb->key));
    app_pc addr = shadow->ip_shadow[handle - bb->child_ctxt_start_idx];
    char* code = shadow->disasm_shadow + (handle - bb->child_ctxt_start_idx)*DISASM_CACHE_SIZE;
    

    drsym_error_t symres;
    drsym_info_t sym;
    char name[MAXIMUM_SYMNAME];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        context_t *ctxt = ctxt_create(handle, 0, addr);
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
            ctxt = ctxt_create(handle, 0, addr);
        } else {
            ctxt = ctxt_create(handle, sym.line, addr);
        }
        sprintf(ctxt->func_name, "%s", sym.name);
        sprintf(ctxt->file_path, "%s", data->full_path);
        sprintf(ctxt->code_asm, "%s", code);
        dr_free_module_data(data);
        return ctxt;
    } else {
        context_t *ctxt = ctxt_create(handle, 0, addr);
        sprintf(ctxt->func_name, "<noname>");
        sprintf(ctxt->file_path, "%s", data->full_path);
        sprintf(ctxt->code_asm, "%s", code);
        dr_free_module_data(data);
        return ctxt;
    }
}

DR_EXPORT
void
drcctlib_print_ctxt_hndle_msg(context_handle_t handle, bool print_asm, bool print_file_path)
{
    context_t* ctxt = ctxt_get_from_ctxt_hndl(handle);
    if(print_asm && print_file_path){
        dr_fprintf(global_logfile, "(%s)%d:\"(%p)%s\"[%s]\n",
               ctxt->func_name, ctxt->line_no, (uint64_t)ctxt->ip, ctxt->code_asm, ctxt->file_path);
    } else if(print_asm){
        dr_fprintf(global_logfile, "(%s)%d:\"(%p)%s\"\n",
               ctxt->func_name, ctxt->line_no, (uint64_t)ctxt->ip, ctxt->code_asm);
    } else if(print_file_path) {
        dr_fprintf(global_logfile, "(%s)%d:\"(%p)\"[%s]\n",
               ctxt->func_name, ctxt->line_no, (uint64_t)ctxt->ip, ctxt->file_path);
    } else {
        dr_fprintf(global_logfile, "(%s)%d:\"(%p)\"\n",
               ctxt->func_name, ctxt->line_no, (uint64_t)ctxt->ip);
    }
    
}

DR_EXPORT
void
drcctlib_print_full_cct(context_handle_t handle, bool print_asm, bool print_file_path)
{
    if (!drcctlib_ctxt_is_valid(handle)) {
        dr_printf("drcctlib_print_full_cct: !drcctlib_ctxt_is_valid \n");
        return;
    }
    dr_fprintf(global_logfile, "\n\n");
    // drcctlib_print_ctxt_hndle_msg(handle,true,true);
    dr_fprintf(global_logfile, "\n++++++calling context++++++\n");
    int depth = 0;
    while (drcctlib_ctxt_is_valid(handle) && (depth < MAX_CCT_PRINT_DEPTH)) {
        drcctlib_print_ctxt_hndle_msg(handle, print_asm, print_file_path);
        cct_bb_node_t *bb = drcctlib_ctxt_to_ip(handle)->parent_bb_node;
        handle = bb->caller_ctxt_hndl;
        depth++;
        if (depth >= MAX_CCT_PRINT_DEPTH) {
            dr_fprintf(global_logfile, "Truncated call path (due to deep call chain)\n");
        }
    }
}

DR_EXPORT
context_t *
drcctlib_get_full_cct(context_handle_t handle)
{
    if (!drcctlib_ctxt_is_valid(handle)) {
        dr_printf("drcctlib_get_full_cct res: !drcctlib_ctxt_is_valid\n");
        return NULL;
    }

    context_t *start = ctxt_get_from_ctxt_hndl(handle);
    context_t *next = start;
    int depth = 1;

    handle = drcctlib_ctxt_to_ip(handle)->parent_bb_node->caller_ctxt_hndl;
    while (drcctlib_ctxt_is_valid(handle) && (depth < MAX_CCT_PRINT_DEPTH)) {
        context_t* ctxt = ctxt_get_from_ctxt_hndl(handle);
        next->pre_ctxt = ctxt;
        next = ctxt;
        depth++;
        handle = drcctlib_ctxt_to_ip(handle)->parent_bb_node->caller_ctxt_hndl;
        if (depth >= MAX_CCT_PRINT_DEPTH) {
            context_t *ctxt = ctxt_create(handle, 0, 0);
            sprintf(ctxt->func_name, "Truncated call path (due to deep call chain)");
            sprintf(ctxt->file_path, " ");
            sprintf(ctxt->code_asm, " ");
            next->pre_ctxt = ctxt;
            next = ctxt;
        }
    }
    return start;
}

DR_EXPORT
context_handle_t
drcctlib_get_context_handle(void *drcontext, const slot_t slot)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if(slot >= pt->cur_bb_node->max_slots){
        dr_printf("drcctlib_get_context_handle error\n");
        dr_exit_process(-1);
    }
    return pt->cur_bb_node->child_ctxt_start_idx + slot;
}

DR_EXPORT
bool
have_same_caller_prefix(context_handle_t ctxt1, context_handle_t ctxt2)
{
    if (ctxt1 == ctxt2)
        return true;
    context_handle_t t1 =
        drcctlib_ctxt_to_ip(ctxt1)->parent_bb_node->caller_ctxt_hndl;
    context_handle_t t2 =
        drcctlib_ctxt_to_ip(ctxt2)->parent_bb_node->caller_ctxt_hndl;
    return t1 == t2;
}

DR_EXPORT
void
drcctlib_instr_instrument_list_add(drcctlib_instr_instrument_list_t *list,
                                   drcctlib_instr_instrument_t *ninstrument)
{
    instr_instrument_list_add(list, ninstrument);
}

DR_EXPORT
context_handle_t
drcctlib_get_caller_handle(context_handle_t hndl)
{
    cct_bb_node_t* bb_node = drcctlib_ctxt_to_ip(hndl)->parent_bb_node;
    return bb_node->caller_ctxt_hndl;
}


static inline bool
test_is_app_ctxt_hndl(context_handle_t handle)
{
    if(!drcctlib_ctxt_is_valid(handle)) {
        dr_printf("!!!!!!!!!!");
        return false;
    }
    cct_bb_node_t * bb = drcctlib_ctxt_to_ip(handle)->parent_bb_node;
    if(bb->key == -1) {
        return false;
    }
    bb_shadow_t *shadow = (bb_shadow_t *)hashtable_lookup(
        &global_bb_shadow_table, (void*)(ptr_int_t)(bb->key));
    app_pc addr = shadow->ip_shadow[handle - bb->child_ctxt_start_idx];
    module_data_t *data = dr_lookup_module(addr);
    const char *app_path = "/home/dolanwm/Github/drcctlib/appsamples/build/sample";
    return strcmp(data->full_path, app_path) == 0;
}

DR_EXPORT
void
test_print_app_ctxt_hndl_msg(context_handle_t handle)
{
    if(test_is_app_ctxt_hndl(handle)){
        drcctlib_print_ctxt_hndle_msg(handle, false, false);
    }
}

DR_EXPORT
void
test_print_app_ctxt_hndl_cct(context_handle_t handle)
{
    // dr_printf("test_print_app_ctxt_hndl_cct ");
    if(test_is_app_ctxt_hndl(handle)){
        // dr_printf("-- test_is_app_ctxt_hndl\n");
        drcctlib_print_full_cct(handle, false, false);
    }
}



// API to get the handle for a data object
DR_EXPORT
DataHandle_t
GetDataObjectHandle(void *drcontext, void *address)
{
    DataHandle_t dataHandle;
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // if it is a stack location, set so and return
    if (address > pt->stack_end && address < pt->stack_base) {
        dataHandle.objectType = STACK_OBJECT;
        return dataHandle;
    }
#if __cplusplus > 199711L
    dataHandle = *(GetOrCreateShadowAddress<0>(g_DataCentricShadowMemory,
                                               (size_t)(uint64_t)address));
#else
    dataHandle = *(
        GetOrCreateShadowAddress_0(g_DataCentricShadowMemory, (size_t)(uint64_t)address));
#endif
    return dataHandle;
}

DR_EXPORT
char *
GetStringFromStringPool(int index)
{
    return global_string_pool+ index;
}