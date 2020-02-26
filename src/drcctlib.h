#ifndef _DRCCTLIB_H_
#define _DRCCTLIB_H_

#include "drcctlib_global_share.h"

#define bb_key_t drcctlib_key_t
#define BB_KEY_MAX DRCCTLIB_KEY_MAX
#define ATOM_GET_NEXT_BB_KEY(origin) ATOM_DRCCTLIB_KEY_ADD(origin, 1)
#define OPND_CREATE_BB_KEY OPND_CREATE_DRCCTLIB_KEY

#define context_handle_t int
#define CONTEXT_HANDLE_MAX 2147483647L // 1^31 - 1
#define ATOM_ADD_CTXT_HNDL(origin, val) dr_atomic_add32_return_sum(&origin, val)

#define slot_t int
#define OPND_CREATE_SLOT OPND_CREATE_INT32
#define pt_id_t int
#define ATOM_ADD_THREAD_ID_MAX(origin) dr_atomic_add32_return_sum(&origin, 1)
#define ATOM_ADD_STRING_POOL_INDEX(origin, val) dr_atomic_add32_return_sum(&origin, val)

enum {
    DRCCTLIB_INSTR_INSTRUMENT_CCT_BB_ENTRY = -500, /**< Priority of  */
    DRCCTLIB_INSTR_INSTRUMENT_CCT_PRE = 100,
    DRCCTLIB_INSTR_INSTRUMENT_USER_PRE = 250, /**< Priority of  */
    DRCCTLIB_INSTR_INSTRUMENT_CCT_CALL = 500, /**< Priority of  */
    DRCCTLIB_INSTR_INSTRUMENT_CCT_RETRUN = 500, /**< Priority of  */
    DRCCTLIB_INSTR_INSTRUMENT_CCT_NORMAL = 500,
    DRCCTLIB_INSTR_INSTRUMENT_USER_POST = 750, /**< Priority of  */
    DRCCTLIB_INSTR_INSTRUMENT_CCT_POST = 900,
    DRCCTLIB_INSTR_INSTRUMENT_EXCEPTION_CHECK = 1000 /**< Priority of  */
};
#define drcctlib_instr_instrument_pri_t int


enum { 
    DRCCTLIB_INSTR_STATE_USER_INTEREST = 0x01,
    DRCCTLIB_INSTR_STATE_CALL_DIRECT = 0x02,
    DRCCTLIB_INSTR_STATE_CALL_IN_DIRECT = 0x04,
    DRCCTLIB_INSTR_STATE_RETURN = 0x08
};
#define drcctlib_instr_state_flag_t int


// The handle representing a data object
typedef struct DataHandle_t {
    uint8_t objectType;
    union {
        context_handle_t pathHandle;
        int symName;
    };
} DataHandle_t;

enum{ 
    STACK_OBJECT, 
    DYNAMIC_OBJECT, 
    STATIC_OBJECT, 
    UNKNOWN_OBJECT
};

typedef struct _context_t {
    char func_name[MAXIMUM_SYMNAME];
    char file_path[MAXIMUM_PATH];
    char code_asm[MAXIMUM_SYMNAME];
    context_handle_t ctxt_hndl;
    int line_no;
    app_pc ip;
    struct _context_t *pre_ctxt;
} context_t;

enum {
    DRCCTLIB_DEFAULT = 0x00,
    DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE = 0x0001,
    DRCCTLIB_SAVE_CCTLIB_FILE = 0x02,
    DRCCTLIB_SAVE_HPCTOOLKIT_FILE = 0x04
};
#define drcctlib_global_flags_t int


typedef struct _drcctlib_instr_instrument_t {
    instr_t *instr;
    drcctlib_instr_instrument_pri_t priority;
    void *callee;
    int num_args;
    opnd_t *args_array;
    struct _drcctlib_instr_instrument_t *next;
    struct _drcctlib_instr_instrument_t *pre;
} drcctlib_instr_instrument_t;

typedef struct _drcctlib_instr_instrument_list_t {
    drcctlib_instr_instrument_t *first;
    drcctlib_instr_instrument_t *last;
    drcctlib_instr_instrument_t *next_insert;
    uint64_t instrument_num;
    uint64_t bb_key;
} drcctlib_instr_instrument_list_t;



typedef void (*drcctlib_instr_instrument_cb_t)(drcctlib_instr_instrument_list_t *, instr_t *, slot_t,
                   drcctlib_instr_instrument_pri_t, void *);

typedef bool(*drcctlib_interest_filter_t)(instr_t * instr);


DR_EXPORT
bool
drcctlib_filter_0_instr(instr_t *instr)
{
    return false;
}

DR_EXPORT
bool
drcctlib_filter_all_instr(instr_t *instr)
{
    return true;
}

DR_EXPORT
bool
drcctlib_filter_mem_access_instr(instr_t *instr)
{
    return (instr_reads_memory(instr) || instr_writes_memory(instr));
}

#define DRCCTLIB_FILTER_ZERO_INSTR drcctlib_filter_0_instr
#define DRCCTLIB_FILTER_ALL_INSTR drcctlib_filter_all_instr
#define DRCCTLIB_FILTER_MEM_ACCESS_INSTR drcctlib_filter_mem_access_instr


DR_EXPORT
bool
drcctlib_init(void);

DR_EXPORT
bool
drcctlib_init_ex(drcctlib_interest_filter_t filter, file_t file, drcctlib_instr_instrument_cb_t post_cb,
                 void *post_cb_data);

DR_EXPORT
void
drcctlib_exit(void);

DR_EXPORT
void
drcctlib_set_instr_instrument_filter(bool (*interesting_filter)(instr_t *));

DR_EXPORT
void
drcctlib_set_instr_instrument_cb(drcctlib_instr_instrument_cb_t pre_cb, void *pre_cb_data,
                                 drcctlib_instr_instrument_cb_t post_cb,
                                 void *post_cb_data);

DR_EXPORT bool
drcctlib_set_global_flags(drcctlib_global_flags_t flags);

DR_EXPORT
void
drcctlib_config_logfile(file_t file);

DR_EXPORT
file_t
drcctlib_get_log_file();

DR_EXPORT
drcctlib_instr_instrument_t *
instr_instrument_create(instr_t *instr, void *callee,
                        drcctlib_instr_instrument_pri_t priority, int num_args, ...);

DR_EXPORT
void
drcctlib_instr_instrument_list_add(drcctlib_instr_instrument_list_t *list,
                          drcctlib_instr_instrument_t *ninstrument);

DR_EXPORT
void
drcctlib_print_ctxt_hndle_msg(context_handle_t handle, bool print_asm, bool print_file_path);

DR_EXPORT
void
drcctlib_print_full_cct(context_handle_t handle, bool print_asm, bool print_file_path);

DR_EXPORT
context_t *
drcctlib_get_full_cct(context_handle_t handle);

DR_EXPORT
context_handle_t
drcctlib_get_context_handle(void *drcontext, const slot_t slot);

DR_EXPORT
context_handle_t
drcctlib_get_caller_handle(context_handle_t handle);

DR_EXPORT
bool
drcctlib_ctxt_is_valid(context_handle_t ctxt);

DR_EXPORT
bool
have_same_caller_prefix(context_handle_t ctxt1, context_handle_t ctxt2);

DR_EXPORT
void
test_print_app_ctxt_hndl_msg(context_handle_t handle);

DR_EXPORT
void
test_print_app_ctxt_hndl_cct(context_handle_t cur_ctxt_hndl);


DR_EXPORT
DataHandle_t
GetDataObjectHandle(void *drcontext, void *address);

DR_EXPORT
char *
GetStringFromStringPool(int index);



#endif // _DRCCTLIB_H_
