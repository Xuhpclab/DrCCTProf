#ifndef _DRCCTLIB_H_
#define _DRCCTLIB_H_

#include "dr_api.h"
#include "drcctlib_global_share.h"
#include "drcctlib_filter_func_list.h"

#define context_handle_t int32_t
#ifdef CCTLIB_32
#define aligned_ctxt_hndl_t int32_t
#else 
#define aligned_ctxt_hndl_t int64_t
#endif

#define CONTEXT_HANDLE_MAX 7483647L
// #define CONTEXT_HANDLE_MAX 2147483647L // 1^31 - 1
#define DISASM_CACHE_SIZE 80
#define MAXIMUM_SYMNAME 256

// The handle representing a data object
typedef struct data_handle_t {
    uint8_t object_type;
    union {
        context_handle_t path_handle;
        int32_t sym_name;
    };
} data_handle_t;

enum{ 
    STACK_OBJECT, 
    DYNAMIC_OBJECT, 
    STATIC_OBJECT, 
    UNKNOWN_OBJECT
};
enum {
    INSTR_STATE_CLIENT_INTEREST = 0x01,
    INSTR_STATE_CALL_DIRECT = 0x02,
    INSTR_STATE_CALL_IN_DIRECT = 0x04,
    INSTR_STATE_RETURN = 0x08,
    INSTR_STATE_UNINTEREST_FIRST = 0X10,
    INSTR_STATE_THREAD_ROOT_VIRTUAL = 0x20,
    INSTR_STATE_EVENT_SIGNAL = 0x40,
    INSTR_STATE_EVENT_EXCEPTION = 0x80,
#ifdef ARM_CCTLIB 
    INSTR_STATE_BB_START_NOP = 0X100
#endif
};

typedef struct _instr_instrument_msg_t {
    instrlist_t *bb;
    instr_t *instr;
    bool interest_start;
    int32_t slot;
    int32_t state;
    struct _instr_instrument_msg_t *next;
} instr_instrument_msg_t;

typedef struct _context_t {
    char func_name[MAXIMUM_SYMNAME];
    char file_path[MAXIMUM_PATH];
    char code_asm[DISASM_CACHE_SIZE];
    context_handle_t ctxt_hndl;
    int line_no;
    app_pc ip;
    struct _context_t *pre_ctxt;
} context_t;

enum {
    DRCCTLIB_DEFAULT = 0x00,
    DRCCTLIB_USE_CLEAN_CALL = 0x01,
    DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE = 0x02,
    DRCCTLIB_SAVE_CCTLIB_FILE = 0x04,
    DRCCTLIB_SAVE_HPCTOOLKIT_FILE = 0x08
};

DR_EXPORT
bool
drcctlib_init_ex(bool (*filter)(instr_t *), file_t file,
                 void (*func1)(void *, instr_instrument_msg_t *, void *), void *data1,
                 void (*func2)(void *), void *data2, char flag);

DR_EXPORT
void
drcctlib_exit(void);

DR_EXPORT
void
drcctlib_register_instr_filter(bool (*filter)(instr_t *));

DR_EXPORT
void
drcctlib_register_client_cb(void (*func_instr_analysis)(void *, instr_instrument_msg_t *,
                                                        void *),
                            void *analysis_data, void (*func_insert_bb_start)(void *),
                            void *insert_data);

DR_EXPORT
void
drcctlib_config_log_file(file_t file);

DR_EXPORT
file_t
drcctlib_get_log_file();

DR_EXPORT
int
drcctlib_get_per_thread_date_id();

DR_EXPORT
void
drcctlib_print_ctxt_hndl_msg(file_t file, context_handle_t ctxt_hndl, bool print_asm, bool print_file_path);

DR_EXPORT
void
drcctlib_print_full_cct(file_t file, context_handle_t ctxt_hndl, bool print_asm, bool print_file_path, int max_depth);

DR_EXPORT
context_t *
drcctlib_get_full_cct(context_handle_t ctxt_hndl, int max_depth);

DR_EXPORT
context_handle_t
drcctlib_get_context_handle();

DR_EXPORT
context_handle_t
drcctlib_get_bb_start_context_handle();

DR_EXPORT
void
drcctlib_get_context_handle_in_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                   reg_id_t store_reg);

DR_EXPORT
void
drcctlib_get_bb_start_context_handle_in_reg(void *drcontext, instrlist_t *ilist, instr_t *where,
                                            reg_id_t store_reg);

DR_EXPORT
context_handle_t
drcctlib_get_caller_handle(context_handle_t ctxt_hndl);

DR_EXPORT
context_handle_t
drcctlib_get_global_context_handle_num();

DR_EXPORT
bool
drcctlib_ctxt_hndl_is_valid(context_handle_t ctxt_hndl);

DR_EXPORT
app_pc
drcctlib_get_pc(context_handle_t ctxt_hndl);

DR_EXPORT
bool
have_same_caller_prefix(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2);




DR_EXPORT
data_handle_t
drcctlib_get_date_hndl(void *drcontext, void *address);

DR_EXPORT
char *
drcctlib_get_str_from_strpool(int index);

#endif // _DRCCTLIB_H_
