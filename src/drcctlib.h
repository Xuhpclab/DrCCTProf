#ifndef _DRCCTLIB_H_
#define _DRCCTLIB_H_

#include "dr_api.h"
#include "drcctlib_global_share.h"
#include "drcctlib_filter_func_list.h"
#include "drcctlib_debug.h"

#if defined(ARM) || defined(AARCH64)
#define ARM_CCTLIB
#endif

#define context_handle_t int32_t
// #define CONTEXT_HANDLE_MAX 7483647L
#define CONTEXT_HANDLE_MAX 2147483647L // 1^31 - 1
#define DISASM_CACHE_SIZE 80
#define MAXIMUM_SYMNAME 256

// The handle representing a data object
// typedef struct DataHandle_t {
//     uint8_t objectType;
//     union {
//         context_handle_t pathHandle;
//         int symName;
//     };
// } DataHandle_t;

// enum{ 
//     STACK_OBJECT, 
//     DYNAMIC_OBJECT, 
//     STATIC_OBJECT, 
//     UNKNOWN_OBJECT
// };

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
    DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE = 0x01,
    DRCCTLIB_SAVE_CCTLIB_FILE = 0x02,
    DRCCTLIB_SAVE_HPCTOOLKIT_FILE = 0x04
};


DR_EXPORT
bool
drcctlib_init(void);

DR_EXPORT
bool
drcctlib_init_ex(bool (*filter)(instr_t *), file_t file,
                 void (*func)(void *, instrlist_t *, instr_t *, void *), void *data);

DR_EXPORT
void
drcctlib_exit(void);

DR_EXPORT
void
drcctlib_register_instr_filter(bool (*filter)(instr_t *));

DR_EXPORT
void
drcctlib_register_client_cb(void (*func)(void *, instrlist_t *, instr_t *, void *),
                            void *data);

DR_EXPORT
bool
drcctlib_set_global_flags(char flags);

DR_EXPORT
void
drcctlib_config_log_file(file_t file);

DR_EXPORT
file_t
drcctlib_get_log_file();

DR_EXPORT
int
drcctlib_get_per_thread_date_id();

// DR_EXPORT
// void
// drcctlib_instr_instrument_list_add(void * instrument_list, instr_t * instr, void *callee, int priority, int num_args, ...);


DR_EXPORT
void
drcctlib_print_ctxt_hndl_msg(context_handle_t ctxt_hndl, bool print_asm, bool print_file_path);

DR_EXPORT
void
drcctlib_print_full_cct(context_handle_t ctxt_hndl, bool print_asm, bool print_file_path, int max_depth);

DR_EXPORT
context_t *
drcctlib_get_full_cct(context_handle_t ctxt_hndl, int max_depth);

DR_EXPORT
context_handle_t
drcctlib_get_context_handle();

DR_EXPORT
context_handle_t
drcctlib_get_caller_handle(context_handle_t ctxt_hndl);

DR_EXPORT
context_handle_t
drcctlib_get_global_context_handle_num();

DR_EXPORT
int64_t *
drcctlib_get_global_gloabl_hndl_call_num_buff();

DR_EXPORT
bool
drcctlib_ctxt_hndl_is_valid(context_handle_t ctxt_hndl);

DR_EXPORT
app_pc
drcctlib_get_pc(context_handle_t ctxt_hndl);

DR_EXPORT
bool
have_same_caller_prefix(context_handle_t ctxt_hndl1, context_handle_t ctxt_hndl2);




// DR_EXPORT
// DataHandle_t
// GetDataObjectHandle(void *drcontext, void *address);

// DR_EXPORT
// char *
// GetStringFromStringPool(int index);

#ifdef DRCCTLIB_DEBUG
DR_EXPORT
bool
test_is_app_ctxt_hndl(context_handle_t ctxt_hndl);

DR_EXPORT
void
test_print_app_ctxt_hndl_msg(context_handle_t ctxt_hndl);

DR_EXPORT
void
test_print_app_ctxt_hndl_cct(context_handle_t ctxt_hndl);

#endif

#endif // _DRCCTLIB_H_
