/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */
#include <vector>

#include "dr_api.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drwrap.h"
#include "drcctlib.h"

#include "dr_go_wrap.h"

using namespace std;

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("goroutines", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("goroutines", _FORMAT, ##_ARGS)

static int tls_idx;
static file_t gTraceFile;
static void *thread_sync_lock;

typedef struct _per_thread_t {
    thread_id_t thread_id;
    vector<context_handle_t> call_rt_exec_list;
    vector<uint64_t> go_g_addr_list;
} per_thread_t;

// client want to do
void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl)
{

}

// dr clean call
void
InsertCleancall(int32_t slot)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    DoWhatClientWantTodo(drcontext, cur_ctxt_hndl);
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    // dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 1,
    //                      OPND_CREATE_CCT_INT(slot));
}

static void
WrapBeforeRTExecute(void *wrapcxt, void **user_data)
{
    void *drcontext = (void *)drwrap_get_drcontext(wrapcxt);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    uint64_t go_g_addr = (uint64_t)dgw_get_go_func_arg(wrapcxt, 0);
    // if (go_g_addr != 0) {
        // int64_t* go_g_goid_ptr = (int64_t*)(go_g_addr + 152);
    //     DRCCTLIB_PRINTF("thread(%ld) runtime.execute to goid(%p)", pt->thread_id, go_g_goid_ptr);
    // } else {
    pt->call_rt_exec_list.push_back(drcctlib_get_context_handle(drcontext));
    pt->go_g_addr_list.push_back(go_g_addr);
    // DRCCTLIB_PRINTF("thread(%ld) runtime.execute to go_g_addr == NULL", pt->thread_id);
    // }
    
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

static void
RegisteBeforeExecute(void *drcontext, const module_data_t *info,
                                    bool loaded)
{
    app_pc func_entry = moudle_get_function_entry(info, "runtime.execute", true);
    if (func_entry != NULL) {
        drwrap_wrap(func_entry, WrapBeforeRTExecute, NULL);
    }
}

static void
PrintAllRTExec(per_thread_t *pt)
{
    dr_mutex_lock(thread_sync_lock);

    for (uint64_t i = 0; i < pt->go_g_addr_list.size(); i++) {
        uint64_t go_g_addr = pt->go_g_addr_list[i];
        int64_t* go_g_goid_ptr = (int64_t*)(go_g_addr + 152);
        context_handle_t exec_ctxt = pt->call_rt_exec_list[i];
        dr_fprintf(gTraceFile, "\n\nthread(%ld) runtime.execute to goid(%d)", pt->thread_id, *go_g_goid_ptr);
        drcctlib_print_ctxt_hndl_msg(gTraceFile, exec_ctxt, false, false);
        dr_fprintf(gTraceFile,
                   "====================================================================="
                   "===========\n");
        drcctlib_print_full_cct(gTraceFile, exec_ctxt, true, true,
                                -1);
        dr_fprintf(gTraceFile,
                   "====================================================================="
                   "===========\n\n\n");
    }
    dr_mutex_unlock(thread_sync_lock);
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);
    pt->thread_id = dr_get_thread_id(drcontext);
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    PrintAllRTExec(pt);
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    char name[MAXIMUM_PATH] = "";
    DRCCTLIB_INIT_LOG_FILE_NAME(name, "drcctlib_goroutines", "out");
    DRCCTLIB_PRINTF("Creating log file at:%s", name);

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");
    for (int i = 0; i < argc; i++) {
        dr_fprintf(gTraceFile, "%d %s ", i, argv[i]);
    }
    dr_fprintf(gTraceFile, "\n");

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "unable to initialize drmgr");
    }
    if (!drwrap_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "unable to initialize drwrap");
    }

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "drmgr_register_tls_field fail");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    drmgr_priority_t before_drcctlib_module_load = { sizeof(before_drcctlib_module_load), "before_drcctlib_module_load",
                                         NULL, NULL, DRCCTLIB_MODULE_REGISTER_PRI + 1 };
    drmgr_register_module_load_event_ex(RegisteBeforeExecute, &before_drcctlib_module_load);

    drcctlib_init(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, InstrumentInsCallback,
                  false);
    if (drsym_init(0) != true) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "unable to initialize drsym");
    }
    thread_sync_lock = dr_mutex_create();
}

static void
ClientExit(void)
{
    drcctlib_exit();
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_goroutines failed to "
            "unregister in ClientExit");
    }
    if (drsym_exit() != DRSYM_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drsym");
    }
    drwrap_exit();
    drmgr_exit();
    dr_mutex_destroy(thread_sync_lock);
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name(
        "DynamoRIO Client 'drcctlib_goroutines'",
        "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif