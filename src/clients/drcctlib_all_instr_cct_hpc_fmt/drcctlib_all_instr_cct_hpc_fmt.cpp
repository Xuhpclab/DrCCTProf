/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drmgr.h"

#include "drcctlib.h"
#include "drcctlib_hpcviewer_format.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("all_instr_cct_hpc_fmt", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("all_instr_cct_hpc_fmt", _FORMAT, ##_ARGS)

static void
ClientThreadStart(void *drcontext)
{
}

static void
ClientThreadEnd(void *drcontext)
{
    write_thread_all_cct_hpcrun_format(drcontext);
}

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd)) {
        DRCCTLIB_PRINTF("failed to unregister in ClientExit");
    }
    drmgr_exit();

    drcctlib_exit();
    hpcrun_format_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_all_instr_cct_hpc_fmt'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_instr_statistics unable to initialize drmgr");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "drcctlib_reuse-thread_init", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "drcctlib_reuse-thread-exit", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri);

    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL, NULL,
                     DRCCTLIB_CACHE_MODE);
    hpcrun_format_init(dr_get_application_name(), true);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif