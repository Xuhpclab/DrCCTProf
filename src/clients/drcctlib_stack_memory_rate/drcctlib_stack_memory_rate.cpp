/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"
#include "drcctlib_ext.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("stack_memory_rate", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("stack_memory_rate", _FORMAT, ##_ARGS)

static int tls_idx;

typedef struct _per_thread_t {
    uint64_t cur_mem_idx;
    bool init_stack_config;
    thread_stack_config_t stack_config;
    uint64_t number1;
    uint64_t number2;
} per_thread_t;

#define SAMPLE_RUN
#ifdef SAMPLE_RUN
#    define UNITE_NUM 1000000000
#    define SAMPLE_NUM 100000000
#endif

static uint64_t global_number1 = 0;
static uint64_t global_number2 = 0;

static inline void
Collect(per_thread_t *pt, app_pc addr)
{
    if (addr > pt->stack_config.stack_end && addr < pt->stack_config.stack_base) {
        pt->number2++;
    }
    pt->number1++;
    pt->cur_mem_idx++;
}

// client want to do
static inline void
DoWhatClientWantTodo(void *drcontext, per_thread_t *pt, context_handle_t cur_ctxt_hndl,
                     app_pc addr)
{
#ifdef SAMPLE_RUN
    if (pt->cur_mem_idx % UNITE_NUM <= SAMPLE_NUM) {
        Collect(pt, addr);
    }
#else
    Collect(pt, addr);
#endif
}

static inline void
InstrumentPerBBCache(void *drcontext, context_handle_t ctxt_hndl, int32_t slot_num,
                     int32_t mem_ref_num, mem_ref_msg_t *mem_ref_start, void **data)
{
    per_thread_t *pt;
    if (*data != NULL) {
        pt = (per_thread_t *)*data;
    } else {
        pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        *data = pt;
    }
    if (!pt->init_stack_config) {
        pt->stack_config = drcctlib_get_thread_stack_config(drcontext);
        pt->init_stack_config = true;
        DRCCTLIB_PRINTF("pt %d stack_base %p, stack_end %p", pt->stack_config.thread_id,
                        pt->stack_config.stack_base, pt->stack_config.stack_base);
    }
    for (int32_t i = 0; i < mem_ref_num; i++) {
        if (mem_ref_start[i].slot >= slot_num) {
            break;
        }
        DoWhatClientWantTodo(drcontext, pt, ctxt_hndl + mem_ref_start[i].slot,
                             mem_ref_start[i].addr);
    }
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_mem_idx = 0;
    pt->init_stack_config = false;
    pt->number1 = 0;
    pt->number2 = 0;
}
void *lock;
static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    dr_mutex_lock(lock);
    global_number1 += pt->number1;
    global_number2 += pt->number2;
    dr_mutex_unlock(lock);

    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    lock = dr_mutex_create();
}

static void
ClientExit(void)
{
    drcctlib_exit();

    DRCCTLIB_PRINTF("global_number1 : %llu globalnumber2: %llu rate %.2f", global_number1,
                    global_number2, (float)global_number2 / global_number1);
    dr_mutex_destroy(lock);

    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_stack_memory_rate failed to unregister in ClientExit");
    }
    drmgr_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_stack_memory_rate'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_stack_memory_rate unable to initialize drmgr");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "drcctlib_stack_memory_rate-thread_init", NULL,
                                         NULL, DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "drcctlib_stack_memory_rate-thread-exit", NULL,
                                         NULL, DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri);
    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_stack_memory_rate drmgr_register_tls_field fail");
    }
    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache,
                     DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE | DRCCTLIB_CACHE_MODE |
                         DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif