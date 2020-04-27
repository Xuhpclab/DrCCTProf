#include <iostream>
#include <string.h>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <unistd.h>
#include <vector>

#include <sys/resource.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                             \
    do {                                                                             \
        char name[MAXIMUM_PATH] = "";                                                \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));               \
        pid_t pid = getpid();                                                        \
        dr_printf("[(%s%d)drcctlib_instr_statistics msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                      \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[(%s%d)drcctlib_instr_statistics(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                    \
    dr_exit_process(-1)

static uint64 ins_number = 0;
static uint64 bb_number = 0;
static uint64 call_bb_number = 0;
static uint64 dcall_bb_number = 0;
static uint64 ret_bb_number = 0;

void *count_lock;
static int tls_idx;
typedef struct _per_thread_t {
    uint64 ins_number;
    uint64 bb_number;
    uint64 call_bb_number;
    uint64 dcall_bb_number;
    uint64 ret_bb_number;
} per_thread_t;


void 
BBStartInsertCleancall(uint ct, uint call, uint dcall, uint ret)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    pt->ins_number += ct;
    pt->bb_number++;
    pt->call_bb_number += call;
    pt->dcall_bb_number += dcall;
    pt->ret_bb_number += ret;
}

static dr_emit_flags_t
drcctlib_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data)
{
    instr_t *first_instr = instrlist_first_app(bb);
    if(instr_is_exclusive_store(first_instr)) {
        return DR_EMIT_DEFAULT;
    }
    uint num_instructions = 0;
    instr_t *instr;
    for (instr = instrlist_first_app(bb); instr != NULL; instr = instr_get_next_app(instr)) {
        num_instructions++;
    }
    instr = instrlist_last_app(bb);
    uint call = 0;
    uint dcall = 0;
    uint ret = 0;
    if (instr_is_call_direct(instr)) {
        call = 1;
    } else if (instr_is_call_indirect(instr)) {
        dcall = 1;
    } else if (instr_is_return(instr)) {
        ret = 1;
    }

    dr_insert_clean_call(drcontext, bb, first_instr,
                                 (void *)BBStartInsertCleancall,
                                 false, 4, OPND_CREATE_INT(num_instructions), OPND_CREATE_INT(call), OPND_CREATE_INT(dcall), OPND_CREATE_INT(ret));
    return DR_EMIT_DEFAULT;
}


static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if(pt == NULL){
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);
    pt->ins_number = 0;
    pt->bb_number = 0;
    pt->call_bb_number = 0;
    pt->dcall_bb_number = 0;
    pt->ret_bb_number = 0;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(count_lock);
    ins_number += pt->ins_number;
    bb_number += pt->bb_number;
    call_bb_number += pt->call_bb_number;
    dcall_bb_number += pt->dcall_bb_number;
    ret_bb_number += pt->ret_bb_number;

    dr_mutex_unlock(count_lock);

    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientExit(void)
{
    dr_printf("\n\n ++++++++++ ins_number %llu bb_number %llu", ins_number, bb_number);
    dr_printf("\n ++++++++++ call_bb_number %llu dcall_bb_number %llu ret_bb_number %llu", call_bb_number, dcall_bb_number, ret_bb_number);
    drmgr_unregister_bb_instrumentation_event(drcctlib_event_bb_analysis);
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("failed to unregister in ClientExit");
    }

    dr_mutex_destroy(count_lock);
}


#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_time_overhead_test'",
                       "http://dynamorio.org/issues");

    drmgr_init();
    drmgr_register_bb_instrumentation_event(drcctlib_event_bb_analysis,
                                                 NULL, NULL);
    
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);
    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1){
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_instr_statistics drmgr_register_tls_field fail");
    }

    count_lock = dr_mutex_create();
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif