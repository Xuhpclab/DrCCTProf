/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <iterator>
#include <vector>
#include <map>
#include <algorithm>
#include <sys/time.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"
#include "drcctlib_vscodeex_format.h"

using namespace std;
using namespace DrCCTProf;

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("trace", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("trace", _FORMAT, ##_ARGS)

uint64_t process_start_time;
uint64_t process_end_time;

typedef struct _ctxt_duration_t {
    context_handle_t handle;
    context_handle_t call_handle;
    int32_t depth;
    uint64_t start_time;
    uint64_t end_time;
} ctxt_duration_t;

typedef struct _per_thread_t {
    int64_t thread_id;
    int32_t call_time_stack_num;
    uint64_t thread_start_time;
    vector<context_handle_t>* call_hndl_stack;
    vector<uint64_t>* call_time_stack;
    vector<ctxt_duration_t>* ctxt_duration_list;
    bool last_is_call;
} per_thread_t;

static int tls_idx;

void *lock; 
map<int64_t, vector<ctxt_duration_t>*>* global_duration_map;

bool ctxt_duration_cmp_by_depth (ctxt_duration_t a, ctxt_duration_t b) {
    return a.depth < b.depth;
}

void
InsertBeforeBBStart()
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (pt->last_is_call) {
        context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, 0);
        (*(pt->call_hndl_stack)).push_back(cur_ctxt_hndl);
    }

    pt->last_is_call = false;
}


// dr clean call
void
InsertBeforeCallInsCleancall(int32_t slot)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    (*(pt->call_time_stack)).push_back( (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000));
    pt->call_time_stack_num++;

    context_handle_t call_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    (*(pt->call_hndl_stack)).push_back(call_ctxt_hndl);

    pt->last_is_call = true;
}


// dr clean call
void
InsertBeforeReturnInsCleancall(int32_t slot)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int32_t depth = pt->call_time_stack_num;

    context_handle_t call_ctxt_hndl = cur_ctxt_hndl;
    uint64_t start_time = pt->thread_start_time;
    if (pt->call_time_stack_num > 0) {
        cur_ctxt_hndl = (*(pt->call_hndl_stack)).back();
        (*(pt->call_hndl_stack)).pop_back();
        call_ctxt_hndl = (*(pt->call_hndl_stack)).back();
        (*(pt->call_hndl_stack)).pop_back();
        
        start_time = (*(pt->call_time_stack)).back();
        (*(pt->call_time_stack)).pop_back();

        pt->call_time_stack_num--;
    }
    
    uint64_t end_time =  (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000);
    ctxt_duration_t cur_dur = {
        cur_ctxt_hndl,
        call_ctxt_hndl,
        depth,
        start_time,
        end_time
    };
    (*(pt->ctxt_duration_list)).push_back(cur_dur);

    pt->last_is_call = false;
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    if (slot == 0) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)InsertBeforeBBStart, false, 0);
    } 
    if (instr_is_call_direct(instr) || instr_is_call_indirect(instr)) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)InsertBeforeCallInsCleancall, false, 1, OPND_CREATE_INT32(slot));
    } else if (instr_is_return(instr)) {
        dr_insert_clean_call(drcontext, bb, instr, (void *)InsertBeforeReturnInsCleancall, false, 1, OPND_CREATE_INT32(0));
    }
    
}

// bool
// CustomFilter(instr_t *instr)
// {   if (instr->next && instr_is_return(instr->next)) {
//         return true;
//     }
//     if (instr_is_call_direct(instr) || instr_is_call_indirect(instr) ||
//         instr_is_return(instr)) {
//         return true;
//     }
//     return false;
// }

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);
    
    pt->thread_id = drcctlib_get_thread_id();
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pt->thread_start_time =  (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000);
    pt->call_time_stack_num = 0;
    pt->call_time_stack = new vector<uint64_t>();
    pt->call_hndl_stack =  new vector<context_handle_t>();
    pt->ctxt_duration_list = new vector<ctxt_duration_t>();
    pt->last_is_call = false;

}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(lock);
    (*global_duration_map).insert(pair<int64_t, vector<ctxt_duration_t>*>(pt->thread_id, pt->ctxt_duration_list));
    dr_mutex_unlock(lock);
    delete pt->call_time_stack;
    delete pt->call_hndl_stack;
    // delete pt->ctxt_duration_list;
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    global_duration_map = new map<int64_t, vector<ctxt_duration_t>*>();

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance_vse_fmt unable to initialize drmgr");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "drcctlib_trace-thread_init", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "drcctlib_trace-thread-exit", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri);
    tls_idx = drmgr_register_tls_field();
    lock = dr_mutex_create();
    drcctlib_init(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, InstrumentInsCallback, false);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    process_start_time =  (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000);
}

static void
ClientExit(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    process_end_time =  (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000);

    uint64_t boundary = (process_end_time - process_start_time)/5000;

    Profile::profile_t* trace_profile = new Profile::profile_t();
    trace_profile->add_metric_type(0, " ", "thread id");
    trace_profile->add_metric_type(1, " ", "call context handle");
    trace_profile->add_metric_type(1, " ", "start time");
    trace_profile->add_metric_type(1, " ", "end time");
    for(uint64_t thread_id = 0; thread_id < (*global_duration_map).size(); thread_id ++) {
        vector<ctxt_duration_t>* ctxt_duration_list = (*global_duration_map)[thread_id];
        sort((*ctxt_duration_list).begin(), (*ctxt_duration_list).end(), ctxt_duration_cmp_by_depth);
        DRCCTLIB_PRINTF("thread id %ld size %llu", (int64_t)thread_id, (*ctxt_duration_list).size());
        uint64_t size = 0;
        for (uint64_t i = 0; i < (*ctxt_duration_list).size(); i++) {
            if (((*ctxt_duration_list)[i].end_time - (*ctxt_duration_list)[i].start_time) < boundary) {
                continue;
            }
            size ++;
            inner_context_t* ctxt = drcctlib_get_full_cct((*ctxt_duration_list)[i].handle);
            Profile::sample_t* sample = trace_profile->add_sample(ctxt);
            sample->append_metirc((int64_t)thread_id + 1);
            sample->append_metirc((uint64_t)(*ctxt_duration_list)[i].call_handle);
            sample->append_metirc((*ctxt_duration_list)[i].start_time);
            sample->append_metirc((*ctxt_duration_list)[i].end_time);
            drcctlib_free_full_cct(ctxt);
        }
        DRCCTLIB_PRINTF("thread id %ld size %llu", (int64_t)thread_id, size);
        delete ctxt_duration_list;
    }
    delete global_duration_map;
    trace_profile->serialize_to_file("runtime.trace.drcctprof");
    delete trace_profile;
    drcctlib_exit();
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_trace failed to unregister in ClientExit");
    }
    drmgr_exit();
    dr_mutex_destroy(lock);
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_trace'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif