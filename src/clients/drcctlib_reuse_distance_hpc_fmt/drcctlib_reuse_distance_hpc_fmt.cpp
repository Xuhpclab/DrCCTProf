/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <map>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"
#include "drcctlib_hpcviewer_format.h"

using namespace std;

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("reuse_distance_hpc_fmt", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("reuse_distance_hpc_fmt", _FORMAT, ##_ARGS)

#define SAMPLE_RUN
#ifdef SAMPLE_RUN
#    define UNITE_NUM 1000000000
#    define SAMPLE_NUM 100000000
#endif

#define OUTPUT_SIZE 200
#define REUSED_THRES 8192
#define REUSED_PRINT_MIN_COUNT 1000
#define MAX_CLIENT_CCT_PRINT_DEPTH 10

static int tls_idx;

typedef struct _use_node_t {
    context_handle_t create_hndl;
    context_handle_t use_hndl;
#ifdef SAMPLE_RUN
    uint32_t last_reuse_mem_idx;
    uint32_t sample_run_index;
#else
    uint64_t last_reuse_mem_idx;
#endif
} use_node_t;

struct reuse_node_t {
    context_handle_t create_hndl;
    uint64_t distance;
    uint64_t count;

    reuse_node_t(context_handle_t ch, uint64_t d, uint64_t c)
        : create_hndl(ch)
        , distance(d)
        , count(c)
    {
    }
};

typedef struct _output_format_t {
    context_handle_t create_hndl;
    context_handle_t use_hndl;
    context_handle_t reuse_hndl;
    uint64_t count;
    uint64_t distance;
} output_format_t;

typedef struct _per_thread_t {
#ifdef SAMPLE_RUN
    uint32_t cur_mem_idx;
    uint64_t sample_run_index;
#else
    uint64_t cur_mem_idx;
#endif
    map<uint64_t, use_node_t> *tls_use_map;
    multimap<uint64_t, reuse_node_t> *tls_reuse_map;
// #define DEBUG_REUSE
#ifdef DEBUG_REUSE
    file_t log_file;
#endif
} per_thread_t;

void
UpdateUseAndReuseMap(void *drcontext, per_thread_t *pt, uint64_t cur_mem_idx,
                     context_handle_t cur_ctxt_hndl, app_pc addr)
{
    map<uint64_t, use_node_t> *use_map = pt->tls_use_map;
    map<uint64_t, use_node_t>::iterator it = (*use_map).find((uint64_t)addr);

    if (it != (*use_map).end()) {
#ifdef SAMPLE_RUN
        if (it->second.sample_run_index != pt->sample_run_index) {
            it->second.sample_run_index = pt->sample_run_index;
            it->second.use_hndl = cur_ctxt_hndl;
            it->second.last_reuse_mem_idx = cur_mem_idx;
            it->second.create_hndl = 0;
            return;
        }
#endif
        uint64_t reuse_distance = cur_mem_idx - it->second.last_reuse_mem_idx;
        if (reuse_distance > REUSED_THRES) {
            if(it->second.create_hndl >= 0) {
                data_handle_t data_hndl =
                    drcctlib_get_data_hndl_ignore_stack_data(drcontext, addr);
                context_handle_t create_hndl = 0;
                if (data_hndl.object_type == DYNAMIC_OBJECT) {
                    create_hndl = data_hndl.path_handle;
                } else if (data_hndl.object_type == STATIC_OBJECT) {
                    create_hndl = -data_hndl.sym_name;
                }
                it->second.create_hndl = create_hndl;
            }
            uint64_t new_pair = (((uint64_t)it->second.use_hndl) << 32) + cur_ctxt_hndl;
            multimap<uint64_t, reuse_node_t> *pair_map = pt->tls_reuse_map;
            multimap<uint64_t, reuse_node_t>::iterator pair_it;
            pair<multimap<uint64_t, reuse_node_t>::iterator,
                    multimap<uint64_t, reuse_node_t>::iterator>
                pair_range_it;
            pair_range_it = (*pair_map).equal_range(new_pair);
            for (pair_it = pair_range_it.first; pair_it != pair_range_it.second; ++pair_it) {
                if (pair_it->second.create_hndl == it->second.create_hndl) {
                    pair_it->second.count++;
                    pair_it->second.distance += reuse_distance;
                    break;
                }
            }
            if (pair_it == pair_range_it.second) {
                reuse_node_t val(it->second.create_hndl, reuse_distance, 1);
                (*pair_map).insert(pair<uint64_t, reuse_node_t>(new_pair, val));
            }
        }
        it->second.use_hndl = cur_ctxt_hndl;
        it->second.last_reuse_mem_idx = cur_mem_idx;
    } else {
        use_node_t new_entry;
        new_entry.create_hndl = 0;
        new_entry.use_hndl = cur_ctxt_hndl;
        new_entry.last_reuse_mem_idx = cur_mem_idx;
#ifdef SAMPLE_RUN
        new_entry.sample_run_index = pt->sample_run_index;
#endif
        (*use_map).insert(pair<uint64_t, use_node_t>((uint64_t)(addr), new_entry));
    }
}

void
PrintTopN(void *drcontext, per_thread_t *pt, uint64_t print_num)
{
    // print_num = (*(pt->tls_reuse_map)).size();
    output_format_t *output_format_list =
        (output_format_t *)dr_global_alloc(print_num * sizeof(output_format_t));
    for (uint64_t i = 0; i < print_num; i++) {
        output_format_list[i].create_hndl = 0;
        output_format_list[i].use_hndl = 0;
        output_format_list[i].reuse_hndl = 0;
        output_format_list[i].count = 0;
        output_format_list[i].distance = 0;
    }
    multimap<uint64_t, reuse_node_t>::iterator it;
    for (it = (*(pt->tls_reuse_map)).begin(); it != (*(pt->tls_reuse_map)).end(); ++it) {
        uint64_t distance = it->second.distance / it->second.count;
        uint64_t count = it->second.count;
        if (distance < REUSED_THRES || count < REUSED_PRINT_MIN_COUNT)
            continue;
        context_handle_t use_hndl = (context_handle_t)(it->first >> 32);
        context_handle_t reuse_hndl = (context_handle_t)(it->first);
        context_handle_t create_hndl = it->second.create_hndl;
        if (create_hndl <= 0) {
            continue;
        }
        if (count > output_format_list[0].count) {
            output_format_list[0].count = count;
            output_format_list[0].distance = distance;
            output_format_list[0].reuse_hndl = reuse_hndl;
            output_format_list[0].use_hndl = use_hndl;
            output_format_list[0].create_hndl = create_hndl;

            uint64_t min_count = output_format_list[0].count;
            uint64_t min_idx = 0;
            for (uint64_t i = 1; i < print_num; i++) {
                if (output_format_list[i].count < min_count) {
                    min_count = output_format_list[i].count;
                    min_idx = i;
                }
            }
            output_format_list[0] = output_format_list[min_idx];
            output_format_list[min_idx].count = count;
            output_format_list[min_idx].distance = distance;
            output_format_list[min_idx].reuse_hndl = reuse_hndl;
            output_format_list[min_idx].use_hndl = use_hndl;
            output_format_list[min_idx].create_hndl = create_hndl;
        }
    }
    output_format_t temp;
    for (uint64_t i = 0; i < print_num; i++) {
        for (uint64_t j = i; j < print_num; j++) {
            if (output_format_list[i].count < output_format_list[j].count) {
                temp = output_format_list[i];
                output_format_list[i] = output_format_list[j];
                output_format_list[j] = temp;
            }
        }
    }
    
    vector<HPCRunCCT_t *> hpcRunNodes;
    for (uint i = 0; i < print_num; i++) {
        if (output_format_list[i].count <= 0) {
            continue;
        }
        HPCRunCCT_t *hpcRunNode = new HPCRunCCT_t();
        hpcRunNode->ctxt_hndl_list.push_back(output_format_list[i].create_hndl);
        hpcRunNode->ctxt_hndl_list.push_back(output_format_list[i].use_hndl);
        hpcRunNode->ctxt_hndl_list.push_back(output_format_list[i].reuse_hndl);
        hpcRunNode->metric_list.push_back(output_format_list[i].count);
        hpcRunNode->metric_list.push_back(output_format_list[i].distance);
        hpcRunNodes.push_back(hpcRunNode);
    }
    build_thread_custom_cct_hpurun_format(hpcRunNodes, drcontext);
    write_thread_custom_cct_hpurun_format(drcontext);

    dr_global_free(output_format_list, print_num * sizeof(output_format_t));
}

// client want to do
inline void
DoWhatClientWantTodo(void *drcontext, per_thread_t *pt, context_handle_t cur_ctxt_hndl,
                     app_pc cur_addr)
{
    pt->cur_mem_idx++;
#ifdef SAMPLE_RUN
    if (pt->cur_mem_idx > 0 && pt->cur_mem_idx % UNITE_NUM == 0) {
        pt->sample_run_index ++;
    }
    if (pt->cur_mem_idx % UNITE_NUM <= SAMPLE_NUM) {
        UpdateUseAndReuseMap(drcontext, pt, pt->cur_mem_idx, cur_ctxt_hndl, cur_addr);
    }
#else
    UpdateUseAndReuseMap(drcontext, pt, pt->cur_mem_idx, cur_ctxt_hndl, cur_addr);
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

    for (int32_t i = 0; i < mem_ref_num; i++) {
        if (mem_ref_start[i].slot >= slot_num) {
            break;
        }
        DoWhatClientWantTodo(drcontext, pt, ctxt_hndl + mem_ref_start[i].slot,
                             mem_ref_start[i].addr);
    }
}

#ifdef DEBUG_REUSE
static void
ThreadDebugFileInit(per_thread_t *pt)
{
    int32_t id = drcctlib_get_thread_id();
    char debug_file_name[MAXIMUM_FILEPATH] = "";
    DRCCTLIB_INIT_THREAD_LOG_FILE_NAME(
        debug_file_name, "drcctlib_reuse_distance_hpc_fmt", id, "debug.log");
    pt->log_file =
        dr_open_file(debug_file_name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(pt->log_file != INVALID_FILE);
}
#endif

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_mem_idx = 0;
#ifdef SAMPLE_RUN
    pt->sample_run_index = 0;
#endif
    pt->tls_use_map = new map<uint64_t, use_node_t>();
    pt->tls_reuse_map = new multimap<uint64_t, reuse_node_t>();
#ifdef DEBUG_REUSE
    ThreadDebugFileInit(pt);
#endif
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    PrintTopN(drcontext, pt, OUTPUT_SIZE);
    delete pt->tls_use_map;
    delete pt->tls_reuse_map;
#ifdef DEBUG_REUSE
    dr_close_file(pt->log_file);
#endif
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    drcctlib_exit();
    hpcrun_format_exit();
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_reuse_distance_hpc_fmt failed to unregister in ClientExit");
    }
    drmgr_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_reuse_distance_hpc_fmt'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance_hpc_fmt unable to initialize drmgr");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "drcctlib_reuse-thread_init", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "drcctlib_reuse-thread-exit", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri);
    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance_hpc_fmt drmgr_register_tls_field fail");
    }
    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache,
                     DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE | DRCCTLIB_CACHE_MODE |
                         DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR);
    hpcrun_format_init(dr_get_application_name(), false);
    hpcrun_create_metric("SUM_COUNT");
    hpcrun_create_metric("AVG_DIS");
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif