/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */
#include <map>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"
#include "drcctlib_vscodeex_format.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_access_statistics", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_access_statistics", _FORMAT, ##_ARGS)

using namespace DrCCTProf;

static std::map<uint64_t, uint64_t>* memory_access_map;

void *lock;
static int tls_idx;

typedef struct _per_thread_t {
    uint64_t sample_idx;
    std::map<uint64_t, uint64_t> *tls_memory_access_map;
} per_thread_t;

// client want to do
static inline void
DoWhatClientWantTodo(void *drcontext, per_thread_t *pt, context_handle_t cur_ctxt_hndl, app_pc addr)
{
    // use {cur_ctxt_hndl}
    data_handle_t data_hndl = drcctlib_get_data_hndl_runtime(drcontext, addr);
    context_handle_t data_ctxt_hndl = 0;
    if (data_hndl.object_type == DYNAMIC_OBJECT) {
        data_ctxt_hndl = data_hndl.path_handle;
    } else if (data_hndl.object_type == STATIC_OBJECT) {
        data_ctxt_hndl = drcctlib_get_hndl_from_strpool(data_hndl.sym_name);
    }
    
    if (data_ctxt_hndl != 0) {
        uint64_t key = ((uint64_t)data_ctxt_hndl << 32) + cur_ctxt_hndl;
        std::map<uint64_t, uint64_t>::iterator it = (*(pt->tls_memory_access_map)).find(key);
        if (it == (*pt->tls_memory_access_map).end()) {
            (*(pt->tls_memory_access_map)).insert(std::pair<uint64_t, uint64_t>(key, 1));
        } else {
            (*pt->tls_memory_access_map)[key] += 1;
        }
    }
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
        pt->sample_idx ++;
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

    pt->tls_memory_access_map = new std::map<uint64_t, uint64_t>();
    pt->sample_idx = 0;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // merge all local maps to the global map
    dr_mutex_lock(lock);
    for (std::map<uint64_t, uint64_t>::iterator it= (*(pt->tls_memory_access_map)).begin(); it!= (*(pt->tls_memory_access_map)).end(); ++it) {
      if ((*memory_access_map).find(it->first) == (*memory_access_map).end()) {
        (*memory_access_map).insert(std::pair<uint64_t, uint64_t>(it->first, it->second));
      }
      else {
        (*memory_access_map)[it->first] += it->second;
      }
    }
    dr_mutex_unlock(lock);
    delete pt->tls_memory_access_map;
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}


static void
ClientInit(int argc, const char *argv[])
{
    memory_access_map = new std::map<uint64_t, uint64_t>();

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_memory_access_statistics_vse_fmt unable to initialize drmgr");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "drcctlib_memory_access_statistics_vse_fmt-thread_init", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "drcctlib_memory_access_statistics_vse_fmt-thread-exit", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri);
    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance drmgr_register_tls_field fail");
    }
    lock = dr_mutex_create();
}



#define ALLOC_THRES 128
#define ACCESS_THRES 1024
static void
ClientExit(void)
{
    Profile::profile_t* data_centric_profile = new Profile::profile_t();
    data_centric_profile->add_metric_type(0, " ", "alloc type");
    data_centric_profile->add_metric_type(1, "bytes", "alloc memory");
    std::vector<datacentric_node_t>* static_datacentric_nodes = drcctlib_get_static_datacentric_nodes();
    std::vector<datacentric_node_t>* dynamic_datacentric_nodes = drcctlib_get_dynamic_datacentric_nodes();

    std::vector<datacentric_node_t>::iterator it = (*static_datacentric_nodes).begin();
    for (; it != (*static_datacentric_nodes).end();it++) {
        if ((*it).count < ALLOC_THRES) {
            continue;
        }
        inner_context_t* cur_ctxt = drcctlib_get_full_cct_of_datacentric_nodes(*it);
        // DRCCTLIB_PRINTF("%s", cur_ctxt->func_name);
        Profile::sample_t* sample = data_centric_profile->add_sample(cur_ctxt);
        sample->append_metirc((int64_t)0);
        sample->append_metirc((*it).count);
        drcctlib_free_full_cct(cur_ctxt);
    }

    it = (*dynamic_datacentric_nodes).begin();
    for (; it != (*dynamic_datacentric_nodes).end();it++) {
        if ((*it).count < ALLOC_THRES) {
            continue;
        }
        inner_context_t* cur_ctxt = drcctlib_get_full_cct_of_datacentric_nodes(*it);
        // DRCCTLIB_PRINTF("%s", cur_ctxt->func_name);
        Profile::sample_t* sample = data_centric_profile->add_sample(cur_ctxt);
        sample->append_metirc((int64_t)1);
        sample->append_metirc((*it).count);
        drcctlib_free_full_cct(cur_ctxt);
    }
    data_centric_profile->serialize_to_file("data.datacentric.drcctprof");
    delete data_centric_profile;
    
    Profile::profile_t* memory_access_profile = new Profile::profile_t();
    memory_access_profile->add_metric_type(1, " ", "alloc context");
    memory_access_profile->add_metric_type(1, "times", "memory access time");
    std::map<uint64_t, uint64_t>::iterator m_it = (*memory_access_map).begin();
    for (; m_it != (*memory_access_map).end(); m_it++) {
        if (m_it->second < ACCESS_THRES) {
            continue;
        }
        context_handle_t alloc_hndl = (context_handle_t)(m_it->first >> 32);
        context_handle_t cur_hndl = (context_handle_t)((m_it->first << 32) >> 32);
        inner_context_t* cur_ctxt = drcctlib_get_full_cct(cur_hndl);
        Profile::sample_t* sample = memory_access_profile->add_sample(cur_ctxt);
        sample->append_metirc((uint64_t)alloc_hndl);
        sample->append_metirc(m_it->second);
        drcctlib_free_full_cct(cur_ctxt);
    }
    memory_access_profile->serialize_to_file("memory_access_statistics.normal.drcctprof");
    delete memory_access_profile;
    delete memory_access_map;
    drcctlib_exit();
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_memory_access_statistics_vse_fmt failed to unregister in ClientExit");
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
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_access_statistics_vse_fmt'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache,
                     DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE | DRCCTLIB_CACHE_MODE |
                         DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif