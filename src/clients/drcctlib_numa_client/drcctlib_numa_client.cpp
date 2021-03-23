/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drcctlib.h"
#include "drmgr.h"

#include <numaif.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <map>
#include <vector>
#include <string>
#include <algorithm> 
#include <sys/stat.h>
#include <limits.h>

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("numa_client", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("numa_client", _FORMAT, ##_ARGS)

#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define SAMPLE_PERIOD (10013)

using namespace std;

typedef struct _numa_metric_t {
  uint64_t local_access;
  uint64_t remote_access;
  uint64_t min;
  uint64_t max;
} numa_metric_t;

typedef struct _global_numa_metric_t {
  uint64_t local_access;
  uint64_t remote_access;
  vector<pair<uint64_t, uint64_t>> pattern;
} global_numa_metric_t;

typedef struct _per_thread_t {
    uint64_t sample_idx;
    map<context_handle_t, numa_metric_t> *tls_numa_map;
} per_thread_t;

static std::string g_folder_name;
static int tls_idx;
static map<context_handle_t, global_numa_metric_t> global_numa_map;
void *lock;
file_t output_file;

// client want to do
static inline void
DoWhatClientWantTodo(void *drcontext, per_thread_t *pt, context_handle_t cur_ctxt_hndl, app_pc addr, int numa_access_node)
{
    // use {cur_ctxt_hndl}
    data_handle_t data_hndl = drcctlib_get_data_hndl_runtime(drcontext, addr);
    context_handle_t data_ctxt_hndl = 0;
    if (data_hndl.object_type == DYNAMIC_OBJECT) {
        data_ctxt_hndl = data_hndl.path_handle;
    } else if (data_hndl.object_type == STATIC_OBJECT) {
        data_ctxt_hndl = -data_hndl.sym_name; // a negative value
    } 

    map<context_handle_t, numa_metric_t>::iterator it = pt->tls_numa_map->find(data_ctxt_hndl);
    if (it == pt->tls_numa_map->end()) {
      numa_metric_t metric = {0, 0, ULONG_MAX, 0};
      pt->tls_numa_map->insert(std::pair<context_handle_t,numa_metric_t>(data_ctxt_hndl,metric));
    }

    int numa_location_node = 0;
    void * ad = (void *) addr;
    if (move_pages(0, 1, &ad, NULL, &numa_location_node, 0) == 0) {
      if(numa_access_node == numa_location_node) {
        (*(pt->tls_numa_map))[data_ctxt_hndl].local_access++;
      }
      else {
        (*(pt->tls_numa_map))[data_ctxt_hndl].remote_access++;
      }
      if ((*(pt->tls_numa_map))[data_ctxt_hndl].min > (uint64_t)addr)
        (*(pt->tls_numa_map))[data_ctxt_hndl].min = (uint64_t)addr;
      if ((*(pt->tls_numa_map))[data_ctxt_hndl].max < (uint64_t)addr)
        (*(pt->tls_numa_map))[data_ctxt_hndl].max = (uint64_t)addr;
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
   
    int numa_access_node = 0;
    syscall(SYS_getcpu, NULL, &numa_access_node, NULL);
    for (int32_t i = 0; i < mem_ref_num; i++) {
      if (mem_ref_start[i].slot >= slot_num) {
          break;
      }
      pt->sample_idx ++;
      if (pt->sample_idx >= SAMPLE_PERIOD) {
        DoWhatClientWantTodo(drcontext, pt, ctxt_hndl + mem_ref_start[i].slot,
                             mem_ref_start[i].addr, numa_access_node);
        pt->sample_idx = 0;
      }
    }
}

static void
OutputFileInit()
{
    char name[MAXIMUM_PATH] = "";
    sprintf(name + strlen(name), "%s/numa.topn.log", g_folder_name.c_str());
    output_file = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(output_file != INVALID_FILE);
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->tls_numa_map = new map<context_handle_t, numa_metric_t>();
    pt->sample_idx = 0;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);

    // merge all local maps to the global map
    dr_mutex_lock(lock);
    for (map<context_handle_t,numa_metric_t>::iterator it= (*(pt->tls_numa_map)).begin(); it!= (*(pt->tls_numa_map)).end(); ++it) {
      if (global_numa_map.find(it->first) == global_numa_map.end()) {
        global_numa_map[it->first].local_access = it->second.local_access;
        global_numa_map[it->first].remote_access = it->second.remote_access;
      }
      else {
        global_numa_map[it->first].local_access += it->second.local_access;
        global_numa_map[it->first].remote_access += it->second.remote_access;
      }
      global_numa_map[it->first].pattern.push_back(make_pair(it->second.min, it->second.max));
    }
    dr_mutex_unlock(lock);

    delete pt->tls_numa_map;
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}


static void
ClientInit(int argc, const char *argv[])
{
    char name[MAXIMUM_PATH] = "";
    DRCCTLIB_INIT_LOG_FILE_NAME(
        name, "drcctlib_numa", "out");
    g_folder_name.assign(name, strlen(name));
    mkdir(g_folder_name.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    OutputFileInit();

    lock = dr_mutex_create();
    global_numa_map.clear();
}

bool
comp(const pair<context_handle_t,global_numa_metric_t> &t1, 
        const pair<context_handle_t,global_numa_metric_t> &t2)
{
  return (t1.second.remote_access > t2.second.remote_access);
}

static void
print_result ()
{
  vector<pair<context_handle_t,global_numa_metric_t>> vec;
  for (map<context_handle_t,global_numa_metric_t>::iterator it= global_numa_map.begin(); it!= global_numa_map.end(); ++it) {
    if (it->second.remote_access > 0) vec.push_back(*it);
  }
  // sort the vector
  sort(vec.begin(), vec.end(), comp);

  // print the vector
  dr_fprintf(output_file, "NUMA analysis results\n");
  for (uint i = 0; i < vec.size(); i++) { 
    dr_fprintf(output_file, "==================================\n");
    dr_fprintf(output_file, "Local accesses %llu, remote accesses %llu\n", vec[i].second.local_access * SAMPLE_PERIOD, vec[i].second.remote_access * SAMPLE_PERIOD);
    if (vec[i].first == 0) {
      dr_fprintf(output_file, "Unknown object\n");
    }
    else if (vec[i].first > 0) {
            drcctlib_print_full_cct(output_file, vec[i].first,
                                    true, true, MAX_CLIENT_CCT_PRINT_DEPTH);
    } else {
            dr_fprintf(output_file, "STATIC_OBJECT %s\n",
                       drcctlib_get_str_from_strpool(-vec[i].first));
    }   
    dr_fprintf(output_file, "------pattern------\n");
    for (uint j = 0; j < vec[i].second.pattern.size(); j++) {
      dr_fprintf(output_file, "%lu-[0x%llx, 0x%llx] ", j, vec[i].second.pattern[j].first, vec[i].second.pattern[j].second);
    }
    dr_fprintf(output_file, "\n");
  }
  dr_close_file(output_file);
}

static void
ClientExit(void)
{
    print_result();

    drcctlib_exit();
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_numa failed to unregister in ClientExit");
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
    dr_set_client_name("DynamoRIO Client 'drcctlib_numa'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

   if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_numa unable to initialize drmgr");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "drcctlib_numa-thread_init", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "drcctlib_numa-thread-exit", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri);
    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance drmgr_register_tls_field fail");
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
