// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h>
#include <iostream>
// #include <unistd.h>
// #include <assert.h>
#include <string.h>
#include <sstream>
// #include <unordered_map>
// #include <map>
#include <algorithm>
#include <iterator>
#include <vector>

// #include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                             \
    do {                                                                             \
        char name[MAXIMUM_PATH] = "";                                                \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));               \
        pid_t pid = getpid();                                                        \
        dr_printf("[(%s%d)drcctlib_client msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                      \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[(%s%d)drcctlib_client(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                    \
    dr_exit_process(-1)

// typedef struct _per_thread_t {
//     unordered_map<context_handle_t, int> *local_map;
// }per_thread_t;


#define MAX_CLIENT_CCT_PRINT_DEPTH 5
#define TOP_REACH__NUM_SHOW 100

// static int client_tls_idx;
// static void *client_thread_lock;

// unordered_map<context_handle_t, int> global_handle_call_number_map;
int64_t *global_handle_call_number_buffer;
static file_t gTraceFile;


// void
// AddCtxtHandleCallNum(context_handle_t hndl, int num, unordered_map<context_handle_t, int> * local_map)
// {
//     if(!drcctlib_ctxt_hndl_is_valid(hndl)){
//         return;
//     }
//     unordered_map<context_handle_t, int>::const_iterator it =
//         (*local_map).find(hndl);
//     if (it == (*local_map).end()) {
//         (*local_map)[hndl] = num;
//     } else {
//         (*local_map)[hndl] = (*local_map)[hndl] + num;
//     }
// }

// void
// GlobalMapAddCtxtHandleCallNum(context_handle_t hndl, int num)
// {
//     if(!drcctlib_ctxt_hndl_is_valid(hndl)){
//         return;
//     }
//     unordered_map<context_handle_t, int>::const_iterator it =
//         global_handle_call_number_map.find(hndl);
//     if (it == global_handle_call_number_map.end()) {
//         global_handle_call_number_map[hndl] = num;
//     } else {
//         global_handle_call_number_map[hndl] = global_handle_call_number_map[hndl] + num;
//     }
// }

// void
// SimpleCCTQuery()
// {
//     context_handle_t cur_ctxt_hndl =
//         drcctlib_get_context_handle();
//     drcctlib_print_ctxt_hndl_msg(cur_ctxt_hndl, false, false);
//     // int *store = global_handle_call_number_buffer + cur_ctxt_hndl;
//     // *store = *store + 1;
//     // drcctlib_print_ctxt_hndl_msg(cur_ctxt_hndl, true, false);
//     // per_thread_t *client_pt =
//     //     (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), client_tls_idx);
//     // AddCtxtHandleCallNum(cur_ctxt_hndl, 1, client_pt->local_map);

// #ifdef DRCCTLIB_DEBUG
//     // uint64_t printNumber = drcctlib_get_pt_run_number(dr_get_current_drcontext());
//     // if (!drcctlib_ctxt_hndl_is_valid(cur_ctxt_hndl)) {
//     //     DRCCTLIB_EXIT_PROCESS("cur_ctxt_hndl %d pt_id %d\n", cur_ctxt_hndl,
//     //               drcctlib_get_per_thread_date_id());
//     // } else if (printNumber % 2000000000 == 0) {
//     //     DRCCTLIB_PRINTF("printNumber %lu cur_ctxt_hndl %d pt_id %d", printNumber,
//     //                     cur_ctxt_hndl, drcctlib_get_per_thread_date_id());
//     // }
// #endif
// }

void
InstrumentInsCallback(void *drcontext, instrlist_t *bb, instr_t *instr, void *data)
{
    // dr_insert_clean_call(drcontext, bb, instr, (void *)SimpleCCTQuery, false, 0);
}

// static void
// ClientEventThreadStart(void *drcontext)
// {
//     per_thread_t * client_pt = (per_thread_t*)dr_thread_alloc(drcontext, sizeof(per_thread_t));
//     DR_ASSERT(client_pt != NULL);
//     drmgr_set_tls_field(drcontext, client_tls_idx, (void *)client_pt);

//     client_pt->local_map = new unordered_map<context_handle_t, int>();
// }
#ifdef DRCCTLIB_DEBUG
static void
ClientEventThreadEnd(void *drcontext)
{
    // per_thread_t *client_pt =
    //     (per_thread_t *)drmgr_get_tls_field(drcontext, client_tls_idx);
    // unordered_map<context_handle_t, int>::iterator iter = (*(client_pt->local_map)).begin();
    // dr_mutex_lock(client_thread_lock);
    // for(; iter != (*(client_pt->local_map)).end(); iter++) {
    //     GlobalMapAddCtxtHandleCallNum(iter->first, iter->second);
    // }
    // dr_mutex_unlock(client_thread_lock);
    // delete client_pt->local_map;
    // dr_thread_free(drcontext, client_pt, sizeof(per_thread_t));
    long long printNumber = drcctlib_get_pt_run_number(drcontext);
    DRCCTLIB_PRINTF("%lld seconds", printNumber);

}
#endif

void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM
    char name[MAXIMUM_PATH] = "arm.drcctlib.client.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib.client.out.";
#endif
    char *envPath = getenv("DR_CCTLIB_CLIENT_OUTPUT_FILE");

    if (envPath) {
        // assumes max of MAXIMUM_PATH
        strcpy(name, envPath);
    }

    gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    cerr << "Creating log file at:" << name << endl;

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    // char testName[MAXIMUM_PATH] = "client.out.ksun";
    // gTraceFile = dr_open_file(testName, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");

    for (int i = 0; i < argc; i++) {
        dr_fprintf(gTraceFile, "%s ", argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");
}

void
ClientExit(void)
{
    global_handle_call_number_buffer = drcctlib_get_global_gloabl_hndl_call_num_buff();
    vector<pair<context_handle_t, int>> tmp;
    context_handle_t max_ctxt_hndl = drcctlib_get_global_context_handle_num();
    for(context_handle_t i = 0; i < max_ctxt_hndl; i++){
        tmp.push_back(make_pair(i, global_handle_call_number_buffer[i]));
    }
    sort(tmp.begin(), tmp.end(),
         [=](pair<context_handle_t, int> &a, pair<context_handle_t, int> &b) {
             return a.second > b.second;
             });
    for(uint i = 0; i < TOP_REACH__NUM_SHOW; i++) {
    // for(uint i = 0; i < tmp.size(); i++) {
        dr_fprintf(gTraceFile, "NO. %d ins call number %d ====", i, tmp[i].second);
        drcctlib_print_ctxt_hndl_msg(tmp[i].first, false, false);
        dr_fprintf(gTraceFile, "================================================================================\n");
        drcctlib_print_full_cct(tmp[i].first, true, false, MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "================================================================================\n\n\n");
    }
    // if (!drmgr_unregister_thread_init_event(ClientEventThreadStart) ||
    //     !drmgr_unregister_thread_exit_event(ClientEventThreadEnd)||
    //     !drmgr_unregister_tls_field(client_tls_idx)) {
    //     DRCCTLIB_EXIT_PROCESS("failed to unregister in ClientExit");
    // }
    // dr_mutex_destroy(client_thread_lock);
    drcctlib_exit();
}


// static inline void
// InitBuffer()
// {
    // global_handle_call_number_buffer =
    //     (int *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(int),
    //                           PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // if (global_handle_call_number_buffer == MAP_FAILED) {
    //     DRCCTLIB_EXIT_PROCESS("InitBuffer error: MAP_FAILED global_handle_call_number_buffer");
    // }
// }


#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_client'",
                       "http://dynamorio.org/issues");
    if (!drmgr_init()) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drmgr");
    }
    // InitBuffer();
    ClientInit(argc, argv);
    // client_tls_idx = drmgr_register_tls_field();
    // drmgr_register_thread_init_event(ClientEventThreadStart);
#ifdef DRCCTLIB_DEBUG
    drmgr_register_thread_exit_event(ClientEventThreadEnd);
#endif
    // client_thread_lock = dr_mutex_create();
    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, gTraceFile, InstrumentInsCallback, NULL);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif