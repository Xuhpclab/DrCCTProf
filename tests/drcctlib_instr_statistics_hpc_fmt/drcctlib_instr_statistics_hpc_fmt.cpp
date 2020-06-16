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
#include "drreg.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                                 \
    do {                                                                                 \
        char name[MAXIMUM_PATH] = "";                                                    \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));                   \
        pid_t pid = getpid();                                                            \
        dr_printf("[(%s%d)drcctlib_instr_statistics_hpc_fmt msg]====" format "\n", name, \
                  pid, ##args);                                                          \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    do {                                                                                 \
        char name[MAXIMUM_PATH] = "";                                                    \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));                   \
        pid_t pid = getpid();                                                            \
        dr_printf("[(%s%d)drcctlib_instr_statistics_hpc_fmt(%s%d) msg]====" format "\n", \
                  name, pid, ##args);                                                    \
    } while (0);                                                                         \
    dr_exit_process(-1)

#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH__NUM_SHOW 200

#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH__NUM_SHOW 200

int64_t *gloabl_hndl_call_num;
static file_t gTraceFile;
static int tls_idx;

// dr clean call per ins cache
void InstrumentPerInsCache(void *drcontext, context_handle_t ctxt_hndl, int32_t mem_ref_num, mem_ref_msg_t * mem_ref_start, void *data)
{
    gloabl_hndl_call_num[ctxt_hndl] ++;
}

static inline void
InitGlobalBuff()
{
    gloabl_hndl_call_num = (int64_t *)dr_raw_mem_alloc(
        CONTEXT_HANDLE_MAX * sizeof(int64_t),
        DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (gloabl_hndl_call_num == NULL) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: dr_raw_mem_alloc fail gloabl_hndl_call_num");
    }
}

static inline void
FreeGlobalBuff()
{
    dr_raw_mem_free(gloabl_hndl_call_num, CONTEXT_HANDLE_MAX * sizeof(int64_t));
}

static void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.drcctlib_instr_statistics.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib_instr_statistics.out.";
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

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");

    for (int i = 0; i < argc; i++) {
        dr_fprintf(gTraceFile, "%d %s ", i, argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");

    InitGlobalBuff();
}

int ins_metric_id = 0;
static void
ClientExit(void)
{
    vector<pair<context_handle_t, int>> tmp;
    context_handle_t max_ctxt_hndl = drcctlib_get_global_context_handle_num();
    for(context_handle_t i = 0; i < max_ctxt_hndl; i++){
        tmp.push_back(make_pair(i, gloabl_hndl_call_num[i]));
    }
    sort(tmp.begin(), tmp.end(),
         [=](pair<context_handle_t, int> &a, pair<context_handle_t, int> &b) {
             return a.second > b.second;
             });
    vector<HPCRunCCT_t*> hpcRunNodes;
    for(uint i = 0; i < TOP_REACH__NUM_SHOW; i++) {
        HPCRunCCT_t *hpcRunNode = new HPCRunCCT_t();
        hpcRunNode->ctxt_hndl_list.push_back(tmp[i].first);
        hpcRunNode->metric_list.push_back(tmp[i].second);
        hpcRunNodes.push_back(hpcRunNode);
    }
    build_progress_custom_cct_hpurun_format(hpcRunNodes);
    write_progress_custom_cct_hpurun_format();

    FreeGlobalBuff();
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_instr_statistics_hpc_fmt'",
                       "http://dynamorio.org/issues");
    
    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL,
                     NULL, NULL, InstrumentPerInsCache, NULL, DRCCTLIB_SAVE_HPCTOOLKIT_FILE);
    init_hpcrun_format(dr_get_application_name(), false);
    ins_metric_id = hpcrun_create_metric("TOT_CALLS");
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif