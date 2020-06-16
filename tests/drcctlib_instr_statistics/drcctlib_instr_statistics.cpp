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


#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH_NUM_SHOW 200

uint64_t *gloabl_hndl_call_num;
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
    gloabl_hndl_call_num = (uint64_t *)dr_raw_mem_alloc(
        CONTEXT_HANDLE_MAX * sizeof(uint64_t),
        DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (gloabl_hndl_call_num == NULL) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: dr_raw_mem_alloc fail gloabl_hndl_call_num");
    }
}

static inline void
FreeGlobalBuff()
{
    dr_raw_mem_free(gloabl_hndl_call_num, CONTEXT_HANDLE_MAX * sizeof(uint64_t));
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

typedef struct _output_format_t {
    context_handle_t handle;
    uint64_t count;
} output_format_t;

static void
ClientExit(void)
{
    output_format_t* output_list =  (output_format_t*)dr_global_alloc(TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    context_handle_t max_ctxt_hndl = drcctlib_get_global_context_handle_num();
    for(context_handle_t i = 0; i < max_ctxt_hndl; i++){
        if (gloabl_hndl_call_num[i] <= 0) {
            continue;
        }
        if (gloabl_hndl_call_num[i] > output_list[0].count) {
            uint64_t min_count = gloabl_hndl_call_num[i];
            uint64_t min_idx = 0;
            for (uint64_t i = 1; i < TOP_REACH_NUM_SHOW; i++) {
                if (output_list[i].count < min_count) {
                    min_count = output_list[i].count;
                    min_idx = i;
                }
            }
            output_list[0].count = min_count;
            output_list[0].handle = output_list[min_idx].handle;
            output_list[min_idx].count = gloabl_hndl_call_num[i];
            output_list[min_idx].handle = i;
        }
    }
    output_format_t temp;
    for (uint64_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        for (uint64_t j = i; j < TOP_REACH_NUM_SHOW; j++) {
            if(output_list[i].count < output_list[j].count) {
                temp = output_list[i];
                output_list[i] = output_list[j];
                output_list[j] = temp;
            }
        }
    }
    for(uint i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        dr_fprintf(gTraceFile, "NO. %d ins call number %lld ctxt handle %lld====", i+1, output_list[i].handle, output_list[i].count);
        drcctlib_print_ctxt_hndl_msg(gTraceFile, output_list[i].handle, false, false);
        dr_fprintf(gTraceFile, "================================================================================\n");
        drcctlib_print_full_cct(gTraceFile, output_list[i].handle, true, false, MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "================================================================================\n\n\n");
    }
    dr_global_free(output_list, TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    FreeGlobalBuff();
    drcctlib_exit();

    dr_close_file(gTraceFile);
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_instr_statistics'",
                       "http://dynamorio.org/issues");
    
    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL,
                     NULL, NULL, InstrumentPerInsCache, NULL, DRCCTLIB_CACHE_MODE);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif