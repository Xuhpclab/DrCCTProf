#include <iostream>
#include <string.h>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <vector>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                             \
    do {                                                                             \
        char name[MAXIMUM_PATH] = "";                                                \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));               \
        pid_t pid = getpid();                                                        \
        dr_printf("[(%s%d)drcctlib_test_client msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                      \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[(%s%d)drcctlib_test_client(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                    \
    dr_exit_process(-1)


#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH__NUM_SHOW 200

int64_t *global_handle_call_number_buffer;
static file_t gTraceFile;

void
InstrumentInsCallback(void *drcontext, instrlist_t *bb, instr_t *instr, void *data)
{

}


void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM_CCTLIB
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
        dr_fprintf(gTraceFile, "NO. %d ins call number %d ====", i+1, tmp[i].second);
        drcctlib_print_ctxt_hndl_msg(tmp[i].first, false, false);
        dr_fprintf(gTraceFile, "================================================================================\n");
        drcctlib_print_full_cct(tmp[i].first, true, false, MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "================================================================================\n\n\n");
    }
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_test_client'",
                       "http://dynamorio.org/issues");
    if (!drmgr_init()) {
        DRCCTLIB_PRINTF("WARNING: drcctlib unable to initialize drmgr");
    }
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_ZERO_INSTR, gTraceFile, InstrumentInsCallback, NULL);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif