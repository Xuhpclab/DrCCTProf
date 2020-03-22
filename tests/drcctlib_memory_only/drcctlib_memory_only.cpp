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
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                             \
    do {                                                                             \
        char name[MAXIMUM_PATH] = "";                                                \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));               \
        pid_t pid = getpid();                                                        \
        dr_printf("[(%s%d)drcctlib_memory_only msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                      \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[(%s%d)drcctlib_memory_only(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                    \
    dr_exit_process(-1)


#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH__NUM_SHOW 200

static file_t gTraceFile;

void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg, void *data)
{
}


static void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.drcctlib_memory_only.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib_memory_only.out.";
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
        dr_fprintf(gTraceFile, "%d %s ", i, argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");
}

static void
ClientExit(void)
{
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_only'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, gTraceFile, InstrumentInsCallback, NULL, NULL, NULL);
    // drcctlib_set_global_flags(DRCCTLIB_USE_CLEAN_CALL);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif