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
#include "drmgr.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                              \
    do {                                                                              \
        char name[MAXIMUM_PATH] = "";                                                 \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));                \
        pid_t pid = getpid();                                                         \
        dr_printf("[(%s%d)drcctlib_all_instr_cct_hpc_fmt msg]====" format "\n", name, \
                  pid, ##args);                                                       \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                        \
    do {                                                                              \
        char name[MAXIMUM_PATH] = "";                                                 \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));                \
        pid_t pid = getpid();                                                         \
        dr_printf("[(%s%d)drcctlib_all_instr_cct_hpc_fmt(%s%d) msg]====" format "\n", \
                  name, pid, ##args);                                                 \
    } while (0);                                                                      \
    dr_exit_process(-1)



static void
ClientThreadStart(void *drcontext)
{

}

static void
ClientThreadEnd(void *drcontext)
{
    write_thread_all_cct_hpcrun_format(drcontext);
}

static void
ClientInit(int argc, const char *argv[])
{

}

static void
ClientExit(void)
{
    drcctlib_exit();

    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd)) {
        DRCCTLIB_PRINTF("failed to unregister in ClientExit");
    }
    drmgr_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_all_instr_cct_hpc_fmt'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_instr_statistics unable to initialize drmgr");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);
    
    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL, NULL, NULL, DRCCTLIB_SAVE_HPCTOOLKIT_FILE);
    init_hpcrun_format(dr_get_application_name(), true);
    dr_register_exit_event(ClientExit);    
}

#ifdef __cplusplus
}
#endif