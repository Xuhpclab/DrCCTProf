#include <iostream>
#include <string.h>
#include <sstream>
#include <algorithm>
#include <climits>
#include <iterator>
#include <unistd.h>
#include <vector>
#include <map>

#include <sys/resource.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                            \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[(%s%d)drcctlib_cct_only_op msg]====" format "\n", name, pid, \
                  ##args);                                                          \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                       \
    do {                                                                             \
        char name[MAXIMUM_PATH] = "";                                                \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));               \
        pid_t pid = getpid();                                                        \
        dr_printf("[(%s%d)drcctlib_cct_only_op(%s%d) msg]====" format "\n", name, \
                  pid, ##args);                                                      \
    } while (0);                                                                     \
    dr_exit_process(-1)


// client want to do
void
DoWhatClientWantTodo(void* drcontext, context_handle_t cur_ctxt_hndl)
{
    // use {cur_ctxt_hndl}
}

// dr clean call per bb
void 
InstrumentBBStartInsertCallback(void* drcontext, int32_t slot_num, int32_t mem_ref_num, void* data)
{
    for (int i = 0; i < slot_num; i++) {
        DoWhatClientWantTodo(drcontext, drcctlib_get_context_handle_cache(drcontext, i));
    }
}



static void
ClientInit(int argc, const char *argv[])
{
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
    dr_set_client_name("DynamoRIO Client 'drcctlib_cct_only_op'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL,
                    InstrumentBBStartInsertCallback, NULL, NULL, NULL, DRCCTLIB_CACHE_MODE);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif