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

#define DRCCTLIB_PRINTF(format, args...)                                                 \
    do {                                                                                 \
        char name[MAXIMUM_PATH] = "";                                                    \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));                   \
        pid_t pid = getpid();                                                            \
        dr_printf("[(%s%d)drcctlib_memory_with_data_centric_with_search msg]====" format \
                  "\n",                                                                  \
                  name, pid, ##args);                                                    \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                           \
    do {                                                                                 \
        char name[MAXIMUM_PATH] = "";                                                    \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));                   \
        pid_t pid = getpid();                                                            \
        dr_printf(                                                                       \
            "[(%s%d)drcctlib_memory_with_data_centric_with_search(%s%d) msg]====" format \
            "\n",                                                                        \
            name, pid, ##args);                                                          \
    } while (0);                                                                         \
    dr_exit_process(-1)

// client want to do
static inline void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, app_pc addr)
{
    // use {cur_ctxt_hndl}
    data_handle_t data_hndl = drcctlib_get_data_hndl_runtime(drcontext, addr);
    context_handle_t data_ctxt_hndl = 0;
    if (data_hndl.object_type == DYNAMIC_OBJECT) {
        data_ctxt_hndl = data_hndl.path_handle;
    } else if (data_hndl.object_type == STATIC_OBJECT) {
        data_ctxt_hndl = - data_hndl.sym_name;
    }
}

static inline void
InstrumentPerBBCache(void *drcontext, context_handle_t ctxt_hndl, int32_t slot_num,
                     int32_t mem_ref_num, mem_ref_msg_t *mem_ref_start, void **data)
{

    for (int32_t i = 0; i < mem_ref_num; i++) {
        if (mem_ref_start[i].slot >= slot_num) {
            break;
        }
        DoWhatClientWantTodo(drcontext, ctxt_hndl + mem_ref_start[i].slot,
                             mem_ref_start[i].addr);
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
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_with_data_centric_with_search'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE,
                     NULL, NULL, InstrumentPerBBCache,
                     DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE | DRCCTLIB_CACHE_MODE |
                         DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif