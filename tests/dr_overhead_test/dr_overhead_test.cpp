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
#include "drcctlib_global_share.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                      \
    do {                                                                      \
        char name[MAXIMUM_PATH] = "";                                         \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));        \
        pid_t pid = getpid();                                                 \
        dr_printf("[dr(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                \
    do {                                                                      \
        char name[MAXIMUM_PATH] = "";                                         \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));        \
        pid_t pid = getpid();                                                 \
        dr_printf("[dr(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                              \
    dr_exit_process(-1)



#ifdef INTEL_CCTLIB
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT32
#    define OPND_CREATE_SLOT OPND_CREATE_INT32
#    define OPND_CREATE_STATE OPND_CREATE_INT32
#    define OPND_CREATE_MEM_REF_NUM OPND_CREATE_INT32
#elif defined(ARM_CCTLIB)
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT
#    define OPND_CREATE_SLOT OPND_CREATE_INT
#    define OPND_CREATE_STATE OPND_CREATE_INT
#    define OPND_CREATE_MEM_REF_NUM OPND_CREATE_INT
#endif

static void
insert_clean_call(int32_t new_key, int32_t num, int32_t end_state, int32_t memory_ref_num)
{
    dr_get_current_drcontext();
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                           bool translating, OUT void **user_data)
{
    instr_t *first_instr = instrlist_first_app(bb);
    if (instr_is_exclusive_store(first_instr)) {
        return DR_EMIT_DEFAULT;
    }
    dr_insert_clean_call(
                drcontext, bb, first_instr, (void *)insert_clean_call, false, 4,
                OPND_CREATE_BB_KEY(0), OPND_CREATE_SLOT(0),
                OPND_CREATE_STATE(0), OPND_CREATE_MEM_REF_NUM(0));
    return DR_EMIT_DEFAULT;
}

static void
ClientInit(int argc, const char *argv[])
{

}

static void
ClientExit(void)
{

}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'dr_overhead_test'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("WARNING: dr_overhead_test unable to initialize drmgr");
    }
    if (!drmgr_register_bb_instrumentation_event(event_bb_analysis,
                                                 NULL, NULL)) {
        DRCCTLIB_EXIT_PROCESS("WARNING: dr_overhead_test fail to register bb instrumentation event");
    }
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif