/**
 * @file drcctlib_instr_analysis.cpp
 * @author Jacob Salzberg (jssalzbe@ncsu.edu)
 * DrCCTProf instruction analysis client.
 * Analyzes every instruction,
 * grouping them into five groups:
 * memory load, memory store, conditional branch,
 * unconditional branch, and other.
 * Prints the statistics per context to a file.
 * Forked from drcctlib_instr_statistics.cpp
 */

#include <algorithm>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string.h>
#include <unistd.h>
#include <vector>

#include <map>
#include <sys/mman.h>
#include <sys/resource.h>

#include "dr_api.h"
#include "drmgr.h"
#include "dr_ir_instr.h"
#include "dr_ir_instrlist.h"
#include "dr_ir_utils.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("instr_statistics", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("instr_statistics", format, ##args)

#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH_NUM_SHOW 200

/**
 * Thread local storage index
 */
static int tls_idx;

/**
 * The log file.
 */
static file_t gTraceFile;

/**
 * Per thread storage for counts of instruction kinds
 */
typedef struct _per_thread_t {
    /**
     * Map from the context handle to the time it first appears
     */
    map<context_handle_t, int> *calling_contexts;

    /**
     * Map from the context handle to the number of times it is called
     */
    map<context_handle_t, int> *calling_contexts_called;

    /**
     * Counters for the number of memory loads,
     * indexed by calling context index
     */
    vector<int> *memloads;

    /**
     * Counters for the number of memory stores,
     * indexed by calling context index
     */
    vector<int> *memstores;

    /**
     * Counters for the number of conditional branches,
     * indexed by calling context index
     */
    vector<int> *branches;

    /**
     * Counters for the number of unconditional branches,
     * indexed by calling context index
     */
    vector<int> *jumps;

    /**
     * Counters for the number of "other" instructions
     * that do not fit the above categories
     * indexed by calling context index
     */
    vector<int> *others;
} per_thread_t;

/**
 * For every basic block
 * Iterate over the instruction list and count the
 * number of branches, memory stores, memory loads,
 * unconditional jumps
 * and other instructions.
 * @param drcontext the dynamorio context
 * @param ctxt_hndl the context handle
 * @param slot_num number of instructions (unused)
 * @param mem_ref_num number of memory references (unused)
 * @param mem_ref_start where the memory references start (unused)
 * @param data additional data passed to this function (unused)
 */
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

    int index;
    if (pt->calling_contexts->find(ctxt_hndl) == pt->calling_contexts->end()) {
        (*(pt->calling_contexts))[ctxt_hndl] = pt->calling_contexts->size();
        pt->memloads->push_back(0);
        pt->memstores->push_back(0);
        pt->branches->push_back(0);
        pt->jumps->push_back(0);
        pt->others->push_back(0);
    }
    index = (*(pt->calling_contexts))[ctxt_hndl];

    if (pt->calling_contexts_called->find(ctxt_hndl) ==
        pt->calling_contexts_called->end()) {
        (*(pt->calling_contexts_called))[ctxt_hndl] = 0;
    }
    (*(pt->calling_contexts_called))[ctxt_hndl] += 1;

    context_t *ctxt = drcctlib_get_full_cct(ctxt_hndl, 1);
    byte *ip = ctxt->ip;
    int memload_count = 0;
    int memstore_count = 0;
    int branch_count = 0;
    int jump_count = 0;
    int other_count = 0;
    if (ip) {
        instrlist_t *bb = decode_as_bb(drcontext, ip);
        instr_t *next;
        for (instr_t *instr = instrlist_first_app(bb);
             instr != instrlist_last_app(bb) && instr != NULL; instr = next) {
            if (instr_is_cbr(instr)) {
                branch_count += 1;
            } else if (instr_writes_memory(instr)) {
                memstore_count += 1;
            } else if (instr_reads_memory(instr)) {
                memload_count += 1;
            } else {
                other_count += 1;
            }
            next = instr_get_next_app(instr);
        }

        // Only check the last application for unconditional jumps.
        // This is because unconditional jumps end a branch
        if (instr_is_ubr(instrlist_last_app(bb))) {
            jump_count += 1;
        }
        if (instr_is_cbr(instrlist_last_app(bb))) {
            branch_count += 1;
        }
        instrlist_clear_and_destroy(drcontext, bb);
    }

    pt->memloads->at(index) = memload_count;
    pt->memstores->at(index) = memstore_count;
    pt->branches->at(index) = branch_count;
    pt->jumps->at(index) = jump_count;
    pt->others->at(index) = other_count;
}

/**
 * Initialize the tool.
 * @param argc The tool's argc
 * @param argv The tool's argv
 */
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
}

/**
 * Record the statistics to a file
 */
static void
ClientExit(void)
{
    drcctlib_exit();
    dr_close_file(gTraceFile);
}

/**
 * Record the statistics to a file
 */
static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    for (std::pair<context_handle_t, int> element : *(pt->calling_contexts)) {
        int i = element.second;
        context_handle_t cct_hndl = element.first;
        int no = i + 1;
        int memload_count = pt->memloads->at(i);
        int memstore_count = pt->memstores->at(i);
        int branch_count = pt->branches->at(i);
        int jump_count = pt->jumps->at(i);
        int other_count = pt->others->at(i);
        int times_called = (*(pt->calling_contexts_called))[cct_hndl];
        dr_fprintf(gTraceFile,
                   "NO. %d"
                   " loads (%02d),"
                   " store (%02d),"
                   " conditional branch (%02d),"
                   " unconditional branch (%02d)"
                   " other: (%02d)"
                   " ins call number %d"
                   " context handle %d"
                   "====",
                   no, memload_count, memstore_count, branch_count, jump_count,
                   other_count, times_called, cct_hndl);
        drcctlib_print_ctxt_hndl_msg(gTraceFile, cct_hndl, false, false);
        dr_fprintf(gTraceFile,
                   "==============================================="
                   "======================"
                   "===========\n");
        drcctlib_print_full_cct(gTraceFile, cct_hndl, true, false,
                                MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile,
                   "==============================================="
                   "======================"
                   "===========\n\n\n");
    }

    delete pt->calling_contexts;
    delete pt->calling_contexts_called;
    delete pt->memloads;
    delete pt->memstores;
    delete pt->branches;
    delete pt->jumps;
    delete pt->others;

    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

/**
 * Initialize per thread storage
 */
static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->calling_contexts = new map<context_handle_t, int>;
    pt->calling_contexts_called = new map<context_handle_t, int>;
    pt->memloads = new vector<int>;
    pt->memstores = new vector<int>;
    pt->branches = new vector<int>;
    pt->jumps = new vector<int>;
    pt->others = new vector<int>;
}

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Main entry point for tool
 * @param id the client id:
 * @param argc the argument count
 * @param argv the argument list
 */
DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_instr_analysis'",
                       "http://dynamorio.org/issues");

    ClientInit(argc, argv);
    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance unable to initialize drmgr");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "drcctlib_reuse-thread_init", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "drcctlib_reuse-thread-exit", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri);

    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache, DRCCTLIB_CACHE_MODE);
    dr_register_exit_event(ClientExit);
    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance drmgr_register_tls_field fail");
    }
}

#ifdef __cplusplus
}
#endif
