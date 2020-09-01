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
// TODO fix count ,it is bugged

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
#include "dr_ir_instr.h"
#include "dr_ir_instrlist.h"
#include "dr_ir_utils.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                       \
    DRCCTLIB_PRINTF_TEMPLATE("instr_statistics", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...)                                 \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("instr_statistics", format, ##args)

#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH_NUM_SHOW 200

/**
 * The log file.
 */
static file_t gTraceFile;

/**
 * Map from the context handle to the time it first appears
 */
static map<context_handle_t, int> *calling_contexts;

/**
 * Map from the context handle to the number of times it is called
 */
static map<context_handle_t, int> *calling_contexts_called;

/**
 * Counters for the number of memory loads,
 * indexed by calling context index
 */
static vector<int> *memloads;

/**
 * Counters for the number of memory stores,
 * indexed by calling context index
 */
static vector<int> *memstores;

/**
 * Counters for the number of conditional branches,
 * indexed by calling context index
 */
static vector<int> *branches;

/**
 * Counters for the number of unconditional branches,
 * indexed by calling context index
 */
static vector<int> *jumps;

/**
 * Counters for the number of "other" instructions
 * that do not fit the above categories
 * indexed by calling context index
 */
static vector<int> *others;

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
static inline void InstrumentPerBBCache(void *drcontext,
                                        context_handle_t ctxt_hndl,
                                        int32_t slot_num, int32_t mem_ref_num,
                                        mem_ref_msg_t *mem_ref_start,
                                        void **data)
{
    int index;
    if (calling_contexts->find(ctxt_hndl) == calling_contexts->end()) {
        (*calling_contexts)[ctxt_hndl] = calling_contexts->size();
        memloads->push_back(0);
        memstores->push_back(0);
        branches->push_back(0);
        jumps->push_back(0);
        others->push_back(0);
    }
    index = (*calling_contexts)[ctxt_hndl];

    if (calling_contexts_called->find(ctxt_hndl) ==
        calling_contexts_called->end()) {
        (*calling_contexts_called)[ctxt_hndl] = 0;
    }
    (*calling_contexts_called)[ctxt_hndl] += 1;

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

    memloads->at(index) = memload_count;
    memstores->at(index) = memstore_count;
    branches->at(index) = branch_count;
    jumps->at(index) = jump_count;
    others->at(index) = other_count;
}

/**
 * Initialize the tool.
 * @param argc The tool's argc
 * @param argv The tool's argv
 */
static void ClientInit(int argc, const char *argv[])
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

    gTraceFile =
        dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);

    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");

    for (int i = 0; i < argc; i++) {
        dr_fprintf(gTraceFile, "%d %s ", i, argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");

    calling_contexts = new map<context_handle_t, int>;
    calling_contexts_called = new map<context_handle_t, int>;
    memloads = new vector<int>;
    memstores = new vector<int>;
    branches = new vector<int>;
    jumps = new vector<int>;
    others = new vector<int>;
}

/**
 * Record the statistics to a file
 */
static void ClientExit(void)
{
    for (std::pair<context_handle_t, int> element : (*calling_contexts)) {
        int i = element.second;
        context_handle_t cct_hndl = element.first;
        int no = i + 1;
        int memload_count = memloads->at(i);
        int memstore_count = memstores->at(i);
        int branch_count = branches->at(i);
        int jump_count = jumps->at(i);
        int other_count = others->at(i);
        int times_called = (*calling_contexts_called)[cct_hndl];
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
        dr_fprintf(gTraceFile, "==============================================="
                               "======================"
                               "===========\n");
        drcctlib_print_full_cct(gTraceFile, cct_hndl, true, false,
                                MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "==============================================="
                               "======================"
                               "===========\n\n\n");
    }

    drcctlib_exit();

    dr_close_file(gTraceFile);
    delete calling_contexts;
    delete calling_contexts_called;
    delete memloads;
    delete memstores;
    delete branches;
    delete jumps;
    delete others;
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
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_instr_analysis'",
                       "http://dynamorio.org/issues");

    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache, DRCCTLIB_CACHE_MODE);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
