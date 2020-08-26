/*
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <iostream>
#include <string.h>
#include <sstream>
#include <algorithm>
#include <climits>
#include <iterator>
#include <unistd.h>
#include <vector>
#include <unordered_map>
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

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_footprint", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_footprint", format, ##args)

static file_t gTraceFile;

static unordered_map<int, uint> mem_opcodes;

static inline void
InstrumentInstruction(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    // dr_mcontext_t* mc = NULL;
    // if (!dr_get_mcontext(drcontext, mc)) return ;
    // app_pc address = instr_compute_address(instr, mc);

    instr_t *instr = instrument_msg->instr;
    if (instr_writes_memory(instr) ||  instr_reads_memory(instr)){
        int opcode = instr_get_opcode(instr);

        if (mem_opcodes.find(opcode) == mem_opcodes.end()) {
            mem_opcodes[opcode] = 0;
        }
        mem_opcodes[opcode] += instr_memory_reference_size(instr);
    }
}

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    cout << "MEM_ACCESS_OPCODES_FOUND: " << endl;
    for (auto code : mem_opcodes) cout << "OPCODE: " << code.first << " NumBytes: " << code.second <<  endl;
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_footprint'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, gTraceFile, InstrumentInstruction, false);

    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif
