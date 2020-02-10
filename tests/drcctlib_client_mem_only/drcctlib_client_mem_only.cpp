#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sstream>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"

using namespace std;

void SimpleCCTQuery(const uint32_t slot) {
    GetContextHandle(dr_get_current_drcontext(), slot);
}

void InstrumentInsCallback(void *drcontext, instrlist_t *ilist, instr_t* ins, void * v, uint slot) {
    if(instr_writes_memory(ins) || instr_reads_memory(ins)){
        dr_insert_clean_call(drcontext, ilist, ins, (void *)SimpleCCTQuery, false, 1, OPND_CREATE_INT32(slot));
    } 
}


file_t gTraceFile;

void ClientInit(int argc,const char* argv[]) {
    char name[CCTLIB_N_MAX_FILE_PATH] = "client.out.";
    char* envPath = getenv("DR_CCTLIB_CLIENT_OUTPUT_FILE");
    
    if(envPath) {
        // assumes max of CCTLIB_N_MAX_FILE_PATH
        strcpy(name, envPath);
    }

    gethostname(name + strlen(name), CCTLIB_N_MAX_FILE_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    cerr << "\n Creating log file at:" << name << "\n";
    gTraceFile = dr_open_file(name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");

    for(int i = 0 ; i < argc; i++) {
        dr_fprintf(gTraceFile, "%s ", argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");
}



#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlibtest'", "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    drcctlib_init(INTERESTING_INS_ALL, gTraceFile, InstrumentInsCallback, 0, nullptr, true);

}

#ifdef __cplusplus
}
#endif
