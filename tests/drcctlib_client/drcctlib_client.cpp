#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sstream>
#include <unordered_map>
#include <map>
#include <algorithm>
#include <iterator>
#include <vector>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"

using namespace std;


unordered_map<context_handle_t, int> global_handle_call_number_map;

void
AddCtxtHandleCallNum(context_handle_t hndl, int num)
{
    if(!drcctlib_ctxt_is_valid(hndl)){
        return;
    }
    // dr_printf("AddCtxtHandleCallNum\n");
    unordered_map<context_handle_t, int>::const_iterator it =
        global_handle_call_number_map.find(hndl);
    if (it == global_handle_call_number_map.end()) {
        global_handle_call_number_map[hndl] = num;
    } else {
        global_handle_call_number_map[hndl] = global_handle_call_number_map[hndl] + num;
    }
    // dr_printf("AddCtxtHandleCallNum\n");
    context_handle_t caller_hndl = drcctlib_get_caller_handle(hndl);
    AddCtxtHandleCallNum(caller_hndl, num);
}

void SimpleCCTQuery(slot_t slot) {
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(dr_get_current_drcontext(), slot);
    AddCtxtHandleCallNum(cur_ctxt_hndl, 1);
}

void
InstrumentInsCallback(drcctlib_instr_instrument_list_t * instrumentList, instr_t * instr, slot_t slot,
                      drcctlib_instr_instrument_pri_t priority, void *data)
{
    // dr_printf("InstrumentInsCallback\n");
    drcctlib_instr_instrument_t * instrument = instr_instrument_create(instr, (void*)SimpleCCTQuery, priority, 1, OPND_CREATE_SLOT(slot));
    drcctlib_instr_instrument_list_add(instrumentList, instrument);
}

file_t gTraceFile;

void ClientInit(int argc,const char* argv[]) {
    char name[MAXIMUM_PATH] = "client.out.";
    char* envPath = getenv("DR_CCTLIB_CLIENT_OUTPUT_FILE");
    
    if(envPath) {
        // assumes max of MAXIMUM_PATH
        strcpy(name, envPath);
    }

    gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    cerr << "\n Creating log file at:" << name << "\n";
    
    // gTraceFile = dr_open_file(name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    char testName[MAXIMUM_PATH] = "client.out.ksun";
    gTraceFile = dr_open_file(testName, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);

    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");

    for(int i = 0 ; i < argc; i++) {
        dr_fprintf(gTraceFile, "%s ", argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");
}
void
drcctlib_client_exit(void)
{
    dr_printf("drcctlib_client_exit\n");
    vector<pair<context_handle_t, int>> tmp;
    for (auto& i : global_handle_call_number_map){
        tmp.push_back(i);
    }
    sort(tmp.begin(), tmp.end(),
         [=](pair<context_handle_t, int> &a, pair<context_handle_t, int> &b) {
             return a.second > b.second;
             });
    for(int i = 0; i < 100; i++) {
        dr_fprintf(gTraceFile, "call number %d\n", tmp[i].second);
        drcctlib_print_full_cct(tmp[i].first, false, false);
    }
    drcctlib_exit();
}


#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_client'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, gTraceFile, InstrumentInsCallback, NULL);


    dr_register_exit_event(drcctlib_client_exit);
}

#ifdef __cplusplus
}
#endif