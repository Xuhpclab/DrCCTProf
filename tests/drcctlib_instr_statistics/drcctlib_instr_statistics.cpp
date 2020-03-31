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
#include "drreg.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(format, args...)                                             \
    do {                                                                             \
        char name[MAXIMUM_PATH] = "";                                                \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));               \
        pid_t pid = getpid();                                                        \
        dr_printf("[(%s%d)drcctlib_instr_statistics msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                      \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[(%s%d)drcctlib_instr_statistics(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                    \
    dr_exit_process(-1)


#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH__NUM_SHOW 200

int64_t *gloabl_hndl_call_num;
static file_t gTraceFile;
static int tls_idx;

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, enum_val) *(int64_t **)TLS_SLOT(tls_base, enum_val)
#define MINSERT instrlist_meta_preinsert

#ifdef X86
#define OPND_CREATE_NUM OPND_CREATE_INT32
#elif defined(ARM_CCTLIB)
#define OPND_CREATE_NUM OPND_CREATE_INT
#endif

typedef struct _per_thread_t {
    void* buff;
} per_thread_t;

void
EveryInstrInstrument(void *drcontext, instrlist_t *bb, instr_t *instr, int32_t slot)
{
    if (drreg_reserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "InstrumentInsCallback drreg_reserve_aflags != DRREG_SUCCESS");
    }
    reg_id_t reg_cur_bb_buf_start, reg1;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_cur_bb_buf_start) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, instr, NULL, &reg1) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "InstrumentInsCallback drreg_reserve_register != DRREG_SUCCESS");
    }
    opnd_t opnd_reg_1 = opnd_create_reg(reg1);
    dr_insert_read_raw_tls(drcontext, bb, instr, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_cur_bb_buf_start);
    opnd_t opnd_mem_buff =
        OPND_CREATE_MEM64(reg_cur_bb_buf_start, sizeof(int64_t) * slot);

    MINSERT(bb, instr, XINST_CREATE_load(drcontext, opnd_reg_1, opnd_mem_buff));
    MINSERT(bb, instr, XINST_CREATE_add(drcontext, opnd_reg_1, OPND_CREATE_NUM(1)));
    MINSERT(bb, instr, XINST_CREATE_store(drcontext, opnd_mem_buff, opnd_reg_1));

    if (drreg_unreserve_register(drcontext, bb, instr, reg_cur_bb_buf_start) !=
            DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, instr, reg1) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "InstrumentInsCallback drreg_unreserve_register != DRREG_SUCCESS");
    }
    if (drreg_unreserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "InstrumentInsCallback drreg_unreserve_aflags != DRREG_SUCCESS");
    }
}


void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg, void *data)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    // if (instrument_msg->interest_start) {
    //     dr_insert_clean_call(drcontext, bb, instr, (void *)BBStartCleanCall, false, 0);
    // }
    EveryInstrInstrument(drcontext, bb, instr, instrument_msg->slot);
}

void 
InstrumentBBStartInsertCallback(void* data)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    context_handle_t cur_bb_start = drcctlib_get_bb_start_context_handle();
    BUF_PTR(pt->buff, INSTRACE_TLS_OFFS_BUF_PTR) = (gloabl_hndl_call_num + cur_bb_start);
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if(pt == NULL){
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);
    pt->buff = dr_get_dr_segment_base(tls_seg);
    BUF_PTR(pt->buff, INSTRACE_TLS_OFFS_BUF_PTR) = gloabl_hndl_call_num;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}
static inline void
InitGlobalBuff()
{
    gloabl_hndl_call_num =
        (int64_t *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(int64_t),
                              PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (gloabl_hndl_call_num == MAP_FAILED) {
        DRCCTLIB_EXIT_PROCESS("init_global_buff error: MAP_FAILED gloabl_hndl_call_num");
    }
}

static inline void
FreeGlobalBuff()
{
    if (munmap(gloabl_hndl_call_num, CONTEXT_HANDLE_MAX * sizeof(int64_t)) != 0) {
        // || munmap(global_string_pool, CONTEXT_HANDLE_MAX * sizeof(char)) != 0) {
        DRCCTLIB_PRINTF("free_global_buff munmap error");
    }
}

static void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.drcctlib.drcctlib_instr_statistics.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib.drcctlib_instr_statistics.out.";
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

    InitGlobalBuff();
}

static void
ClientExit(void)
{
    vector<pair<context_handle_t, int>> tmp;
    context_handle_t max_ctxt_hndl = drcctlib_get_global_context_handle_num();
    for(context_handle_t i = 0; i < max_ctxt_hndl; i++){
        tmp.push_back(make_pair(i, gloabl_hndl_call_num[i]));
    }
    sort(tmp.begin(), tmp.end(),
         [=](pair<context_handle_t, int> &a, pair<context_handle_t, int> &b) {
             return a.second > b.second;
             });
    for(uint i = 0; i < TOP_REACH__NUM_SHOW; i++) {
        dr_fprintf(gTraceFile, "NO. %d ins call number %d ====", i+1, tmp[i].second);
        drcctlib_print_ctxt_hndl_msg(gTraceFile, tmp[i].first, false, false);
        dr_fprintf(gTraceFile, "================================================================================\n");
        drcctlib_print_full_cct(gTraceFile, tmp[i].first, true, false, MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "================================================================================\n\n\n");
    }

    FreeGlobalBuff();
    drcctlib_exit();

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: dr_raw_tls_calloc fail");
    } 

    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF("failed to unregister in ClientExit");
    }
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_instr_statistics'",
                       "http://dynamorio.org/issues");
    
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, gTraceFile, InstrumentInsCallback, NULL,
                     InstrumentBBStartInsertCallback, NULL, 0);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_instr_statistics unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false};
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_instr_statistics unable to initialize drreg");
    }
    dr_register_exit_event(ClientExit);
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1){
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_instr_statistics drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_instr_statistics dr_raw_tls_calloc fail");
    }
}

#ifdef __cplusplus
}
#endif