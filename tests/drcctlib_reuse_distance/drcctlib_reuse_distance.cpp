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

#define DRCCTLIB_PRINTF(format, args...)                                             \
    do {                                                                             \
        char name[MAXIMUM_PATH] = "";                                                \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));               \
        pid_t pid = getpid();                                                        \
        dr_printf("[(%s%d)drcctlib_reuse_distance msg]====" format "\n", name, pid, ##args); \
    } while (0)

#define DRCCTLIB_EXIT_PROCESS(format, args...)                                      \
    do {                                                                            \
        char name[MAXIMUM_PATH] = "";                                               \
        gethostname(name + strlen(name), MAXIMUM_PATH - strlen(name));              \
        pid_t pid = getpid();                                                       \
        dr_printf("[(%s%d)drcctlib_reuse_distance(%s%d) msg]====" format "\n", name, pid, ##args); \
    } while (0);                                                                    \
    dr_exit_process(-1)


static file_t gTraceFile;
static int tls_idx;
static char* app_name;

enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, type, offs) *(type **)TLS_SLOT(tls_base, offs)
#define MINSERT instrlist_meta_preinsert

#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    ifdef CCTLIB_64
#        define OPND_CREATE_CCT_INT OPND_CREATE_INT64
#    else
#        define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#    endif
#endif

#ifdef CCTLIB_64
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM64
#else
#    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM32
#endif

#define OPND_CREATE_MEM_IDX_MEM OPND_CREATE_MEM64

struct use_node_t {
    context_handle_t use_hndl;
    uint64_t last_reuse_mem_idx;

    use_node_t(context_handle_t c, uint64_t m)
        : use_hndl(c)
        , last_reuse_mem_idx(m)
    {
    }
};

struct reuse_node_t {
    uint64_t distance;
    uint64_t count;

    reuse_node_t(uint64_t d, uint64_t c)
        : distance(d)
        , count(c)
    {
    }
};

typedef struct _mem_ref_t {
    aligned_ctxt_hndl_t ctxt_hndl;
    app_pc addr;
} mem_ref_t;

typedef struct _output_format_t {
  context_handle_t use_hndl;
  context_handle_t reuse_hndl;
  uint64_t count;
  uint64_t distance;
} output_format_t;

typedef struct _per_thread_t{
    uint64_t last_mem_idx;
    uint64_t cur_mem_idx;
    mem_ref_t *cur_buf_list;
    int cur_buf_fill_num;
    void *cur_buf;
    map<uint64_t, use_node_t> *tls_use_map;
    map<uint64_t, reuse_node_t> *tls_reuse_map;
    bool sample_mem;
} per_thread_t;

#define TLS_MEM_REF_BUFF_SIZE 100000

// #define SAMPLE_RUN
#ifdef SAMPLE_RUN
#define UNITE_NUM 1000000000
#define SAMPLE_NUM 100000000
#endif


#define OUTPUT_SIZE 200
#define REUSED_THRES 8912
#define REUSED_PRINT_MIN_COUNT 100
#define MAX_CLIENT_CCT_PRINT_DEPTH 10

void
UpdateUseAndReuseMap(per_thread_t *pt, mem_ref_t * ref, int cur_mem_idx)
{
    map<uint64_t, use_node_t> *use_map = pt->tls_use_map;
    map<uint64_t, use_node_t>::iterator it = (*use_map).find((uint64_t)ref->addr);
    
    if (it != (*use_map).end()) {
        uint64_t reuse_distance = cur_mem_idx - it->second.last_reuse_mem_idx;
        uint64_t new_pair = (((uint64_t)it->second.use_hndl) << 32) + ref->ctxt_hndl;

        map<uint64_t, reuse_node_t> *pair_map = pt->tls_reuse_map;
        map<uint64_t, reuse_node_t>::iterator pair_it = (*pair_map).find(new_pair);
        if (pair_it != (*pair_map).end()) {
            pair_it->second.count++;
            pair_it->second.distance += reuse_distance;
        } else {
            reuse_node_t val(reuse_distance, 1);
            (*pair_map).insert(
                pair<uint64_t, reuse_node_t>(new_pair, val));
        }
        it->second.use_hndl = ref->ctxt_hndl;
        it->second.last_reuse_mem_idx = cur_mem_idx;
    } else {
        use_node_t new_entry(ref->ctxt_hndl, cur_mem_idx);
        (*use_map).insert(pair<uint64_t, use_node_t>((uint64_t)(ref->addr), new_entry));
    }
}

void
InitPrintFile()
{
#ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.drcctlib_reuse_distance.topn.out.log";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib_reuse_distance.topn.out.log";
#endif
    cerr << "Creating log file at:" << name << endl;

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");
}

void
PrintTopN(per_thread_t *pt, uint32_t print_num)
{
    // print_num = (*(pt->tls_reuse_map)).size();
    output_format_t* output_format_list = (output_format_t*)dr_global_alloc(print_num * sizeof(output_format_t));
    for(uint32_t i = 0; i < print_num; i ++ ) {
        output_format_list[i].use_hndl = 0;
        output_format_list[i].reuse_hndl = 0;
        output_format_list[i].count = 0;
        output_format_list[i].distance = 0;
    }
    map<uint64_t, reuse_node_t>::iterator it;
    for (it = (*(pt->tls_reuse_map)).begin(); it != (*(pt->tls_reuse_map)).end(); ++it) {
        uint64_t distance = it->second.distance / it->second.count;
        if (distance < REUSED_THRES || it->second.count < REUSED_PRINT_MIN_COUNT)
            continue;
        
        context_handle_t use_hndl = (context_handle_t)(it->first >> 32);
        context_handle_t reuse_hndl = (context_handle_t)(it->first);
        if (it->second.count > output_format_list[0].count) {
            uint64_t min_count = output_format_list[1].count;
            uint32_t min_idx = 1;
            for (uint32_t i = 2; i < print_num; i++) {
                if (output_format_list[i].count < min_count) {
                    min_count = output_format_list[i].count;
                    min_idx = i;
                }
            }
            if (it->second.count < min_count) {
                output_format_list[0].count = it->second.count;
                output_format_list[0].distance = distance;
                output_format_list[0].reuse_hndl = reuse_hndl;
                output_format_list[0].use_hndl = use_hndl;
            } else {
                output_format_list[0].count = output_format_list[min_idx].count;
                output_format_list[0].distance = output_format_list[min_idx].distance;
                output_format_list[0].reuse_hndl = output_format_list[min_idx].reuse_hndl;
                output_format_list[0].use_hndl = output_format_list[min_idx].use_hndl;

                output_format_list[min_idx].count = it->second.count;
                output_format_list[min_idx].distance = distance;
                output_format_list[min_idx].reuse_hndl = reuse_hndl;
                output_format_list[min_idx].use_hndl = use_hndl;
            }
        }
    }
    output_format_t temp;
    for (uint32_t i = 0; i < print_num; i++) {
        for (uint32_t j = i; j < print_num; j++) {
            if(output_format_list[i].count < output_format_list[j].count) {
                temp = output_format_list[i];
                output_format_list[i] = output_format_list[j];
                output_format_list[j] = temp;
            }
        }
    }
    InitPrintFile();
    dr_fprintf(gTraceFile, "max memory idx %lu\n", pt->cur_mem_idx);
    // output the selected reuse pairs
    uint32_t no = 0;
    for (uint32_t i = 0; i < print_num; i++) {
        if (output_format_list[i].count == 0)
            continue;
        no ++;
        dr_fprintf(gTraceFile, "No.%u counts(%lu) avg distance(%lu)\n", no, output_format_list[i].count, output_format_list[i].distance);
        dr_fprintf(gTraceFile, "====================================use=======================================\n");
        drcctlib_print_full_cct(gTraceFile, output_format_list[i].use_hndl, true, true, MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "====================================reuse=========================================\n");
        drcctlib_print_full_cct(gTraceFile, output_format_list[i].reuse_hndl, true, true, MAX_CLIENT_CCT_PRINT_DEPTH);
        dr_fprintf(gTraceFile, "================================================================================\n\n\n");
    }
    dr_global_free(output_format_list, print_num * sizeof(output_format_t));
}

void
ResetPtMap(per_thread_t *pt)
{
    delete pt->tls_use_map;
    pt->tls_use_map = new map<uint64_t,use_node_t>();
}

void 
BBStartInsertCleancall(int num)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
    int next_buf_max_idx = pt->cur_buf_fill_num + num;
    if (next_buf_max_idx > TLS_MEM_REF_BUFF_SIZE) {
        pt->cur_mem_idx += pt->cur_buf_fill_num;
#ifdef SAMPLE_RUN
        if (pt->cur_mem_idx % UNITE_NUM <= SAMPLE_NUM) {
            int i = 0;
            if(!pt->sample_mem) {
                i = UNITE_NUM - pt->last_mem_idx % UNITE_NUM;
            }
            for (; i < pt->cur_buf_fill_num; i++) {
                int cur_mem_idx = pt->last_mem_idx + i;
                if (pt->cur_buf_list[i].addr != 0) {
                    UpdateUseAndReuseMap(pt, &pt->cur_buf_list[i], cur_mem_idx);
                }
            }
            pt->sample_mem = true;
        } else if(pt->last_mem_idx % UNITE_NUM <= SAMPLE_NUM) {
            int sample_num = SAMPLE_NUM - pt->last_mem_idx % UNITE_NUM;
            for (int i = 0; i < sample_num; i++) {
                int cur_mem_idx = pt->last_mem_idx + i;
                if (pt->cur_buf_list[i].addr != 0) {
                    UpdateUseAndReuseMap(pt, &pt->cur_buf_list[i], cur_mem_idx);
                }
            }
            pt->sample_mem = true;
        } else if(pt->sample_mem) {
            ResetPtMap(pt);
            pt->sample_mem = false;
        }
#else
        for (int i = 0; i < pt->cur_buf_fill_num; i++) {
            int cur_mem_idx = pt->last_mem_idx + i;
            if (pt->cur_buf_list[i].addr != 0) {
                UpdateUseAndReuseMap(pt, &pt->cur_buf_list[i], cur_mem_idx);
            }
        }
#endif
        BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
        pt->cur_buf_fill_num = 0;
    }
    pt->last_mem_idx = pt->cur_mem_idx;
    pt->cur_buf_fill_num += num;
}

static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
              opnd_t ctxt_hndl_addr)
{
    /* We need two scratch registers */
    reg_id_t reg_mem_ref_ptr, reg_1;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_1) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_1, reg_mem_ref_ptr)) {
        MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_1),
                                    OPND_CREATE_CCT_INT(0)));
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                               tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, addr)),
                opnd_create_reg(reg_1)));
    // store mem_ref_t->ctxt_hndl
    MINSERT(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg_1), ctxt_hndl_addr));
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext,
                OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, ctxt_hndl)),
                opnd_create_reg(reg_1)));

#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(reg_1),
                                    OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                                opnd_create_reg(reg_1)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                                OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
#endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_1) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}

int
BBMemRefNum(instrlist_t *instrlits)
{
    int num = 0;
    for (instr_t *instr = instrlist_first_app(instrlits); instr != NULL;
         instr = instr_get_next_app(instr)) {
        for (int i = 0; i < instr_num_srcs(instr); i++) {
            if (opnd_is_memory_reference(instr_get_src(instr, i))) {
                num++;
            }
        }
        for (int i = 0; i < instr_num_dsts(instr); i++) {
            if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
                num++;
            }
        }
    }
    return num;
}

void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg, void *data)
{

    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    if (instr_is_call_direct(instr) || instr_is_call_indirect(instr) ||
        instr_is_return(instr)) {
        return;
    }
    if (instrument_msg->interest_start) {
        int bb_num = BBMemRefNum(bb);
        dr_insert_clean_call(drcontext, bb, instr, (void *)BBStartInsertCleancall, false, 1,
                             OPND_CREATE_CCT_INT(bb_num));
    }

    reg_id_t reg_ctxt_hndl_addr, reg_tls;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_ctxt_hndl_addr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentInsCallback drreg_reserve_register != DRREG_SUCCESS");
    }
    drcctlib_get_context_handle_in_reg(drcontext, bb, instr, reg_ctxt_hndl_addr);
    opnd_t ctxt_hndl_addr = OPND_CREATE_CTXT_HNDL_MEM(reg_ctxt_hndl_addr, 0);
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))){
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i), ctxt_hndl_addr);
        }     
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i), ctxt_hndl_addr);
        }
    }
    if (drreg_unreserve_register(drcontext, bb, instr, reg_ctxt_hndl_addr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentInsCallback drreg_unreserve_register != DRREG_SUCCESS");
    }
}



static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if(pt == NULL){
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);
    pt->cur_buf_list = (mem_ref_t*)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    pt->last_mem_idx = 0;
    pt->cur_mem_idx = 0;
    pt->cur_buf_fill_num = 0;
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;

    pt->tls_use_map = new map<uint64_t,use_node_t>();
    pt->tls_reuse_map = new map<uint64_t, reuse_node_t>();
    pt->sample_mem = false;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    
    BBStartInsertCleancall(TLS_MEM_REF_BUFF_SIZE);
    PrintTopN(pt, OUTPUT_SIZE);
    
    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    delete pt->tls_use_map;
    delete pt->tls_reuse_map;
    
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}




static void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.drcctlib_reuse_distance.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib_reuse_distance.out.";
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

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");

    for (int i = 0; i < argc; i++) {
        dr_fprintf(gTraceFile, "%d %s \n", i, argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");
}

static void
ClientExit(void)
{
    drcctlib_exit();

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance dr_raw_tls_calloc fail");
    } 

    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd)) {
        DRCCTLIB_PRINTF("ERROR: drcctlib_reuse_distance failed to unregister in ClientExit");
    }
    drmgr_exit();
    drutil_exit();
}


#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_reuse_distance'",
                       "http://dynamorio.org/issues");
    app_name = (char*)dr_global_alloc(MAXIMUM_PATH * sizeof(char));
    const char *name = dr_get_application_name();
    sprintf(app_name, "%s", name);
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, gTraceFile, InstrumentInsCallback, NULL,
                     NULL, NULL, DRCCTLIB_DEFAULT);

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 3 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance unable to initialize drutil");
    }
    dr_register_exit_event(ClientExit);
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance dr_raw_tls_calloc fail");
    }
}

#ifdef __cplusplus
}
#endif