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
// static int tls_idx;
// static vector<void*> gMapList;
// static void *lock;

// enum {
//     INSTRACE_TLS_OFFS_BUF_PTR,
//     INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
// };

// static reg_id_t tls_seg;
// static uint tls_offs;
// #define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
// #define BUF_PTR(tls_base) *(mem_ref_t **)TLS_SLOT(tls_base, INSTRACE_TLS_OFFS_BUF_PTR)
// #define MINSERT instrlist_meta_preinsert

// #ifdef ARM_CCTLIB
// #    define OPND_CREATE_CCT_INT OPND_CREATE_INT
// #else
// #    ifdef CCTLIB_64
// #        define OPND_CREATE_CCT_INT OPND_CREATE_INT64
// #    else
// #        define OPND_CREATE_CCT_INT OPND_CREATE_INT32
// #    endif
// #endif

// #ifdef CCTLIB_64
// #    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM64
// #    define OPND_CREATE_MEM_IDX_MEM OPND_CREATE_MEM64
// #else
// #    define OPND_CREATE_CTXT_HNDL_MEM OPND_CREATE_MEM32
// #    define OPND_CREATE_MEM_IDX_MEM OPND_CREATE_MEM32
// #endif

// #define OUTPUT_SIZE 10
// #define REUSED_THRES 8192
// #define MAX_CLIENT_CCT_PRINT_DEPTH 10
// #define MEM_NUM 100000000

// #ifdef CCTLIB_64
// #define aligned_memeory_idx_t uint64_t
// #else
// #define aligned_memeory_idx_t uint32_t
// #endif

// struct _mem_ref_t {
//     aligned_ctxt_hndl_t ctxt_hndl;
//     aligned_memeory_idx_t memory_idx;
//     app_pc addr;
// } mem_ref_t;

// static mem_ref_t *global_mem_ref_buff;

// struct map_entry_t {
//     context_handle_t ctxt_hndl;
//     uint64_t memory_idx;
//     map_entry_t(context_handle_t c, uint64_t m)
//         : ctxt_hndl(c)
//         , memory_idx(m)
//     {
//     }
// };

// struct reuse_value_t {
//     context_handle_t reuse_hndl;
//     uint64_t distance;
//     uint64_t count;

//     reuse_value_t(context_handle_t ru, uint64_t d, uint64_t c)
//         : reuse_hndl(ru)
//         , distance(d)
//         , count(c)
//     {
//     }
// };

// typedef struct _output_format_t {
//   app_pc addr;
//   context_handle_t reuse_hndl;
//   uint64_t count;
//   uint64_t distance;
// } output_format_t;

// typedef struct _per_thread_t{
//     aligned_memeory_idx_t cur_memory_idx;
//     mem_ref_t *cur_buf_list;
//     void *cur_buf;
//     map<uint64_t, map_entry_t> *tls_reuse_map;
//     multimap<uint64_t, reuse_value_t> *tls_reuse_pair_map;
// } per_thread_t;

// void
// comp_reuse_d(per_thread_t *pt, mem_ref_t * ref)
// {

//     uint64_t reuse_distance;
//     map<uint64_t, map_entry_t> *map_it = pt->tls_reuse_map;
//     map<uint64_t, map_entry_t>::iterator it;
//     it = (*map_it).find((uint64_t)addr);
//     if (it != (*map_it).end()) {
//         reuse_distance = pt->last_memory_idx - it->second.memory_idx;
//         // dr_fprintf(gTraceFile, "last_memory_idx(%lu) it->second.memory_idx(%lu) reuse_distance(%lu)\n", pt->last_memory_idx, it->second.memory_idx, reuse_distance);
//         // make reuse pairs
//         multimap<uint64_t, reuse_value_t> *pair_map = pt->tls_reuse_pair_map;
//         multimap<uint64_t, reuse_value_t>::iterator pair_it;

//         pair<multimap<uint64_t, reuse_value_t>::iterator,
//              multimap<uint64_t, reuse_value_t>::iterator>
//             pair_range_it;
        
//         pair_range_it = (*pair_map).equal_range((uint64_t)addr);
//         for (pair_it = pair_range_it.first; pair_it != pair_range_it.second; ++pair_it) {
//             if (pair_it->second.reuse_hndl == it->second.ctxt_hndl) {
//                 pair_it->second.count++;
//                 pair_it->second.distance += reuse_distance;
//                 // dr_fprintf(gTraceFile, "addr(%p) counts(%lu) distance(%lu)\n", addr, pair_it->second.count, pair_it->second.distance);
//                 break;
//             }
//         }
//         if (pair_it == pair_range_it.second) {
//             reuse_value_t val(it->second.ctxt_hndl, reuse_distance, 1);
//             // dr_fprintf(gTraceFile, "addr(%p) counts(%lu) distance(%lu)\n", addr, 1, reuse_distance);
//             (*pair_map).insert(pair<uint64_t, reuse_value_t>((uint64_t)addr, val));
//         }

//         it->second.memory_idx = pt->last_memory_idx;
//         it->second.ctxt_hndl = pt->last_ctxt_hndl;
//     } else {
//         map_entry_t new_entry(pt->last_ctxt_hndl, pt->last_memory_idx);
//         (*map_it).insert(pair<uint64_t, map_entry_t>((uint64_t)addr, new_entry));
//     }
// }
// static output_format_t gOutputArray[OUTPUT_SIZE];
// void
// output_top_n(per_thread_t *pt)
// {
//     dr_mutex_lock(lock);
//     int i, ind;
//     uint64_t min_count = ULONG_MAX;
//     multimap<uint64_t, reuse_value_t>::iterator it;
//     for (it = (*(pt->tls_reuse_pair_map)).begin(); it != (*(pt->tls_reuse_pair_map)).end(); ++it) {
//         if (it->second.distance / it->second.count < REUSED_THRES)
//             continue;
//         if (it->second.count > gOutputArray[0].count) {
//             min_count = gOutputArray[1].count;
//             ind = 1;
//             for (i = 2; i < OUTPUT_SIZE; i++) {
//                 if (gOutputArray[i].count < min_count) {
//                     min_count = gOutputArray[i].count;
//                     ind = i;
//                 }
//             }
//             if (it->second.count < min_count) {
//                 gOutputArray[0].count = it->second.count;
//                 gOutputArray[0].distance = it->second.distance;
//                 gOutputArray[0].reuse_hndl = it->second.reuse_hndl;
//                 gOutputArray[0].addr = (app_pc)(it->first);
//             } else {
//                 gOutputArray[0].count = gOutputArray[ind].count;
//                 gOutputArray[0].distance = gOutputArray[ind].distance;
//                 gOutputArray[0].reuse_hndl = gOutputArray[ind].reuse_hndl;
//                 gOutputArray[0].addr = gOutputArray[ind].addr;

//                 gOutputArray[ind].count = it->second.count;
//                 gOutputArray[ind].distance = it->second.distance;
//                 gOutputArray[ind].reuse_hndl = it->second.reuse_hndl;
//                 gOutputArray[ind].addr = (app_pc)(it->first);
//             }
//         }
//     }

//     // output the selected reuse pairs
//     for (i = 0; i < OUTPUT_SIZE; i++) {
//         if (gOutputArray[i].count == 0)
//             continue;
//         dr_fprintf(gTraceFile, "addr(%p) counts(%lu) distance(%lu)\n", (uint64_t)gOutputArray[i].addr, gOutputArray[i].count, gOutputArray[i].distance);
//         dr_fprintf(gTraceFile, "================================================================================\n");
//         drcctlib_print_full_cct(gOutputArray[i].reuse_hndl, true, false, MAX_CLIENT_CCT_PRINT_DEPTH);
//         dr_fprintf(gTraceFile, "================================================================================\n\n\n");
    
//     }
//     dr_mutex_unlock(lock);
// }

// int
// BBMemRefNum(instrlist_t *instrlits)
// {
//     int num = 0;
//     for (instr_t *instr = instrlist_first_app(instrlits); instr != NULL;
//          instr = instr_get_next_app(instr)) {
//         for (int i = 0; i < instr_num_srcs(instr); i++) {
//             if (opnd_is_memory_reference(instr_get_src(instr, i))) {
//                 num++;
//             }
//         }
//         for (int i = 0; i < instr_num_dsts(instr); i++) {
//             if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
//                 num++;
//             }
//         }
//     }
//     return num;
// }

// void 
// BBStartInsertCleancall(int num)
// {
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
//     for(int i = 0; i < num; i++) {

//     }
//     BUF_PTR(pt->cur_buf) = pt->cur_buf_list;
// }

// void
// UpdatePtMemoryRefMap(per_thread_t *pt)
// {
//     for(int i = 0; i < pt->cur_buf_list_size; i ++) {
//         comp_reuse_d(pt, pt->cur_buf_list[i]);
//     }
// }

// void
// CreateNewInstrMemoryRefBuff(per_thread_t *pt, int num)
// {
//     dr_global_free(pt->cur_buf_list, pt->cur_buf_list_size);
//     pt->cur_buf_list = (app_pc*)dr_global_alloc(num * sizeof(app_pc));
//     pt->cur_buf_list_size = num;
//     for(int i = 0; i < pt->cur_buf_list_size; i ++) {
//         pt->cur_buf_list[i] = (app_pc)0;
//     }
//     BUF_PTR(pt->cur_buf) = pt->cur_buf_list;
// }

// void
// InstrumentMemCall(int num)
// {
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);
//     UpdatePtMemoryRefMap(pt);
//     CreateNewInstrMemoryRefBuff(pt, num);
//     pt->last_memory_idx ++;
//     pt->last_ctxt_hndl = drcctlib_get_context_handle();
// }

// static void
// InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
// {
//     /* We need two scratch registers */
//     reg_id_t reg_ptr, reg_addr;
//     if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
//             DRREG_SUCCESS ||
//         drreg_reserve_register(drcontext, ilist, where, NULL, &reg_addr) !=
//             DRREG_SUCCESS) {
//         DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
//     }

//     if(!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr, reg_ptr)) {
//         DRCCTLIB_PRINTF("drutil_insert_get_mem_addr fail");
//     } 
//     dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
//                         tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
//     MINSERT(ilist, where,
//         XINST_CREATE_store(drcontext,
//                             OPND_CREATE_MEMPTR(reg_ptr, 0),
//                             opnd_create_reg(reg_addr)));
//     MINSERT(ilist, where,
//             XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr),
//                                 IF_ARM_CCTLIB_ELSE(OPND_CREATE_INT, OPND_CREATE_INT16)(sizeof(app_pc))));
//     dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
//                             tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
//     /* Restore scratch registers */
//     if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
//         drreg_unreserve_register(drcontext, ilist, where, reg_addr) != DRREG_SUCCESS) {
//         DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
//     }
// }

void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg, void *data)
{
    // int i;
    // instrlist_t *bb = instrument_msg->bb;
    // instr_t *instr = instrument_msg->instr;
    // int32_t slot = instrument_msg->slot;

    // if (instrument_msg->interest_start) {
    //     int bb_num = BBMemRefNum(bb);
    //     dr_insert_clean_call(drcontext, bb, instr, (void *)BBStartCleanCall, false, 1,
    //                          OPND_CREATE_CCT_INT(bb_num));
    // }
    
    // for (i = 0; i < instr_num_srcs(instr); i++) {
    //     if (opnd_is_memory_reference(instr_get_src(instr, i))){
    //         InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
    //     }     
    // }
    // for (i = 0; i < instr_num_dsts(instr); i++) {
    //     if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
    //         InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
    //     }
    // }
}



// #define TLS_MEM_REF_BUFF_SIZE 1000
// static void
// ClientThreadStart(void *drcontext)
// {
//     per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
//     if(pt == NULL){
//         DRCCTLIB_EXIT_PROCESS("pt == NULL");
//     }
//     drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

//     pt->cur_buf = dr_get_dr_segment_base(tls_seg);
//     pt->cur_buf_list = (mem_ref_t*)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
//     pt->cur_memory_idx = 0;
//     BUF_PTR(pt->cur_buf) = pt->cur_buf_list;

//     pt->tls_reuse_map = new map<uint64_t,map_entry_t>();
//     pt->tls_reuse_pair_map = new multimap<uint64_t,reuse_value_t>();
// }

// static void
// ClientThreadEnd(void *drcontext)
// {
//     per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
//     UpdatePtMemoryRefMap(pt);
//     output_top_n(pt);


//     dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
//     delete pt->tls_reuse_map;
//     delete pt->tls_reuse_pair_map;
    
//     dr_thread_free(drcontext, pt, sizeof(per_thread_t));
// }

// static inline void
// InitGlobalBuff()
// {
//     global_mem_ref_buff =
//         (mem_ref_t *)mmap(0, CONTEXT_HANDLE_MAX * sizeof(mem_ref_t),
//                               PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
//     if (global_mem_ref_buff == MAP_FAILED) {
//         DRCCTLIB_EXIT_PROCESS("init_global_buff error: MAP_FAILED global_mem_ref_buff");
//     }
// }

// static inline void
// FreeGlobalBuff()
// {
//     if (munmap(global_mem_ref_buff, CONTEXT_HANDLE_MAX * sizeof(mem_ref_t)) != 0) {
//         // || munmap(global_string_pool, CONTEXT_HANDLE_MAX * sizeof(char)) != 0) {
//         DRCCTLIB_PRINTF("free_global_buff munmap error");
//     }
// }

static void
ClientInit(int argc, const char *argv[])
{
#ifdef ARM_CCTLIB
    char name[MAXIMUM_PATH] = "arm.drcctlib.client.out.";
#else
    char name[MAXIMUM_PATH] = "x86.drcctlib.client.out.";
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
        dr_fprintf(gTraceFile, "%d %s ", i, argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");

    // InitGlobalBuff();
}

static void
ClientExit(void)
{
    // for(uint32_t i = 0; i < gMapList.size(); i++) {

    // }
    // FreeGlobalBuff();
    // drcctlib_exit();

    // dr_mutex_destroy(lock);
    // if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
    //     DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance dr_raw_tls_calloc fail");
    // } 

    // if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
    //     !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
    //     !drmgr_unregister_tls_field(tls_idx)) {
    //     DRCCTLIB_PRINTF("ERROR: drcctlib_reuse_distance failed to unregister in ClientExit");
    // }
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
    ClientInit(argc, argv);
    // drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, gTraceFile, InstrumentInsCallback, NULL,
    //                  NULL, NULL, DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE);

    // if (!drmgr_init()) {
    //     DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance unable to initialize drmgr");
    // }
    // drreg_options_t ops = { sizeof(ops), 3 /*max slots needed*/, false };
    // if (drreg_init(&ops) != DRREG_SUCCESS) {
    //     DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance unable to initialize drreg");
    // }
    // if (!drutil_init()) {
    //     DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance unable to initialize drutil");
    // }
    // dr_register_exit_event(ClientExit);
    // drmgr_register_thread_init_event(ClientThreadStart);
    // drmgr_register_thread_exit_event(ClientThreadEnd);

    // lock = dr_mutex_create();
    // tls_idx = drmgr_register_tls_field();
    // if (tls_idx == -1) {
    //     DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance drmgr_register_tls_field fail");
    // }
    // if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
    //     DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_reuse_distance dr_raw_tls_calloc fail");
    // }
}

#ifdef __cplusplus
}
#endif

// void
// InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg, void *data)
// {
//     int i;
//     instrlist_t *bb = instrument_msg->bb;
//     instr_t *instr = instrument_msg->instr;
//     int num = 0;
//     for (i = 0; i < instr_num_srcs(instr); i++) {
//         if (opnd_is_memory_reference(instr_get_src(instr, i))) {
//             num ++;
//         }
//     }
//     for (i = 0; i < instr_num_dsts(instr); i++) {
//         if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
//             num ++;
//         }
//     }
//     dr_insert_clean_call(drcontext, bb, instr, (void *)InstrumentMemCall, false, 1,
//                          IF_ARM_CCTLIB_ELSE(OPND_CREATE_INT, OPND_CREATE_INT32)(num));

//     for (i = 0; i < instr_num_srcs(instr); i++) {
//         if (opnd_is_memory_reference(instr_get_src(instr, i)))
//             InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
//     }
//     for (i = 0; i < instr_num_dsts(instr); i++) {
//         if (opnd_is_memory_reference(instr_get_dst(instr, i)))
//             InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
//     }
// }