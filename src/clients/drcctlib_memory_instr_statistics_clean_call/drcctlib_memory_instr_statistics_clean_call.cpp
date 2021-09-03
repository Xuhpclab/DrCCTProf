/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cstddef>
#include <vector>
#include <map>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"

using namespace std;

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_instr_statistics_clean_call", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...)                                           \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_instr_statistics_clean_call", _FORMAT, \
                                          ##_ARGS)

static int tls_idx;

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
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT64
#endif

typedef struct _mem_ref_t {
    app_pc addr;
} mem_ref_t;

typedef struct _per_thread_t {
    mem_ref_t *cur_buf_list;
    void *cur_buf;
} per_thread_t;
#define TLS_MEM_REF_BUFF_SIZE 100

static map<context_handle_t, uint64_t>* mah_exe_times_map;
static multimap<context_handle_t, context_handle_t>* mah_used_memory_list_map;
static file_t gTraceFile;

void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, mem_ref_t *ref)
{
    data_handle_t data_hndl = drcctlib_get_data_hndl_runtime(drcontext, ref->addr);
    context_handle_t data_ctxt_hndl = 0;
    if (data_hndl.object_type == DYNAMIC_OBJECT) {
        data_ctxt_hndl = data_hndl.path_handle;
    } else if (data_hndl.object_type == STATIC_OBJECT) {
        data_ctxt_hndl = -data_hndl.sym_name;
    }

    multimap<context_handle_t, context_handle_t>::iterator pair_it;
    pair<multimap<context_handle_t, context_handle_t>::iterator,
            multimap<context_handle_t, context_handle_t>::iterator>
        pair_range_it;
    pair_range_it = (*mah_used_memory_list_map).equal_range(cur_ctxt_hndl);
    for (pair_it = pair_range_it.first; pair_it != pair_range_it.second; ++pair_it) {
        if (pair_it->second == data_ctxt_hndl) {
            break;
        }
    }

    if (pair_it == pair_range_it.second) {
        (*mah_used_memory_list_map).insert(pair<context_handle_t, context_handle_t>(cur_ctxt_hndl, data_ctxt_hndl));
    }
}

// dr clean call
void
InsertCleancall(int slot, int num)
{
    void *drcontext = dr_get_current_drcontext();
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if(num > 0) {
        map<context_handle_t, uint64_t>::iterator it = (*mah_exe_times_map).find(cur_ctxt_hndl);
        if (it != (*mah_exe_times_map).end()) {
            it->second ++;
        } else {
            (*mah_exe_times_map).insert(pair<context_handle_t, uint64_t>(cur_ctxt_hndl, 1));
        }
    }
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0) {
            DoWhatClientWantTodo(drcontext, cur_ctxt_hndl, &pt->cur_buf_list[i]);
        }
    }
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

// insert
static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
{
    /* We need two scratch registers */
    reg_id_t reg_mem_ref_ptr, free_reg;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &free_reg) !=
            DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, free_reg,
                                    reg_mem_ref_ptr)) {
        MINSERT(ilist, where,
                XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                      OPND_CREATE_CCT_INT(0)));
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, addr)),
                opnd_create_reg(free_reg)));

#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             opnd_create_reg(free_reg)));
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
        drreg_unreserve_register(drcontext, ilist, where, free_reg) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    int num = 0;
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i));
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            num++;
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i));
        }
    }
    dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 2,
                         OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(num));
}

void
InitBuffer()
{
    mah_exe_times_map = new map<context_handle_t, uint64_t>();
    mah_used_memory_list_map = new multimap<context_handle_t, context_handle_t>(); 
}

void
FreeBuffer()
{
    delete mah_exe_times_map;
    delete mah_used_memory_list_map;
}

void
InitLogFile()
{
    char name[MAXIMUM_FILEPATH] = "";
    DRCCTLIB_INIT_LOG_FILE_NAME(name, "drcctlib_memory_instr_statistics_clean_call", "out");
    DRCCTLIB_PRINTF("Creating log file at:%s", name);

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
}

#define TOP_REACH_NUM_SHOW 200
typedef struct _output_format_t {
    context_handle_t handle;
    uint64_t count;
} output_format_t;

void
PrintToLogFile()
{
    output_format_t *output_list =
        (output_format_t *)dr_global_alloc(TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        output_list[i].handle = 0;
        output_list[i].count = 0;
    }

    map<context_handle_t, uint64_t>::iterator it;
    for(it = (*mah_exe_times_map).begin(); it != (*mah_exe_times_map).end(); it++) {
        if(it->second > output_list[0].count) {
            bool has_known_dataobj = false;
            multimap<context_handle_t, context_handle_t>::iterator pair_it;
            pair<multimap<context_handle_t, context_handle_t>::iterator,
                    multimap<context_handle_t, context_handle_t>::iterator>
                pair_range_it;
            pair_range_it = (*mah_used_memory_list_map).equal_range(it->first);
            for (pair_it = pair_range_it.first; pair_it != pair_range_it.second; ++pair_it) {
                if(pair_it->second != 0) {
                    has_known_dataobj = true;
                    break;
                }
            }
            if(!has_known_dataobj){
                continue;
            }
            uint64_t min_count = it->second;
            int32_t min_idx = 0;
            for (int32_t j = 1; j < TOP_REACH_NUM_SHOW; j++) {
                if (output_list[j].count < min_count) {
                    min_count = output_list[j].count;
                    min_idx = j;
                }
            }
            output_list[0] = output_list[min_idx];
            output_list[min_idx].count = it->second;
            output_list[min_idx].handle = it->first;
        }
    }

    output_format_t temp;
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        for (int32_t j = i; j < TOP_REACH_NUM_SHOW; j++) {
            if (output_list[i].count < output_list[j].count) {
                temp = output_list[i];
                output_list[i] = output_list[j];
                output_list[j] = temp;
            }
        }
    }
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        if (output_list[i].handle == 0) {
            break;
        }
        dr_fprintf(gTraceFile, "NO. %d PC ", i + 1);
        drcctlib_print_backtrace_first_item(gTraceFile, output_list[i].handle, true, false);
        dr_fprintf(gTraceFile, "=>EXECUTION TIMES\n%lld\n=>BACKTRACE\n",
                   output_list[i].count);
        drcctlib_print_backtrace(gTraceFile, output_list[i].handle, false, true, -1);

        multimap<context_handle_t, context_handle_t>::iterator pair_it;
        pair<multimap<context_handle_t, context_handle_t>::iterator,
                multimap<context_handle_t, context_handle_t>::iterator>
            pair_range_it;
        pair_range_it = (*mah_used_memory_list_map).equal_range(output_list[i].handle);
        for (pair_it = pair_range_it.first; pair_it != pair_range_it.second; ++pair_it) {
            if (pair_it->second < 0) {
                dr_fprintf(gTraceFile, "=>USED STATIC MEMORY OBJECT BACKTRACE\n%s\n",drcctlib_get_str_from_strpool(-pair_it->second));
            } else if (pair_it->second > 0) {
                dr_fprintf(gTraceFile, "=>USED DYNAMIC MEMORY OBJECT BACKTRACE\n");
                drcctlib_print_backtrace(gTraceFile, pair_it->second, false, true, -1);
            // } else {
            //     dr_fprintf(gTraceFile, "=>UNKNOWN MEMORY OBJECT\n???\n");
            }
        }
        dr_fprintf(gTraceFile, "\n\n\n");
    }
    dr_global_free(output_list, TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    dr_close_file(gTraceFile);
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);

    pt->cur_buf = dr_get_dr_segment_base(tls_seg);
    pt->cur_buf_list =
        (mem_ref_t *)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    drmgr_init();
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    drreg_init(&ops);
    drutil_init();
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    tls_idx = drmgr_register_tls_field();
    dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0);
    drcctlib_init(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback, true);

    InitBuffer();
    InitLogFile();
}

static void
ClientExit(void)
{
    PrintToLogFile();
    FreeBuffer();

    drcctlib_exit();
    
    drmgr_unregister_thread_init_event(ClientThreadStart);
    drmgr_unregister_thread_exit_event(ClientThreadEnd);
    drmgr_unregister_tls_field(tls_idx);
    drmgr_exit();
    dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT);

    drreg_exit();
    drutil_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    ClientInit(argc, argv);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif