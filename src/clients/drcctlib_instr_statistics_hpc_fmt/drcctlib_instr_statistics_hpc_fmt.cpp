/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drcctlib.h"
#include "drcctlib_hpcviewer_format.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("instr_statistics_hpc_fmt", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("instr_statistics_hpc_fmt", _FORMAT, ##_ARGS)

#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH_NUM_SHOW 200

uint64_t *gloabl_hndl_call_num;

// dr clean call per ins cache
static inline void
InstrumentPerInsCache(void *drcontext, context_handle_t ctxt_hndl, int32_t mem_ref_num,
                      mem_ref_msg_t *mem_ref_start, void *data)
{
    gloabl_hndl_call_num[ctxt_hndl]++;
}

static inline void
InstrumentPerBBCache(void *drcontext, context_handle_t ctxt_hndl, int32_t slot_num,
                     int32_t mem_ref_num, mem_ref_msg_t *mem_ref_start, void **data)
{
    int32_t temp_index = 0;
    for (int32_t i = 0; i < slot_num; i++) {
        int32_t ins_ref_number = 0;
        mem_ref_msg_t *ins_cache_mem_start = NULL;
        for (; temp_index < mem_ref_num; temp_index++) {
            if (mem_ref_start[temp_index].slot == i) {
                if (ins_cache_mem_start == NULL) {
                    ins_cache_mem_start = mem_ref_start + temp_index;
                }
                ins_ref_number++;
            } else if (mem_ref_start[temp_index].slot > i) {
                break;
            }
        }
        InstrumentPerInsCache(drcontext, ctxt_hndl + i, ins_ref_number,
                              ins_cache_mem_start, data);
    }
}

static inline void
InitGlobalBuff()
{
    gloabl_hndl_call_num = (uint64_t *)dr_raw_mem_alloc(
        CONTEXT_HANDLE_MAX * sizeof(uint64_t), DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (gloabl_hndl_call_num == NULL) {
        DRCCTLIB_EXIT_PROCESS(
            "init_global_buff error: dr_raw_mem_alloc fail gloabl_hndl_call_num");
    }
}

static inline void
FreeGlobalBuff()
{
    dr_raw_mem_free(gloabl_hndl_call_num, CONTEXT_HANDLE_MAX * sizeof(int64_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    InitGlobalBuff();
}

typedef struct _output_format_t {
    context_handle_t handle;
    uint64_t count;
} output_format_t;

static void
ClientExit(void)
{
    output_format_t *output_list =
        (output_format_t *)dr_global_alloc(TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        output_list[i].handle = 0;
        output_list[i].count = 0;
    }
    context_handle_t max_ctxt_hndl = drcctlib_get_global_context_handle_num();
    for (context_handle_t i = 0; i < max_ctxt_hndl; i++) {
        if (gloabl_hndl_call_num[i] <= 0) {
            continue;
        }
        if (gloabl_hndl_call_num[i] > output_list[0].count) {
            uint64_t min_count = gloabl_hndl_call_num[i];
            int32_t min_idx = 0;
            for (int32_t j = 1; j < TOP_REACH_NUM_SHOW; j++) {
                if (output_list[j].count < min_count) {
                    min_count = output_list[j].count;
                    min_idx = j;
                }
            }
            output_list[0].count = min_count;
            output_list[0].handle = output_list[min_idx].handle;
            output_list[min_idx].count = gloabl_hndl_call_num[i];
            output_list[min_idx].handle = i;
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

    vector<HPCRunCCT_t *> hpcRunNodes;
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        HPCRunCCT_t *hpcRunNode = new HPCRunCCT_t();
        hpcRunNode->ctxt_hndl_list.push_back(output_list[i].handle);
        hpcRunNode->metric_list.push_back(output_list[i].count);
        hpcRunNodes.push_back(hpcRunNode);
    }
    dr_global_free(output_list, TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    build_progress_custom_cct_hpurun_format(hpcRunNodes);
    write_progress_custom_cct_hpurun_format();

    FreeGlobalBuff();

    drcctlib_exit();
    hpcrun_format_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_instr_statistics_hpc_fmt'",
                       "http://dynamorio.org/issues");

    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache, DRCCTLIB_CACHE_MODE);
    hpcrun_format_init(dr_get_application_name(), false);
    hpcrun_create_metric("TOT_CALLS");
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif