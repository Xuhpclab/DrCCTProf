/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drcctlib.h"
#include "drcctlib_vscodeex_format.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("memory_with_data_centric", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("memory_with_data_centric", _FORMAT, ##_ARGS)


using namespace DrCCTProf;

// client want to do
static inline void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl, app_pc addr)
{
}

static inline void
InstrumentPerBBCache(void *drcontext, context_handle_t ctxt_hndl, int32_t slot_num,
                     int32_t mem_ref_num, mem_ref_msg_t *mem_ref_start, void **data)
{
    for (int32_t i = 0; i < mem_ref_num; i++) {
        if (mem_ref_start[i].slot >= slot_num) {
            break;
        }
        DoWhatClientWantTodo(drcontext, ctxt_hndl + mem_ref_start[i].slot,
                             mem_ref_start[i].addr);
    }
}

static void
ClientInit(int argc, const char *argv[])
{
}
#define ALLOC_THRES 128
static void
ClientExit(void)
{
    std::vector<datacentric_node_t>* static_datacentric_nodes = drcctlib_get_static_datacentric_nodes();
    std::vector<datacentric_node_t>* dynamic_datacentric_nodes = drcctlib_get_dynamic_datacentric_nodes();

    Profile::profile_t* static_profile = new Profile::profile_t();
    static_profile->add_metric_type(0, " ", "alloc type");
    static_profile->add_metric_type(1, "bytes", "alloc memory");
    std::vector<datacentric_node_t>::iterator it = (*static_datacentric_nodes).begin();
    for (; it != (*static_datacentric_nodes).end();it++) {
        if ((*it).count < ALLOC_THRES) {
            continue;
        }
        inner_context_t* cur_ctxt = drcctlib_get_full_cct_of_datacentric_nodes(*it);
        // DRCCTLIB_PRINTF("%s", cur_ctxt->func_name);
        Profile::sample_t* sample = static_profile->add_sample(cur_ctxt);
        sample->append_metirc((int64_t)0);
        sample->append_metirc((*it).count);
        drcctlib_free_full_cct(cur_ctxt);
    }
    static_profile->serialize_to_file("static_data.datacentric.drcctprof");
    delete static_profile;

    Profile::profile_t* dynamic_profile = new Profile::profile_t();
    dynamic_profile->add_metric_type(0, " ", "alloc type");
    dynamic_profile->add_metric_type(1, "bytes", "alloc memory");
    it = (*dynamic_datacentric_nodes).begin();
    for (; it != (*dynamic_datacentric_nodes).end();it++) {
        if ((*it).count < ALLOC_THRES) {
            continue;
        }
        inner_context_t* cur_ctxt = drcctlib_get_full_cct_of_datacentric_nodes(*it);
        // DRCCTLIB_PRINTF("%s", cur_ctxt->func_name);
        Profile::sample_t* sample = dynamic_profile->add_sample(cur_ctxt);
        sample->append_metirc((int64_t)1);
        sample->append_metirc((*it).count);
        drcctlib_free_full_cct(cur_ctxt);
    }
    dynamic_profile->serialize_to_file("dynamic_data.datacentric.drcctprof");
    delete dynamic_profile;
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_memory_with_data_centric_vse_fmt'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    drcctlib_init_ex(DRCCTLIB_FILTER_MEM_ACCESS_INSTR, INVALID_FILE, NULL, NULL,
                     InstrumentPerBBCache,
                     DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE | DRCCTLIB_CACHE_MODE |
                         DRCCTLIB_CACHE_MEMEORY_ACCESS_ADDR);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif