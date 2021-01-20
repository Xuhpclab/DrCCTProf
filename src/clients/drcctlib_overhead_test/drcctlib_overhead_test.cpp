/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drcctlib.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("overhead", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("overhead", _FORMAT, ##_ARGS)

#ifdef x86_CCTLIB
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT32
#    define OPND_CREATE_SLOT OPND_CREATE_INT32
#    define OPND_CREATE_STATE OPND_CREATE_INT32
#    define OPND_CREATE_MEM_REF_NUM OPND_CREATE_INT32
#elif defined(ARM_CCTLIB)
#    define OPND_CREATE_BB_KEY OPND_CREATE_INT
#    define OPND_CREATE_SLOT OPND_CREATE_INT
#    define OPND_CREATE_STATE OPND_CREATE_INT
#    define OPND_CREATE_MEM_REF_NUM OPND_CREATE_INT
#endif

static void
insert_clean_call(int32_t new_key, int32_t num, int32_t end_state, int32_t memory_ref_num)
{
    dr_get_current_drcontext();
}

static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                bool for_trace, bool translating, void *user_data)
{
    instr_t *first_instr = instrlist_first_app(bb);
    if (instr_is_exclusive_store(first_instr)) {
        return DR_EMIT_DEFAULT;
    }

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                  bool translating, OUT void **user_data)
{
    instr_t *first_instr = instrlist_first_app(bb);
    if (instr_is_exclusive_store(first_instr)) {
        return DR_EMIT_DEFAULT;
    }
    dr_insert_clean_call(drcontext, bb, first_instr, (void *)insert_clean_call, false, 4,
                         OPND_CREATE_BB_KEY(0), OPND_CREATE_SLOT(0), OPND_CREATE_STATE(0),
                         OPND_CREATE_MEM_REF_NUM(0));
    for (instr_t *instr = first_instr; instr != NULL; instr = instr_get_next_app(instr)) {
        if (drreg_reserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
            DRCCTLIB_EXIT_PROCESS(
                "instrument_before_every_bb_first drreg_reserve_aflags != DRREG_SUCCESS");
        }
        if (drreg_unreserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
            DRCCTLIB_EXIT_PROCESS("instrument_before_every_bb_first "
                                  "drreg_unreserve_aflags != DRREG_SUCCESS");
        }
    }

    return DR_EMIT_DEFAULT;
}

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    drmgr_exit();
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_overhead_test'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "WARNING: drcctlib_overhead_test unable to initialize drmgr");
    }
    if (!drmgr_register_bb_instrumentation_event(event_bb_analysis, event_bb_insert,
                                                 NULL)) {
        DRCCTLIB_EXIT_PROCESS(
            "WARNING: drcctlib_overhead_test fail to register bb instrumentation event");
    }
    drreg_options_t ops = { sizeof(ops), 5, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("WARNING: drcctlib unable to initialize drreg");
    }
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif