/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drcctlib.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("all_instr_cct_with_data_centric", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...)                                       \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("all_instr_cct_with_data_centric", _FORMAT, \
                                          ##_ARGS)

static void
ClientInit(int argc, const char *argv[])
{
}

static void
ClientExit(void)
{
    drcctlib_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_all_instr_cct_with_data_centric'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL, NULL,
                     DRCCTLIB_CACHE_MODE | DRCCTLIB_COLLECT_DATA_CENTRIC_MESSAGE);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif