/* 
 *  Copyright (c) 2020 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "dr_api.h"
#include "drcctlib.h"

#define DRCCTLIB_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("all_instr_cct_no_cache", format, ##args)
#define DRCCTLIB_EXIT_PROCESS(format, args...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("all_instr_cct_no_cache", format, ##args)

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
    dr_set_client_name("DynamoRIO Client 'drcctlib_all_instr_cct_no_cache'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    drcctlib_init_ex(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, NULL, NULL, NULL,
                     DRCCTLIB_DEFAULT);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif