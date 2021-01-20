/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_HPCVIEWER_FORMAT_H_
#define _DRCCTLIB_HPCVIEWER_FORMAT_H_

#include <cstdint>
#include <vector>

#include "dr_api.h"
#include "drcctlib_defines.h"
#include "drcctlib_utils.h"

using namespace std;

typedef struct _HPCRunCCT_t {
    vector<context_handle_t> ctxt_hndl_list;
    vector<uint64_t> metric_list;
} HPCRunCCT_t;

DR_EXPORT
void
hpcrun_format_init(const char *app_name, bool metric_cct);

DR_EXPORT
void
hpcrun_format_exit();

DR_EXPORT
int
hpcrun_create_metric(const char *name);

DR_EXPORT
int
write_thread_all_cct_hpcrun_format(void *drcontext);

DR_EXPORT
int
build_thread_custom_cct_hpurun_format(vector<HPCRunCCT_t *> &run_cct_list,
                                      void *drcontext);

DR_EXPORT
int
write_thread_custom_cct_hpurun_format(void *drcontext);

DR_EXPORT
int
build_progress_custom_cct_hpurun_format(vector<HPCRunCCT_t *> &run_cct_list);

DR_EXPORT
int
write_progress_custom_cct_hpurun_format();

#endif // _DRCCTLIB_HPCVIEWER_FORMAT_H_