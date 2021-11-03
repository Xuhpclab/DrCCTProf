/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_FILETER_FUNC_LIST_H_
#define _DRCCTLIB_FILETER_FUNC_LIST_H_
#include "dr_api.h"

DR_EXPORT
bool
drcctlib_filter_0_instr(instr_t *instr);

DR_EXPORT
bool
drcctlib_filter_all_instr(instr_t *instr);

DR_EXPORT
bool
drcctlib_filter_mem_access_instr(instr_t *instr);

#define DRCCTLIB_FILTER_ZERO_INSTR drcctlib_filter_0_instr
#define DRCCTLIB_FILTER_ALL_INSTR drcctlib_filter_all_instr
#define DRCCTLIB_FILTER_MEM_ACCESS_INSTR drcctlib_filter_mem_access_instr

#endif // _DRCCTLIB_FILETER_FUNC_LIST_H_