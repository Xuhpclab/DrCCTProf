/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "drcctlib_filter_func_list.h"

bool
drcctlib_filter_0_instr(instr_t *instr)
{
    return false;
}

bool
drcctlib_filter_all_instr(instr_t *instr)
{
    return true;
}

bool
drcctlib_filter_mem_access_instr(instr_t *instr)
{
    return (instr_reads_memory(instr) || instr_writes_memory(instr));
}