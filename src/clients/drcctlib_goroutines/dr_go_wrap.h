/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DR_GO_WRAP_H_
#define _DR_GO_WRAP_H_

#ifdef __cplusplus
extern "C" {
#endif

void *
dgw_get_go_func_arg(void *wrapcxt, int arg_no);

void *
dgw_get_go_func_retaddr(void *wrapcxt_opaque, int max, int ret);

#ifdef __cplusplus
}
#endif

#endif // _DR_GO_WRAP_H_