/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_GO_WRAP_H_
#define _DRCCTLIB_GO_WRAP_H_

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT
void *
dgw_get_go_func_arg(void *wrapcxt, int arg);

#ifdef __cplusplus
}
#endif

#endif // _DRCCTLIB_GO_WRAP_H_