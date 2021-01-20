/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTPROF_ATTACH_H_
#define _DRCCTPROF_ATTACH_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT
bool
drcct_attach_inject_ptrace(pid_t pid, const char *appname, bool verbose_on);

DR_EXPORT
bool
drcct_detach_inject_ptrace(pid_t pid, bool verbose_on);

#endif /* _DR_INJECT_H_ */
