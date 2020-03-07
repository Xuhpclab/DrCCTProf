#ifndef _DRCCTLIB_GLOBAL_SHARE_H_
#define _DRCCTLIB_GLOBAL_SHARE_H_

#include <unistd.h>
#include "dr_api.h"

#ifdef X64
#    define drcctlib_key_t int64_t
#    define DRCCTLIB_KEY_MAX 9223372036854775807L
#    define ATOM_ADD_DRCCTLIB_KEY(origin, val) dr_atomic_add64_return_sum(&origin, val)
#    define OPND_CREATE_DRCCTLIB_KEY OPND_CREATE_INT64
#else
#    define drcctlib_key_t int32_t
#    define DRCCTLIB_KEY_MAX 2147483647L
#    define ATOM_ADD_DRCCTLIB_KEY(origin, val) dr_atomic_add32_return_sum(&origin, val)
#    define OPND_CREATE_DRCCTLIB_KEY OPND_CREATE_INT32
#endif

#endif //_DRCCTLIB_GLOBAL_SHARE_H_