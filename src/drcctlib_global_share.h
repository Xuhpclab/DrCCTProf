#ifndef _DRCCTLIB_GLOBAL_SHARE_H_
#define _DRCCTLIB_GLOBAL_SHARE_H_

// typedef app_pc drcctlib_key_t;
#ifdef X64
#define drcctlib_key_t int64
typedef int64_t drcctlib_key_t;
#    define DRCCTLIB_KEY_MAX 9223372036854775807L
#    define ATOM_DRCCTLIB_KEY_ADD(origin, val) dr_atomic_add64_return_sum(&origin, val)
#    define OPND_CREATE_DRCCTLIB_KEY OPND_CREATE_INT64
#else
#define drcctlib_key_t int
#    define DRCCTLIB_KEY_MAX 2147483647L
#    define ATOM_DRCCTLIB_KEY_ADD(origin, val) dr_atomic_add32_return_sum(&origin, val)
#    define OPND_CREATE_DRCCTLIB_KEY OPND_CREATE_INT32
#endif

#ifdef ARM
#    define DR_DISASM_DRCCTLIB DR_DISASM_ARM
#else
#    define DR_DISASM_DRCCTLIB DR_DISASM_INTEL
#endif

#define DISASM_CACHE_SIZE 80
#define MAXIMUM_SYMNAME 256

#endif //_DRCCTLIB_GLOBAL_SHARE_H_