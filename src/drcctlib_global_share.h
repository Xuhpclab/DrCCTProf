#ifndef _DRCCTLIB_GLOBAL_SHARE_H_
#define _DRCCTLIB_GLOBAL_SHARE_H_

#include "dr_api.h"

#ifdef X64
#    define CCTLIB_64
#else
#    define CCTLIB_32
#endif

#if defined(ARM) || defined(AARCH64)
#    define ARM_CCTLIB
#    ifdef ARM
#        define ARM32_CCTLIB
#    else
#        define ARM64_CCTLIB
#    endif
#else
#    define INTEL_CCTLIB
#endif

#ifdef ARM_CCTLIB
#   define IF_ARM_CCTLIB(value) value
#   define IF_ARM_CCTLIB_ELSE(value1, value2) value1
#else
#   define IF_ARM_CCTLIB(value)
#   define IF_ARM_CCTLIB_ELSE(value1, value2) value2
#endif

#ifdef ARM
#   define IF_ARM32_CCTLIB(value) value
#else
#   define IF_ARM32_CCTLIB(value) 
#endif


// #define DRCCTLIB_DEBUG
#ifdef DRCCTLIB_DEBUG
#   define IF_DRCCTLIB_DEBUG(value) value
#else
#   define IF_DRCCTLIB_DEBUG(value) 
#endif

#define USE_DATA_CENTRIC
#ifndef USE_DATA_CENTRIC
#    define DRCCTLIB_DATA_CENTRIC 0
#else
#    define DRCCTLIB_DATA_CENTRIC 1
#endif

#endif //_DRCCTLIB_GLOBAL_SHARE_H_