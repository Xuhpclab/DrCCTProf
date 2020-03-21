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
#else
#    define INTEL_CCTLIB
#endif

#endif //_DRCCTLIB_GLOBAL_SHARE_H_