#ifndef _DRCCTLIB_IF_H_
#define _DRCCTLIB_IF_H_

#include <unwind.h>


#ifdef __cplusplus
extern "C" {
#endif

_Unwind_Ptr c_use__Unwind_GetIP(struct _Unwind_Context * exception_caller_ctxt);

#ifdef __cplusplus
}
#endif

#endif