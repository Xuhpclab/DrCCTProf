#include "drcctlib_if.h"


#ifdef __cplusplus
extern "C" {
#endif

_Unwind_Ptr c_use__Unwind_GetIP(struct _Unwind_Context * exception_caller_ctxt){
    return _Unwind_GetIP(exception_caller_ctxt);
}


#ifdef __cplusplus
}
#endif
