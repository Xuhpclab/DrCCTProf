#ifndef _DRCCTLIB_DEFINE_H_
#define _DRCCTLIB_DEFINE_H_

#define CCTLIB_STR_PTHREAD_CREATE "pthread_create"
#define CCTLIB_STR_ARCH_LONGJMP "__longjmp"
#define CCTLIB_STR_SETJMP "_setjmp"
#define CCTLIB_STR_LONGJMP CCTLIB_STR_ARCH_LONGJMP
#define CCTLIB_STR_SIGSETJMP "sigsetjmp"
#define CCTLIB_STR_SIGLONGJMP CCTLIB_STR_ARCH_LONGJMP
#define CCTLIB_STR_UNWIND_SETIP "_Unwind_SetIP"
#define CCTLIB_STR_UNWIND_RAISEEXCEPTION "_Unwind_RaiseException"
#define CCTLIB_STR_UNWIND_RESUME "_Unwind_Resume"
#define CCTLIB_STR_UNWIND_FORCEUNWIND "_Unwind_ForcedUnwind"
#define CCTLIB_STR_UNWIND_RESUME_OR_RETHROW "_Unwind_Resume_or_Rethrow"
#define CCTLIB_STR_MALLOC_FN_NAME "malloc"
#define CCTLIB_STR_CALLOC_FN_NAME "calloc"
#define CCTLIB_STR_REALLOC_FN_NAME "realloc"
#define CCTLIB_STR_FREE_FN_NAME "free"

#define X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite) \
    (callsite - 5)
#define X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite) \
    (callsite - 2)

const int kMaxCCTPrintDepth = 20;
const int kMaxCCTPathDepth = 100;
const uint64_t kMaxIPNodesNum = 1L << 32;
const uint64_t kMaxStringPoolNodesNum = 1L << 32;

enum {
    CollectionMode,
    PostmorteMode 
};

enum CCTLibCallbackState{
    CCTLibInitCallback,
    CCTLibFiniCallback,
    CCTLibThreadStartCallback,
    CCTLibThreadEndCallback
};

enum CCTLibInsState { 
    UserInterestingIns = 0b0001,
    InstrIsCallDirect = 0b0010,
    InstrIsCallInDirect = 0b0100,
    InstrIsReturn = 0b1000
};

#endif // _DRCCTLIB_DEFINE_H_