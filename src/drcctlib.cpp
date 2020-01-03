#define __STDC_FORMAT_MACROS
#include <iostream>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>

#include "shadow_memory.h"
#include "drcctlib.h"


using namespace std;

 /** 
 * Normalize macro naming
 * CCTLIB_C_* : This macro represents a non-numeric constant;
 * CCTLIB_N_* : This macro represents a numeric type constant;
 * CCTLIB_S_* : This macro represents a string type constant;
 * CCTLIB_T_* : This macro stands for a nickname of a type;
 * CCTLIB_F_* : This macro represents a macro function.
**/
#ifndef __GNUC__
#pragma region MacroDefineRegion
#endif
#define CCTLIB_C_PTR_NULL nullptr
#define CCTLIB_C_DR_NULL NULL

#define CCTLIB_N_MAX_CCT_PRINT_DEPTH (20)
#define CCTLIB_N_MAX_CCT_PATH_DEPTH (100)
#define CCTLIB_N_MAX_FILE_PATH (200)
#define CCTLIB_N_CALL_INITIATED (0b1)
#define CCTLIB_N_STACK_PTR_STASHED (0b10)
#define CCTLIB_N_MAX_PATH_NAME (1024)
#define CCTLIB_N_MAX_IPNODES (1L << 32)
#define CCTLIB_N_MAX_STRING_POOL_NODES (1L << 32)
#define CCTLIB_N_CACHE_LINE_SIZE (128) // Assuming 128 byte line size.
#define CCTLIB_N_NOT_ROOT_CTX (-1)
#define CCTLIB_N_MAX_SYM_RESULT (256)

#define CCTLIB_S_MALLOC_FN_NAME "malloc"
#define CCTLIB_S_CALLOC_FN_NAME "calloc"
#define CCTLIB_S_REALLOC_FN_NAME "realloc"
#define CCTLIB_S_FREE_FN_NAME "free"
#define CCTLIB_S_CCTLIB_SERIALIZATION_DEFAULT_DIR_NAME "cctlib-database-"
#define CCTLIB_S_SERIALIZED_SHADOW_BB_IP_FILE_SUFFIX "/BBMap.bbShadowMap"
#define CCTLIB_S_SERIALIZED_CCT_FILE_PREFIX "/Thread-"
#define CCTLIB_S_SERIALIZED_CCT_FILE_EXTN ".cct"
#define CCTLIB_S_SERIALIZED_CCT_FILE_SUFFIX "-CCTMap.cct"

// Micro Func
#define CCTLIB_F_GET_CONTEXT_HANDLE_FROM_IP_NODE(node) \
    ((ContextHandle_t)((node) ? ((node) - GLOBAL_STATE.preAllocatedContextBuffer) : 0 ))
#define CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(handle) \
    (GLOBAL_STATE.preAllocatedContextBuffer + handle)
#define CCTLIB_F_IS_VALID_CONTEXT(c) \
    (c != 0)
#define CCTLIB_F_EXE_CALLBACK_FUNC(funcsStructPtr, funcName) \
    if ((funcsStructPtr != CCTLIB_C_PTR_NULL) &&             \
        (funcsStructPtr->funcName != CCTLIB_C_PTR_NULL)) {   \
        (funcsStructPtr->funcName)();                        \
    }
#define CCTLIB_F_SET_STACK_STATUS(v, flag) \
    (v = v | flag)
#define CCTLIB_F_UNSET_STACK_STATUS(v, flag) \
    (v = v & (~flag))
#define CCTLIB_F_RESET_STACK_STATUS(v) \
    (v = 0)
#define CCTLIB_F_IS_STACK_STATUS(v, flag) \
    (v & flag)
#define CCTLIB_F_X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite) \
    (callsite - 5)
#define CCTLIB_F_X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(callsite) \
    (callsite - 2)

#ifndef __GNUC__
#pragma endregion MacroDefineRegion
#endif

enum {
    INSERT = 0,
    DELETE = 1
};

#ifndef __GNUC__
#pragma region DataStructRegion
#endif
/**
* ref "2014 - Call paths for pin tools - Chabbi, Liu, Mellor-Crummey" figure 2,3,4
* A CCTLib BBNode logically represents a dynamorio basic block.(different with Pin CCTLib)
**/
struct BBNode {
    ContextHandle_t callerCtxtHndl;
    ContextHandle_t childCtxtStartIdx;
    uint32_t bbKey; // max of 2^32 basic blocks allowed
    uint32_t nSlots;
};
struct BBSplay {
    uint32_t key;
    BBNode *value;
    BBSplay *left;
    BBSplay *right;
};
struct IPNode {
    BBNode *parentBBNode;
    BBSplay *calleeBBNodes;
};
struct QNode {
    struct QNode* volatile next;
    union {
        struct {
            volatile bool locked: 1;
            volatile bool predecessorWasWriter: 1;
        };
        volatile uint8_t status;
    };
};
struct SerializedBBNode {
    uint32_t bbKey;
    uint32_t nSlots;
    ContextHandle_t  childCtxtStartIdx;
};
// Information about loaded images.
struct ModuleInfo {
    // name
    string moduleName;
    //Offset from the image's link-time address to its load-time address.
    uint32_t imgLoadOffset;
};
struct NormalizedIP{
    int lm_id;
    uint32_t offset;
};

// TLS(thread local storage)
struct ThreadData {
    uint32_t tlsThreadId;

    ContextHandle_t tlsCurrentCtxtHndl;
    ContextHandle_t tlsCurrentChildContextStartIndex;
    BBNode *tlsCurrentBBNode;

    ContextHandle_t tlsRootCtxtHndl;
    BBNode *tlsRootBBNode;
#ifdef CCTLIB_USE_STACK_STATUS
    uint32_t tlsStackStatus;
#else
    bool tlsInitiatedCall;
#endif

    ContextHandle_t tlsParentThreadCtxtHndl;
    BBNode* tlsParentThreadBBNode;

    unordered_map<uint32_t, IPNode*> tlsLongJmpMap;
    uint32_t tlsLongJmpHoldBuf;

    uint32_t tlsCurSlotNo;

    // The caller that can handle the current exception
    BBNode* tlsExceptionHandlerBBNode;
    ContextHandle_t tlsExceptionHandlerIPNode;
    void* tlsStackBase;
    void* tlsStackEnd;
    //DO_DATA_CENTRIC
    size_t tlsDynamicMemoryAllocationSize;
    ContextHandle_t tlsDynamicMemoryAllocationPathHandle;

} __attribute__((aligned));

// Global State
struct CCT_LIB_GLOBAL_STATE {
    // Should data-centric attribution be perfomed?
    bool doDataCentric; // false  by default

    // in dynamorio: the register funs don't have a start register; the callback_list_t don't have a start callback; 
    bool applicationStarted;

    uint8_t cctLibUsageMode;

    file_t CCTLibLogFile;

    CCTLibInstrumentInsCallback userInstrumentationCallback;
    void *userInstrumentationCallbackArg;

    char disassemblyBuff[200]; // string of 0 by default

    // prefix string for flushing all data for post processing.
    string CCTLibFilePathPrefix;

    IPNode *preAllocatedContextBuffer;
    uint32_t curPreAllocatedContextBufferIndex __attribute__((aligned(CCTLIB_N_CACHE_LINE_SIZE))); // align to eliminate any false sharing with other  members

    char* preAllocatedStringPool;
    uint32_t curPreAllocatedStringPoolIndex __attribute__((aligned(CCTLIB_N_CACHE_LINE_SIZE))); // align to eliminate any false sharing with other  members

    // SEGVHANDLEING FOR BAD .plt
    jmp_buf env;
    struct sigaction sigAct;
    //Load module info
    unordered_map<uint64_t, ModuleInfo> ModuleInfoMap;

    // serialization directory path
    string serializationDirectory;
    // Deserialized CCTs
    vector<ThreadData> deserializedCCTs;

    unordered_map<uint32_t, void*> bbShadowMap;

    void *lock;

    IsInterestingInsFptr isInterestingIns;

    unordered_map<uint64, vector<pair<app_pc, string>>> blockInterestInstrs;

    // key for accessing TLS storage in the threads. initialized once in main()
    /**
     * set tls field different with Pin
     * dynamorio: (drcontect, tlskey)->tdata;
     * pin: (threadid, tlskey)->tdata
     **/
    TLS_KEY CCTLibTlsKey __attribute__((aligned(
        CCTLIB_N_CACHE_LINE_SIZE))); // align to eliminate any false sharing with other  members
    // initial value = 0
    uint32_t numThreads __attribute__((aligned(
        CCTLIB_N_CACHE_LINE_SIZE))); // align to eliminate any false sharing with other  members
    unordered_map<uint32_t, ThreadData *> threadDataMap;
    // keys to associate parent child threads
    volatile uint64_t threadCreateCount __attribute__((aligned(CCTLIB_N_CACHE_LINE_SIZE))) ; // initial value = 0  // align to eliminate any false sharing with other  members
    volatile uint64_t threadCaptureCount __attribute__((aligned(CCTLIB_N_CACHE_LINE_SIZE))) ; // initial value = 0  // align to eliminate any false sharing with other  members
    volatile BBNode* threadCreatorBBNode __attribute__((aligned(CCTLIB_N_CACHE_LINE_SIZE)));  // align to eliminate any false sharing with other  members
    volatile ContextHandle_t threadCreatorCtxtHndl __attribute__((aligned(CCTLIB_N_CACHE_LINE_SIZE)));  // align to eliminate any false sharing with other  members
    volatile bool DSLock;
    
    CCTLibCallbackFuncsPtr_t callbackFuncs;
};

#ifndef __GNUC__
#pragma endregion DataStructRegion
#endif
// thread shared global veriables
static CCT_LIB_GLOBAL_STATE GLOBAL_STATE;
static ConcurrentShadowMemory<DataHandle_t> sm;

#ifndef __GNUC__
#pragma region PrivateFunctionRegion
#endif
// function to get the next unique key for a basic block
static uint32_t
GetNextBBKey()
{
    static uint32_t bbKey = 0;
    uint32_t key = __sync_fetch_and_add(&bbKey, 1);

    if (key == UINT_MAX) {
        cerr<<"UINT_MAX basic blocks created! Exiting..."<<endl;
        dr_exit_process(-1);
    }

    return key;
}

// function to access thread-specific data
static inline ThreadData *
CCTLibGetTLS(void *drcontext)
{
    ThreadData *tdata = static_cast<ThreadData *>(
        drmgr_get_tls_field(drcontext, GLOBAL_STATE.CCTLibTlsKey));
    return tdata;
}

static inline ThreadData *
CCTLibGetTLS(uint32_t threadIndex)
{
    ThreadData *tdata = GLOBAL_STATE.threadDataMap[threadIndex];
    return tdata;
}

static inline void
UpdateCurBBAndIp(ThreadData *tData, BBNode *const bbNode,
                        ContextHandle_t const ctxtHndle)
{
    tData->tlsCurrentBBNode = bbNode;
    tData->tlsCurrentChildContextStartIndex = bbNode->childCtxtStartIdx;
    tData->tlsCurrentCtxtHndl = ctxtHndle;
}

static inline void
UpdateCurBBAndIp(ThreadData *tData, BBNode *const bbNode)
{
    UpdateCurBBAndIp(tData, bbNode, bbNode->childCtxtStartIdx);
}

static inline void
UpdateCurBBOnly(ThreadData *tData, BBNode *const bbNode)
{
    tData->tlsCurrentBBNode = bbNode;
    tData->tlsCurrentChildContextStartIndex = bbNode->childCtxtStartIdx;
}

#if 0
    // This function is for dumping call path from debugger.
    static void
    DumpCallStack(void *drcontext, uint32_t slot)
    {
        ThreadData *tData = CCTLibGetTLS(drcontext);
        fprintf(stderr, "\n slot =%u, max = %u\n", slot,
                tData->tlsCurrentBBNode->nSlots);
        dr_mutex_lock(GLOBAL_STATE.lock);
        ContextHandle_t h = tData->tlsCurrentBBNode->childCtxtStartIdx + slot;
        fprintf(stderr, "\n");
        vector<Context> contextVec;
        GetFullCallingContext(h, contextVec);

        for (uint32_t i = 0; i < contextVec.size(); i++) {
            fprintf(stderr, "\n%u:%p:%s:%s:%s:%u", contextVec[i].ctxtHandle,
                    (void *)contextVec[i].ip, contextVec[i].disassembly.c_str(),
                    contextVec[i].functionName.c_str(), contextVec[i].filePath.c_str(),
                    contextVec[i].lineNo);
        }
        dr_mutex_unlock(GLOBAL_STATE.lock);
    }

    // This function is for dumping call path from debugger.
    static void
    DumpCallStackEasy()
    {
        DumpCallStack(dr_get_current_drcontext(), 0);
    }
#endif

#if 0
    static inline void
    CaptureSigSetJmpCtxt(void *drcontext, uint32_t buf)
    {
        ThreadData *tData = CCTLibGetTLS(drcontext);
        // Does not work when a bb has zero IPs!! tData->tlsLongJmpMap[buf] = tData->tlsCurrentIPNode->parentBBNode->callerIPNode;
        tData->tlsLongJmpMap[buf] = tData->tlsCurrentBBNode->callerCtxtHndl;
        // dr_fprintf(GLOBAL_STATE.CCTLibLogFile,"\n CaptureSetJmpCtxt buf = %lu, tData->tlsCurrentIPNode = %p", buf, tData->tlsCurrentIPNode);
    }

    static inline void
    HoldLongJmpBuf(void *drcontext, uint32_t buf)
    {
        ThreadData *tData = CCTLibGetTLS(drcontext);
        tData->tlsLongJmpHoldBuf = buf;
        // dr_fprintf(GLOBAL_STATE.CCTLibLogFile,"\n HoldLongJmpBuf tlsLongJmpHoldBuf = %lu, tData->tlsCurrentIPNode = %p", tData->tlsLongJmpHoldBuf, tData->tlsCurrentIPNode);
    }

    static inline void
    RestoreSigLongJmpCtxt(void *drcontext)
    {
        ThreadData *tData = CCTLibGetTLS(drcontext);
        assert(tData->tlsLongJmpHoldBuf);
        tData->tlsCurrentIPNode = tData->tlsLongJmpMap[tData->tlsLongJmpHoldBuf];
        UpdateCurBBOnly(tData, CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->parentBBNode);
        tData->tlsLongJmpHoldBuf =0; // reset so that next time we can check if it was set correctly.
        // dr_fprintf(GLOBAL_STATE.CCTLibLogFile,"\n RestoreSigLongJmpCtxt2 tlsLongJmpHoldBuf = %lu",tData->tlsLongJmpHoldBuf);
    }
#endif

#if 0
    static int
    IsARootIPNode(ContextHandle_t curCtxtHndle)
    {
        // if it is running monitoring we will use CCTLibGetTLS
        if (GLOBAL_STATE.cctLibUsageMode == CCT_LIB_MODE_COLLECTION) {
            for (uint32_t index = 0; index < GLOBAL_STATE.numThreads; index++) {
                ThreadData *tData = GLOBAL_STATE.threadDataMap[index];

                if (tData->tlsRootCtxtHndl == curCtxtHndle)
                    return index;
            }
        } else {
            for (uint32_t id = 0; id < GLOBAL_STATE.numThreads; id++) {
                if (GLOBAL_STATE.deserializedCCTs[id].tlsRootCtxtHndl == curCtxtHndle)
                    return id;
            }
        }

        return CCTLIB_N_NOT_ROOT_CTX;
    }
#endif

#if 0
    static int //unfinish
    GetInstructionLength(uint32_t ip)
    {
        // Get the instruction in a string
        _decoded_inst_t xedd;
        /// XED state
        xed_decoded_inst_zero_set_mode(&xedd, &GLOBAL_STATE.cct_xed_state);

        if (XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t *)(ip), 15)) {
            return xed_decoded_inst_get_length(&xedd);
        } else {
            assert(0 && "failed to disassemble instruction");
            return 0;
        }
    }

    static void //unfinish
    GetNormalizedIpVectorClippedToMainOneAheadIp(vector<NormalizedIP> &ctxt,
                                                ContextHandle_t curCtxtHndle)
    {
        int depth = 0;
        // Dont print if the depth is more than CCTLIB_N_MAX_CCT_PRINT_DEPTH since files become too large
        while (CCTLIB_F_IS_VALID_CONTEXT(curCtxtHndle) && (depth++ < CCTLIB_N_MAX_CCT_PRINT_DEPTH)) {
            int threadCtx = 0;
            if ((threadCtx = IsARootIPNode(curCtxtHndle)) != CCTLIB_N_NOT_ROOT_CTX) {
                // if the thread has a parent, recur over it.
                ContextHandle_t parentThreadCtxtHndl =
                    CCTLibGetTLS(threadCtx)->tlsParentThreadCtxtHndl;
                if (parentThreadCtxtHndl) {
                    fprintf(stderr,
                            "\n Multi threading not supported for this prototype feature. "
                            "Exiting\n");
                    dr_exit_process(-1);
                }
                break;
            } else {
                BBNode *bbNode =
                    CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(curCtxtHndle)->parentBBNode;
                // what is my slot id ?
                uint32_t slotNo = curCtxtHndle - bbNode->childCtxtStartIdx;

                uint32_t *ptr = (uint32_t *)GLOBAL_STATE.bbShadowMap[bbNode->bbKey];
                UINT32 moduleId = ptr[-1]; // module id is stored one behind.
                uint32_t ip = ptr[slotNo];
                ip += GetInstructionLength(ip);
                NormalizedIP nip;
                nip.lm_id = moduleId;
                nip.offset = ip - GLOBAL_STATE.ModuleInfoMap[moduleId].imgLoadOffset;
                ctxt.push_back(nip);

                // if we are already in main, we are done
                RTN r = RTN_FindByAddress(ip);
                if (RTN_Invalid() != r && RTN_Name(r) == "main")
                    return;
            }
            curCtxtHndle =
                CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(curCtxtHndle)->parentBBNode->callerCtxtHndl;
        }
    }

    void //unfinish
    LogContexts(iostream &ios, ContextHandle_t ctxt1, ContextHandle_t ctxt2)
    {
        vector<NormalizedIP> c1;
        vector<NormalizedIP> c2;
        GetNormalizedIpVectorClippedToMainOneAheadIp(c1, ctxt1);
        GetNormalizedIpVectorClippedToMainOneAheadIp(c2, ctxt2);
        for (uint32_t i = 0; i < c1.size(); i++)
            ios << c1[i].lm_id << "-" << (void *)c1[i].offset << ",";
        ios << "SEP";
        for (uint32_t i = 0; i < c2.size(); i++)
            ios << "," << c2[i].lm_id << "-" << (void *)c2[i].offset;
    }

    static bool //unfinish
    IsCallInstruction(uint32_t ip)
    {
        // Get the instruction in a string
        xed_decoded_inst_t xedd;
        /// XED state
        xed_decoded_inst_zero_set_mode(&xedd, &GLOBAL_STATE.cct_xed_state);

        if (XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t *)(ip), 15)) {
            if (XED_CATEGORY_CALL == xed_decoded_inst_get_category(&xedd))
                return true;
            else
                return false;
        } else {
            assert(0 && "failed to disassemble instruction");
            return false;
        }
    }

    bool //unfinish
    IsIpPresentInBB(uint32_t exceptionCallerReturnAddrIP, BBNode *bbNode,
                    uint32_t *ipSlot)
    {
        uint32_t *bbsIPs = (uint32_t *)GLOBAL_STATE.bbShadowMap[bbNode->bbKey];
        uint32_t ipDirectCall =
            CCTLIB_F_X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(exceptionCallerReturnAddrIP);
        uint32_t ipIndirectCall =
            CCTLIB_F_X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(exceptionCallerReturnAddrIP);

        for (uint32_t i = 0; i < bbNode->nSlots; i++) {
            // printf("\n serching = %p", bbsIPs[i]);
            if ((bbsIPs[i] == ipDirectCall) && IsCallInstruction(ipDirectCall)) {
                *ipSlot = i;
                return true;
            }

            if ((bbsIPs[i] == ipIndirectCall) && IsCallInstruction(ipIndirectCall)) {
                *ipSlot = i;
                return true;
            }
        }

        return false;
    }

    static BBNode * //unfinish
    FindNearestCallerCoveringIP(uint32_t exceptionCallerReturnAddrIP, uint32_t *ipSlot,
                                ThreadData *tData)
    {
        BBNode *curBB = tData->tlsCurrentBBNode;

        // int i = 0;
        while (curBB) {
            if (IsIpPresentInBB(exceptionCallerReturnAddrIP, curBB, ipSlot)) {
                // printf("\n found at %d", i++);
                return curBB;
            }

            // break if we have finished looking at the root
            if (curBB == tData->tlsRootBBNode)
                break;

            curBB = GLOBAL_STATE.preAllocatedContextBuffer[curBB->callerCtxtHndl]
                        .parentBBNode;
            // printf("\n did not find so far %d", i++);
        }

        printf("\n This is a terrible place to be in.. report to mc29@rice.edu\n");
        assert(0 && " Should never reach here");
        dr_exit_process(-1);
        return NULL;
    }

    static void //unfinish
    CaptureCallerThatCanHandleException(void *exceptionCallerContext, THREADID threadId)
    {
        // printf("\n Target ip is %p, exceptionCallerIP = %p", targeIp);
        //        extern uint32_t _Unwind_GetIP(void *);
        //        uint32_t exceptionCallerIP = (uint32_t) _Unwind_GetIP(exceptionCallerContext);
        _Unwind_Ptr exceptionCallerReturnAddrIP =
            _Unwind_GetIP((struct _Unwind_Context *)exceptionCallerContext);
        _Unwind_Ptr directExceptionCallerIP =
            CCTLIB_F_X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(exceptionCallerReturnAddrIP);
        _Unwind_Ptr indirectExceptionCallerIP =
            CCTLIB_F_X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(exceptionCallerReturnAddrIP);
        // printf("\n directExceptionCallerIP = %p indirectExceptionCallerIP = %p",
        // (void*)directExceptionCallerIP, (void*)indirectExceptionCallerIP);
        fprintf(GLOBAL_STATE.CCTLibLogFile,
                "\n directExceptionCallerIP = %p indirectExceptionCallerIP = %p",
                (void *)directExceptionCallerIP, (void *)indirectExceptionCallerIP);
        // Walk the CCT chain staring from tData->tlsCurrentBBNode looking for the nearest
        // one that has targeIp in the range.
        ThreadData *tData = CCTLibGetTLS(threadId);
        // Record the caller that can handle the exception.
        uint32_t ipSlot;
        tData->tlsExceptionHandlerBBNode =
            FindNearestCallerCoveringIP(exceptionCallerReturnAddrIP, &ipSlot, tData);
        tData->tlsExceptionHandlerCtxtHndle =
            tData->tlsExceptionHandlerBBNode->childCtxtStartIdx + ipSlot;
    }

    static void //unfinish
    SetCurBBNodeAfterException(THREADID threadId)
    {
        ThreadData *tData = CCTLibGetTLS(threadId);
        // Record the caller that can handle the exception.
        UpdateCurBBAndIp(tData, tData->tlsExceptionHandlerBBNode,
                            tData->tlsExceptionHandlerCtxtHndle);
        
        dr_fprintf(GLOBAL_STATE.CCTLibLogFile,
                "\n reset tData->tlsCurrentBBNode to the handler");
    }

    static void //unfinish
    SetCurBBNodeAfterExceptionIfContextIsInstalled(uint32_t retVal, THREADID threadId)
    {
        // if the return value is _URC_INSTALL_CONTEXT then we will reset the shadow stack,
        // else NOP Commented ... caller ensures it is inserted only at the end. if(retVal !=
        // _URC_INSTALL_CONTEXT)
        //    return;
        ThreadData *tData = CCTLibGetTLS(threadId);
        // Record the caller that can handle the exception.
        UpdateCurBBAndIp(tData, tData->tlsExceptionHandlerBBNode,
                            tData->tlsExceptionHandlerCtxtHndle);
        
        dr_fprintf(GLOBAL_STATE.CCTLibLogFile,
                "\n (SetCurBBNodeAfterExceptionIfContextIsInstalled) reset "
                "tData->tlsCurrentBBNode to the handler");
    }
#endif

static inline void TakeLock() {
    do {
        while(GLOBAL_STATE.DSLock);
    } while(!__sync_bool_compare_and_swap(&GLOBAL_STATE.DSLock, 0, 1));
}

static inline void ReleaseLock() {
    GLOBAL_STATE.DSLock = 0;
}

// Pauses creator thread from thread creation until the previously created child thread has noted its parent.
static inline void
ThreadCreatePoint(uint32_t threadIdex)
{
    while (1) {
        TakeLock();

        if (GLOBAL_STATE.threadCreateCount > GLOBAL_STATE.threadCaptureCount)
            ReleaseLock();
        else
            break;
    }

    GLOBAL_STATE.threadCreatorBBNode = CCTLibGetTLS(threadIdex)->tlsCurrentBBNode;
    GLOBAL_STATE.threadCreatorCtxtHndl = CCTLibGetTLS(threadIdex)->tlsCurrentCtxtHndl;

    GLOBAL_STATE.threadCreateCount++;
    ReleaseLock();
}

// Sets the child thread's CCT's parent to its creator thread's CCT node.
static inline void
ThreadCapturePoint(ThreadData *tdata)
{
    TakeLock();
    if (GLOBAL_STATE.threadCreateCount == GLOBAL_STATE.threadCaptureCount) {
        // Base thread, no parent
        // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n ThreadCapturePoint, no parent ");
    } else {
        // This will be always 0 for flat profiles
        tdata->tlsParentThreadBBNode =
            (BBNode *)GLOBAL_STATE.threadCreatorBBNode;
        tdata->tlsParentThreadCtxtHndl = GLOBAL_STATE.threadCreatorCtxtHndl;
        // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n ThreadCapturePoint, parent BB = %p,
        // parent ip = %p", GLOBAL_STATE.threadCreatorBBNode,
        // GLOBAL_STATE.threadCreatorCtxtHndl);
        GLOBAL_STATE.threadCaptureCount++;
    }
    ReleaseLock();
}

static inline ContextHandle_t
GetNextIPVecBuffer(uint32_t num)
{
    // Multithreaded compatible
    // ensure (oldBufIndex = GLOBAL_STATE.curPreAllocatedContextBufferIndex)
    // GLOBAL_STATE.curPreAllocatedContextBufferIndex = next pre allocated
    uint32_t oldBufIndex =
        __sync_fetch_and_add(&GLOBAL_STATE.curPreAllocatedContextBufferIndex, num);

    if (oldBufIndex + num >= CCTLIB_N_MAX_IPNODES) {
        dr_fprintf(
            GLOBAL_STATE.CCTLibLogFile,
            "\nPreallocated IPNodes exhausted. CCTLib couldn't fit your application "
            "in its memory. Try a smaller program.\n");
        dr_exit_process(-1);
    }

    return (ContextHandle_t)oldBufIndex;
}

/*
    Description:
            Client tools call this API when they need the char string for a symbol from string pool index.
    Arguments:
            index: a string pool index 
*/
#if 0
    static char *
    GetStringFromStringPool(const uint32_t index)
    {
        return GLOBAL_STATE.preAllocatedStringPool + index;
    }

    static inline uint32_t __attribute__((__unused__)) GetNextStringPoolIndex(char *name)
    {
        uint32_t len = strlen(name) + 1;
        uint64_t oldStringPoolIndex =
            __sync_fetch_and_add(&GLOBAL_STATE.curPreAllocatedStringPoolIndex, len);

        if (oldStringPoolIndex + len >= CCTLIB_N_MAX_STRING_POOL_NODES) {
            dr_fprintf(
                GLOBAL_STATE.CCTLibLogFile,
                "\nPreallocated String Pool exhausted. CCTLib couldn't fit your application "
                "in its memory. Try by changing CCTLIB_N_MAX_STRING_POOL_NODES macro.\n");
            dr_exit_process(-1);
        }

        // copy contents
        strncpy(GLOBAL_STATE.preAllocatedStringPool + oldStringPoolIndex, name, len);
        return oldStringPoolIndex;
    }
#endif

static inline void
CCTLibInitThreadData(void *drcontext, ThreadData *const tdata, uint32_t threadId)
{
    BBNode *bbNode = new BBNode();
    bbNode->callerCtxtHndl = 0;
    bbNode->nSlots = 1;
    bbNode->childCtxtStartIdx = GetNextIPVecBuffer(1);
    IPNode *ipNode = CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(bbNode->childCtxtStartIdx);
    ipNode->parentBBNode = bbNode;
    ipNode->calleeBBNodes = CCTLIB_C_PTR_NULL;

    tdata->tlsThreadId = threadId;
    tdata->tlsRootBBNode = bbNode;
    tdata->tlsRootCtxtHndl = bbNode->childCtxtStartIdx;
    UpdateCurBBAndIp(tdata, bbNode);
    tdata->tlsParentThreadCtxtHndl = 0;
    tdata->tlsParentThreadBBNode = CCTLIB_C_PTR_NULL;
#ifdef CCTLIB_USE_STACK_STATUS
    CCTLIB_F_RESET_STACK_STATUS(tdata->tlsStackStatus);
    CCTLIB_F_SET_STACK_STATUS(tdata->tlsStackStatus, CCTLIB_N_CALL_INITIATED);
#else
    tdata->tlsInitiatedCall = true;
#endif
    tdata->tlsCurSlotNo = 0;
#if 0
    // Set stack sizes if data-centric is needed
    if(GLOBAL_STATE.doDataCentric) {
        dr_save_reg();
        uint32_t s =  PIN_GetContextReg(ctxt, REG_STACK_PTR);
        tdata->tlsStackBase = (void*) s;
        struct rlimit rlim;

        if(getrlimit(RLIMIT_STACK, &rlim)) {
            cerr << "\n Failed to getrlimit()\n";
            dr_exit_process(-1);
        }

        if(rlim.rlim_cur == RLIM_INFINITY) {
            cerr << "\n Need a finite stack size. Dont use unlimited.\n";
            dr_exit_process(-1);
        }

        tdata->tlsStackEnd = (void*)(s - rlim.rlim_cur);
    }
#endif
}

static void
CCTLibThreadStart(void *drcontext)
{
    uint32_t threadId = -1; 
    dr_mutex_lock(GLOBAL_STATE.lock);
    threadId = GLOBAL_STATE.numThreads;
    GLOBAL_STATE.numThreads++;
    dr_mutex_unlock(GLOBAL_STATE.lock);

    void* tdata = dr_thread_alloc(drcontext, sizeof(ThreadData));
    DR_ASSERT(tdata != CCTLIB_C_DR_NULL);

    CCTLibInitThreadData(drcontext, (ThreadData *)tdata, threadId);
    GLOBAL_STATE.threadDataMap[threadId] = (ThreadData *)tdata;
    drmgr_set_tls_field(drcontext, GLOBAL_STATE.CCTLibTlsKey, tdata);
    ThreadCapturePoint((ThreadData *)tdata);

    CCTLIB_F_EXE_CALLBACK_FUNC(GLOBAL_STATE.callbackFuncs, threadStartFunc)
}

static void
CCTLibThreadEnd(void *drcontext)
{
    CCTLIB_F_EXE_CALLBACK_FUNC(GLOBAL_STATE.callbackFuncs, threadEndFunc)
    ThreadData *tData =
        (ThreadData *)drmgr_get_tls_field(drcontext, GLOBAL_STATE.CCTLibTlsKey);

    dr_thread_free(drcontext, tData, sizeof(ThreadData));
}

static void
AtCall(uint slot)
{
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          GLOBAL_STATE.CCTLibTlsKey);
#ifdef CCTLIB_USE_STACK_STATUS
    CCTLIB_F_SET_STACK_STATUS(tData->tlsStackStatus, CCTLIB_N_CALL_INITIATED);
#else
    tData->tlsInitiatedCall = true;
#endif
    tData->tlsCurrentCtxtHndl = tData->tlsCurrentBBNode->childCtxtStartIdx + slot;
}

static void
AtReturn()
{
    // cerr<<"atreturn"<<endl;
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          GLOBAL_STATE.CCTLibTlsKey);
    // If we reach the root trace, then fake the call
    if(tData->tlsCurrentBBNode->callerCtxtHndl == tData->tlsRootCtxtHndl) {
#ifdef CCTLIB_USE_STACK_STATUS
        CCTLIB_F_SET_STACK_STATUS(tData->tlsStackStatus, CALL_INITIATED);
#else
        tData->tlsInitiatedCall = true;
#endif
    }
    tData->tlsCurrentCtxtHndl = tData->tlsCurrentBBNode->callerCtxtHndl;
    UpdateCurBBOnly(tData, CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl)->parentBBNode);
}

static void
RememberSlotNoInTLS(uint slot)
{
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          GLOBAL_STATE.CCTLibTlsKey);
    tData->tlsCurSlotNo = slot;
}

static inline bool
IsCallOrRetIns(instr_t *ins)
{
    if (instr_is_call_direct(ins) || instr_is_call_indirect(ins) ||
        instr_is_return(ins)) {
        return true;
    }
    return false;
}

static inline uint32_t
GetNumInterestingInsInBB(instrlist_t *bb)
{
    uint32_t count = 0;
    instr_t *start = instrlist_first_app(bb);
    for (instr_t *ins = start; ins != CCTLIB_C_DR_NULL; ins = instr_get_next_app(ins)) {

        if (IsCallOrRetIns(ins) || GLOBAL_STATE.isInterestingIns(ins)) {
            count++;
        }
    }
    return count;
}


static BBSplay *
UpdateSplayTree(BBSplay *root, uint32_t newKey)
{
    if (root != CCTLIB_C_PTR_NULL) {
        BBSplay* dummyNode = new BBSplay();
        BBSplay *ltreeMaxNode, *rtreeMinNode, *tempNode;
        ltreeMaxNode = rtreeMinNode = dummyNode;
        while (newKey != root->key) {
            if (newKey < root->key) {
                if (root->left == CCTLIB_C_PTR_NULL){
                    BBSplay* newRoot = new BBSplay();
                    newRoot->key = newKey;
                    root->left = newRoot;
                }
                if (newKey < root->left->key) {
                    tempNode = root->left;
                    root->left = tempNode->right;
                    tempNode->right = root;
                    root = tempNode;
                    if(root->left == CCTLIB_C_PTR_NULL) {
                        BBSplay* newRoot = new BBSplay();
                        newRoot->key = newKey;
                        root->left = newRoot;
                    }
                }
                rtreeMinNode->left = root;
                rtreeMinNode = root;
                root = root->left;
            } else if (newKey > root->key) {
                if (root->right == CCTLIB_C_PTR_NULL){
                    BBSplay* newRoot = new BBSplay();
                    newRoot->key = newKey;
                    root->right = newRoot;
                }
                if (newKey > root->right ->key) {
                    tempNode = root->right;
                    root->right = tempNode->left;
                    tempNode->left = root;
                    root = tempNode;
                    if (root->right == CCTLIB_C_PTR_NULL){
                        BBSplay* newRoot = new BBSplay();
                        newRoot->key = newKey;
                        root->right = newRoot;
                    }
                }
                ltreeMaxNode->right = root;
                ltreeMaxNode = root;
                root = root->right;
            }
        }
        ltreeMaxNode->right = root->left;
        rtreeMinNode->left = root->right;
        root->left = dummyNode->right;
        root->right = dummyNode->left;
    } else {
        BBSplay* newRoot = new BBSplay();
        newRoot->key = newKey;
        root = newRoot;
    }
    return root;
}

static void
AtBBEntry(uint newKey, uint numInstrs)
{
    
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          GLOBAL_STATE.CCTLibTlsKey);
#ifdef CCTLIB_USE_STACK_STATUS
    // If the stack pointer is stashed, reset the tlsCurrentBbNode to the root
    if(CCTLIB_F_IS_STACK_STATUS(tData->tlsStackStatus, CCTLIB_N_STACK_PTR_STASHED)) {
        tData->tlsCurrentCtxtHndl = tData->tlsRootCtxtHndl;
    } else if(!CCTLIB_F_IS_STACK_STATUS(tData->tlsStackStatus, CCTLIB_N_CALL_INITIATED)) {
        // if landed here w/o a call instruction, then let's make this bb a sibling.
        // The trick to do it is to go to the parent BbNode and make this bb a child of it
        tData->tlsCurrentCtxtHndl = tData->tlsCurrentBbNode->callerCtxtHndl;
    } else {
        // tlsCurrentCtxtHndl must be pointing to the call IP in the parent bb
    }
    CCTLIB_F_RESET_STACK_STATUS(tData->tlsStackStatus);
#else
    if(!tData->tlsInitiatedCall) {
        tData->tlsCurrentCtxtHndl = tData->tlsCurrentBBNode->callerCtxtHndl;
    } else {
        tData->tlsInitiatedCall = false;
    }
#endif

    IPNode *curParent = CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(tData->tlsCurrentCtxtHndl);
    BBSplay *newTreeRoot = UpdateSplayTree(curParent->calleeBBNodes, newKey);
    BBNode *treeRootBBNode = newTreeRoot->value;
    if(treeRootBBNode == CCTLIB_C_PTR_NULL){
        treeRootBBNode = new BBNode();
        treeRootBBNode->callerCtxtHndl = tData->tlsCurrentCtxtHndl;
        treeRootBBNode->bbKey = (uint32_t)newKey;
        if (numInstrs) {
            treeRootBBNode->childCtxtStartIdx = GetNextIPVecBuffer(numInstrs);
            treeRootBBNode->nSlots = numInstrs;
            IPNode *child = CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(treeRootBBNode->childCtxtStartIdx);
            for (uint i = 0; i < numInstrs; ++i) {
                child[i].parentBBNode = treeRootBBNode;
                child[i].calleeBBNodes = CCTLIB_C_PTR_NULL;
            }
        } else {
            treeRootBBNode->childCtxtStartIdx = 0;
            treeRootBBNode->nSlots = 0;
        }
    }
    curParent->calleeBBNodes = newTreeRoot;
    UpdateCurBBAndIp(tData, treeRootBBNode);
}

#ifdef CCTLIB_USE_STACK_STATUS
    static inline void
    SetCallStackPtrStashFlag()
    {
        ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                            GLOBAL_STATE.CCTLibTlsKey);
        CCTLIB_F_SET_STACK_STATUS(tData->tlsStackStatus, CCTLIB_N_STACK_PTR_STASHED);
    }

    static bool
    TrashesStackPtr(instr_t *instr)
    {
        // stack ptr is modified
        int numDsts = instr_num_dsts(instr);
        for (int i = 0; i < numDsts; i++) {
            opnd_t opnd= instr_get_dst(instr, numDsts);
            if (opnd_is_reg(opnd)) {
                if ((opnd_get_reg(opnd) == DR_REG_ESP) ||
                    (opnd_get_reg(opnd) == REG_RSP)) {
                    // need to write code to achieve the same function as INS_OperandIsImplicit
                    // if (INS_OperandIsImplicit(ins, i) == false) {
                        return true;
                    // }
                }
            }
        }
        return false;
    }
#endif
static void
PrintAddress(app_pc addr, string code)
{
    drsym_error_t symres;
    drsym_info_t sym;
    char name[CCTLIB_N_MAX_SYM_RESULT];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == CCTLIB_C_DR_NULL) {
        dr_fprintf(GLOBAL_STATE.CCTLibLogFile, " " PFX " ? ??:0\n", addr);
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = CCTLIB_N_MAX_SYM_RESULT;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        const char *modname = dr_module_preferred_name(data);
        if (modname == CCTLIB_C_DR_NULL)
            modname = "<noname>";
        dr_fprintf(GLOBAL_STATE.CCTLibLogFile, " " PFX ":%s, %s!%s+" PIFX, addr,
                   code.c_str(), modname, sym.name, addr - data->start - sym.start_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            dr_fprintf(GLOBAL_STATE.CCTLibLogFile, " ??:0\n");
        } else {
            dr_fprintf(GLOBAL_STATE.CCTLibLogFile,
                       " %s:%" UINT64_FORMAT_CODE "+" PIFX "\n", sym.file, sym.line,
                       sym.line_offs);
        }
    } else
        dr_fprintf(GLOBAL_STATE.CCTLibLogFile, " " PFX " ? ??:0\n", addr);
    dr_free_module_data(data);
}

static void
PopulateIPReverseMapAndAccountBbInstructions(void *drcontext, instrlist_t *bb, instr_t *start, uint32_t bbKey,
                                             uint32_t numInterestingInstInBb)
{
    // +1 to hold the number of slots as a metadata and ++1 to hold module id
    uint64_t *ipShadow = (uint64_t *)malloc((2 + numInterestingInstInBb) * sizeof(uint64_t));

    // Record the number of instructions in the bb as the first entry
    ipShadow[0] = numInterestingInstInBb;
    // Record the module id as 2nd entry
    // ipShadow[1] = IMG_Id(IMG_FindByAddress(TRACE_Address(bb)));
    uint32_t slot = 0;
    GLOBAL_STATE.bbShadowMap[bbKey] = &ipShadow[2]; // 0th entry is 2 behind

    for (instr_t *instr = start; instr != CCTLIB_C_DR_NULL; instr = instr_get_next_app(instr)) {
        if (IsCallOrRetIns(instr) || GLOBAL_STATE.isInterestingIns(instr)) {

            app_pc curPc = instr_get_app_pc(instr);
            char disassem[80];
            instr_disassemble_to_buffer(dr_get_current_drcontext(), instr, disassem, 80);
            string code(disassem);
            GLOBAL_STATE.blockInterestInstrs[bbKey].push_back({ curPc, code });

            dr_insert_clean_call(drcontext, bb, instr, (void *)RememberSlotNoInTLS, false, 1,
                                 OPND_CREATE_INT32(slot));
        }
        if (instr_is_call_direct(instr)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)AtCall, false, 1,
                                 OPND_CREATE_INT32(slot));
            if (GLOBAL_STATE.userInstrumentationCallback) {
                if(GLOBAL_STATE.isInterestingIns(instr)){
                    GLOBAL_STATE.userInstrumentationCallback(
                    drcontext, bb, instr, GLOBAL_STATE.userInstrumentationCallbackArg,
                    slot);
                }
            }
            ipShadow[slot + 2] = (uint64_t)(ptr_int_t)instr;
            slot++;
        } else if (instr_is_call_indirect(instr)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)AtCall, false, 1,
                                 OPND_CREATE_INT32(slot));
            if (GLOBAL_STATE.userInstrumentationCallback) {
                if(GLOBAL_STATE.isInterestingIns(instr)){
                    GLOBAL_STATE.userInstrumentationCallback(
                    drcontext, bb, instr, GLOBAL_STATE.userInstrumentationCallbackArg,
                    slot);
                }
            }
            ipShadow[slot + 2] = (uint64_t)(ptr_int_t)instr;
            slot++;
        } else if (instr_is_return(instr)) {
            if (GLOBAL_STATE.userInstrumentationCallback) {
                if(GLOBAL_STATE.isInterestingIns(instr)){
                    GLOBAL_STATE.userInstrumentationCallback(
                    drcontext, bb, instr, GLOBAL_STATE.userInstrumentationCallbackArg,
                    slot);
                }
            }
            dr_insert_clean_call(drcontext, bb, instr, (void *)AtReturn, false, 0);
            ipShadow[slot + 2] = (uint64_t)(ptr_int_t)instr;
            slot++;
        } else if (GLOBAL_STATE.isInterestingIns(instr)) {
            if (GLOBAL_STATE.userInstrumentationCallback) {
                GLOBAL_STATE.userInstrumentationCallback(
                    drcontext, bb, instr, GLOBAL_STATE.userInstrumentationCallbackArg,
                    slot);
            }
            ipShadow[slot + 2] = (uint64_t)(ptr_int_t)instr;
            slot++;
        }
#ifdef CCTLIB_USE_STACK_STATUS
        if (TrashesStackPtr(instr)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)SetCallStackPtrStashFlag, false, 0);
        }
#endif
    }
}

static dr_emit_flags_t
CCTLibBBAnalysis(void *drcontext, void *tag, instrlist_t *bb, bool for_bb,
                 bool translating, OUT void **user_data)
{
    uint32_t numInstrs = GetNumInterestingInsInBB(bb);
    if(numInstrs <= 0){
        return DR_EMIT_DEFAULT;
    }
    uint32_t bbKey = GetNextBBKey();
    instr_t *start = instrlist_first_app(bb);
    dr_insert_clean_call(drcontext, bb, start, (void *)AtBBEntry, false, 2,
                         OPND_CREATE_INT32(bbKey),
                         OPND_CREATE_INT32(numInstrs));
    PopulateIPReverseMapAndAccountBbInstructions(drcontext, bb, start, bbKey,
                                                 numInstrs);
    return DR_EMIT_DEFAULT;
}

static void
CCTLibModuleAnalysis(void *drcontext, const module_data_t *info, bool loaded)
{
    cerr<<"===========CCTLibModuleAnalysis"<<endl;
    
    // UINT32 id = IMG_Id(img);
    // ModuleInfo moudleInfo;
    // if (IMG_IsMainExecutable(img))
    //     mi.id = 1;
    // else
    //     mi.id = 0;
    // moudleInfo.moduleName = dr_module_preferred_name(info);
    // moudleInfo.imgLoadOffset = *(info->start);
    // moudleInfo.imgLoadOffset = IMG_LoadOffset(img);
    // GLOBAL_STATE.ModuleInfoMap[id] = mi;
}

//  Find the pthread_create() function.
#define PTHREAD_CREATE_RTN "pthread_create"
#define ARCH_LONGJMP_RTN "__longjmp"
#define SETJMP_RTN "_setjmp"
#define LONGJMP_RTN ARCH_LONGJMP_RTN
#define SIGSETJMP_RTN "sigsetjmp"
#define SIGLONGJMP_RTN ARCH_LONGJMP_RTN
#define UNWIND_SETIP "_Unwind_SetIP"
#define UNWIND_RAISEEXCEPTION "_Unwind_RaiseException"
#define UNWIND_RESUME "_Unwind_Resume"
#define UNWIND_FORCEUNWIND "_Unwind_ForcedUnwind"
#define UNWIND_RESUME_OR_RETHROW "_Unwind_Resume_or_Rethrow"

#if 0
static void
CCTLibImage(void *drcontext, const module_data_t *info, bool loaded)
{

    RTN pthread_createRtn = RTN_FindByName(img, PTHREAD_CREATE_RTN);
    RTN setjmpRtn = RTN_FindByName(img, SETJMP_RTN);
    RTN longjmpRtn = RTN_FindByName(img, LONGJMP_RTN);
    RTN sigsetjmpRtn = RTN_FindByName(img, SIGSETJMP_RTN);
    RTN siglongjmpRtn = RTN_FindByName(img, SIGLONGJMP_RTN);
    RTN archlongjmpRtn = RTN_FindByName(img, ARCH_LONGJMP_RTN);
    RTN unwindSetIpRtn = RTN_FindByName(img, UNWIND_SETIP);
    RTN unwindRaiseExceptionRtn = RTN_FindByName(img, UNWIND_RAISEEXCEPTION);
    RTN unwindResumeRtn = RTN_FindByName(img, UNWIND_RESUME);
    RTN unwindForceUnwindRtn = RTN_FindByName(img, UNWIND_FORCEUNWIND);

    if (RTN_Valid(pthread_createRtn)) {
        // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",PTHREAD_CREATE_RTN);
        RTN_Open(pthread_createRtn);
        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(pthread_createRtn, IPOINT_AFTER, (AFUNPTR)ThreadCreatePoint,
                       IARG_THREAD_ID, IARG_END);
        RTN_Close(pthread_createRtn);
    }

    // Look for setjmp and longjmp routines present in libc.so.x file only
    if (strstr(IMG_Name(img).c_str(), "libc.so")) {
        if (RTN_Valid(setjmpRtn)) {
            // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",SETJMP_RTN);
            RTN_Open(setjmpRtn);
            RTN_InsertCall(setjmpRtn, IPOINT_BEFORE, (AFUNPTR)CaptureSigSetJmpCtxt,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(setjmpRtn);
        }

        if (RTN_Valid(longjmpRtn)) {
            // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",LONGJMP_RTN);
            RTN_Open(longjmpRtn);
            RTN_InsertCall(longjmpRtn, IPOINT_BEFORE, (AFUNPTR)HoldLongJmpBuf,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(longjmpRtn);
        }

        if (RTN_Valid(sigsetjmpRtn)) {
            // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",SIGSETJMP_RTN);
            RTN_Open(sigsetjmpRtn);
            // CALL_ORDER_LAST so that cctlib's trace level instrumentation has updated
            // the tlsCurrentCtxtHndl
            RTN_InsertCall(sigsetjmpRtn, IPOINT_BEFORE, (AFUNPTR)CaptureSigSetJmpCtxt,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(sigsetjmpRtn);
        }

        if (RTN_Valid(siglongjmpRtn)) {
            // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",SIGLONGJMP_RTN);
            RTN_Open(siglongjmpRtn);
            RTN_InsertCall(siglongjmpRtn, IPOINT_BEFORE, (AFUNPTR)HoldLongJmpBuf,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(siglongjmpRtn);
        }

        if (RTN_Valid(archlongjmpRtn)) {
            // fprintf(GLOBAL_STATE.CCTLibLogFile, "\n Found RTN %s",ARCH_LONGJMP_RTN);
            RTN_Open(archlongjmpRtn);
            // Insert after the last JMP Inst.
            INS lastIns = RTN_InsTail(archlongjmpRtn);
            assert(INS_Valid(lastIns));
            assert(INS_IsBranch(lastIns));
            assert(!INS_IsDirectBranch(lastIns));
            INS_InsertCall(lastIns, IPOINT_TAKEN_BRANCH, (AFUNPTR)RestoreSigLongJmpCtxt,
                           IARG_THREAD_ID, IARG_END);
            // RTN_InsertCall(siglongjmpRtn, IPOINT_BEFORE,
            // (AFUNPTR)RestoreSigLongJmpCtxt, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            // IARG_THREAD_ID, IARG_END);
            RTN_Close(archlongjmpRtn);
        }
    }
    
    // Look for unwinding related routines present in libc.so.x file only
    if (strstr(IMG_Name(img).c_str(), "libgcc_s.so")) {
        if (RTN_Valid(unwindSetIpRtn)) {
            RTN_Open(unwindSetIpRtn);
            // Get the intended target IP and prepare the call stack to be ready to unwind
            // to that level
            RTN_InsertCall(unwindSetIpRtn, IPOINT_BEFORE,
                           (AFUNPTR)CaptureCallerThatCanHandleException,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            // I don;t think there is a need to do this as the last instruction unlike
            // RestoreSigLongJmpCtxt. Since _Unwind_SetIP implementations employ a
            // technique of overwriting the return address to jump to the exception
            // handler, calls made by _Unwind_SetIP if any will not cause any problem even
            // if we rewire the call path before executing the return.
            RTN_Close(unwindSetIpRtn);
        }

        if (RTN_Valid(unwindResumeRtn)) {
            RTN_Open(unwindResumeRtn);

            // *** THIS ROUTINE NEVER RETURNS ****
            // After every return instruction in this function, call
            // SetCurTraceNodeAfterException
            for (INS i = RTN_InsHead(unwindResumeRtn); INS_Valid(i); i = INS_Next(i)) {
                if (!INS_IsRet(i))
                    continue;

                // CALL_ORDER_LAST+10 because CALL_ORDER_LAST is reserved for
                // GoUpCallChain that is executed on each RET instruction. We need to
                // adjust the context after GoUpCallChain has executed.
                INS_InsertCall(i, IPOINT_BEFORE, (AFUNPTR)SetCurTraceNodeAfterException,
                               IARG_CALL_ORDER, CALL_ORDER_LAST + 10, IARG_THREAD_ID,
                               IARG_END);
                // INS_InsertCall(i, IPOINT_TAKEN_BRANCH, (AFUNPTR)
                // SetCurTraceNodeAfterException, IARG_THREAD_ID, IARG_END);
            }

            RTN_Close(unwindResumeRtn);
        }

        if (RTN_Valid(unwindRaiseExceptionRtn)) {
            RTN_Open(unwindRaiseExceptionRtn);
            // After the last return instruction in this function, call
            // SetCurTraceNodeAfterExceptionIfContextIsInstalled
            INS lastIns = INS_Invalid();

            for (INS i = RTN_InsHead(unwindRaiseExceptionRtn); INS_Valid(i);
                 i = INS_Next(i)) {
                if (!INS_IsRet(i))
                    continue;
                else
                    lastIns = i;
            }

            if (lastIns != INS_Invalid()) {
                // CALL_ORDER_LAST+10 because CALL_ORDER_LAST is reserved for
                // GoUpCallChain that is executed on each RET instruction. We need to
                // adjust the context after GoUpCallChain has executed.
                INS_InsertCall(lastIns, IPOINT_BEFORE,
                               (AFUNPTR)SetCurTraceNodeAfterExceptionIfContextIsInstalled,
                               IARG_CALL_ORDER, CALL_ORDER_LAST + 10,
                               IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
                // INS_InsertCall(lastIns, IPOINT_TAKEN_BRANCH, (AFUNPTR)
                // SetCurTraceNodeAfterExceptionIfContextIsInstalled,
                // IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            } else {
                // assert(0 && "did not find the last return in unwindRaiseExceptionRtn");
                // printf("\n did not find the last return in unwindRaiseExceptionRtn");
                fprintf(GLOBAL_STATE.CCTLibLogFile,
                        "\n did not find the last return in unwindRaiseExceptionRtn");
            }

            RTN_Close(unwindRaiseExceptionRtn);
        }

        if (RTN_Valid(unwindForceUnwindRtn)) {
            RTN_Open(unwindForceUnwindRtn);
            // After the last return instruction in this function, call
            // SetCurTraceNodeAfterExceptionIfContextIsInstalled
            INS lastIns = INS_Invalid();

            for (INS i = RTN_InsHead(unwindForceUnwindRtn); INS_Valid(i);
                 i = INS_Next(i)) {
                if (!INS_IsRet(i))
                    continue;
                else
                    lastIns = i;
            }

            if (lastIns != INS_Invalid()) {
                // CALL_ORDER_LAST+10 because CALL_ORDER_LAST is reserved for
                // GoUpCallChain that is executed on each RET instruction. We need to
                // adjust the context after GoUpCallChain has executed.
                INS_InsertCall(lastIns, IPOINT_BEFORE,
                               (AFUNPTR)SetCurTraceNodeAfterExceptionIfContextIsInstalled,
                               IARG_CALL_ORDER, CALL_ORDER_LAST + 10,
                               IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
                // INS_InsertCall(lastIns, IPOINT_TAKEN_BRANCH, (AFUNPTR)
                // SetCurTraceNodeAfterExceptionIfContextIsInstalled,
                // IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            } else {
                // TODO : This function _Unwind_ForcedUnwind also appears in
                // /lib64/libpthread.so.0. in which case, we should ignore it.
                // assert(0 && "did not find the last return in unwindForceUnwindRtn");
                // printf("\n did not find the last return in unwindForceUnwindRtn");
                fprintf(GLOBAL_STATE.CCTLibLogFile,
                        "\n did not find the last return in unwindForceUnwindRtn");
            }

            RTN_Close(unwindForceUnwindRtn);
        }


    } // end strstr
    // end DISABLE_EXCEPTION_HANDLING

    // For new DW2 exception handling, we need to reset the shadow stack to the current
    // handler in the following functions:
    // 1. _Unwind_Reason_Code _Unwind_RaiseException ( struct _Unwind_Exception
    // *exception_object );
    // 2. _Unwind_Reason_Code _Unwind_ForcedUnwind ( struct _Unwind_Exception
    // *exception_object, _Unwind_Stop_Fn stop, void *stop_parameter );
    // 3. void _Unwind_Resume (struct _Unwind_Exception *exception_object); *** INSTALL
    // UNCONDITIONALLY, SINCE THIS NEVER RETURNS ***
    // 4. _Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE _Unwind_Resume_or_Rethrow (struct
    // _Unwind_Exception *exc) *** I AM NOT IMPLEMENTING THIS UNTILL I HIT A CODE THAT
    // NEEDS IT ***

    // These functions call "uw_install_context" at the end of the routine just before
    // returning, which overwrite the return address. uw_install_context itself is a
    // static function inlined or macroed. So we would rely on the more externally visible
    // functions. There are multiple returns in these (_Unwind_RaiseException,
    // _Unwind_ForcedUnwind, _Unwind_Resume_or_Rethrow) functions. Only if the return
    // value is "_URC_INSTALL_CONTEXT" shall we reset the shadow stack.

    // if data centric is enabled, capture allocation routines
    if (GLOBAL_STATE.doDataCentric) {
        RTN mallocRtn = RTN_FindByName(img, MALLOC_FN_NAME);

        if (RTN_Valid(mallocRtn)) {
            RTN_Open(mallocRtn);
            // Capture the allocation size and CCT node
            RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)CaptureMallocSize,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            // capture the allocated pointer and initialize the memory with CCT node.
            RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)CaptureMallocPointer,
                           IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            RTN_Close(mallocRtn);
        }

        RTN callocRtn = RTN_FindByName(img, CALLOC_FN_NAME);

        if (RTN_Valid(callocRtn)) {
            RTN_Open(callocRtn);
            // Capture the allocation size and CCT node
            RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)CaptureCallocSize,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_THREAD_ID, IARG_END);
            // capture the allocated pointer and initialize the memory with CCT node.
            RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)CaptureMallocPointer,
                           IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            RTN_Close(callocRtn);
        }

        RTN reallocRtn = RTN_FindByName(img, REALLOC_FN_NAME);

        if (RTN_Valid(reallocRtn)) {
            RTN_Open(reallocRtn);
            // Capture the allocation size and CCT node
            RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)CaptureReallocSize,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_THREAD_ID, IARG_END);
            // capture the allocated pointer and initialize the memory with CCT node.
            RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)CaptureMallocPointer,
                           IARG_FUNCRET_EXITPOINT_VALUE, IARG_THREAD_ID, IARG_END);
            RTN_Close(reallocRtn);
        }

        RTN freeRtn = RTN_FindByName(img, FREE_FN_NAME);

        if (RTN_Valid(freeRtn)) {
            RTN_Open(freeRtn);
            RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)CaptureFree,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_THREAD_ID, IARG_END);
            RTN_Close(freeRtn);
        }
    }

    // Get the first instruction of main
    if (GLOBAL_STATE.skip) {
        RTN mainRtn = RTN_FindByName(img, "main");
        if (!RTN_Valid(mainRtn)) {
            mainRtn = RTN_FindByName(img, "MAIN");
            if (!RTN_Valid(mainRtn)) {
                mainRtn = RTN_FindByName(img, "MAIN_");
            }
        }
        if (RTN_Valid(mainRtn)) {
            GLOBAL_STATE.mainIP = RTN_Address(mainRtn);
        }
    }
}
#endif

static size_t
getPeakRSS()
{
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    return (size_t)(rusage.ru_maxrss);
}

static void
PrintStats()
{
    dr_fprintf(GLOBAL_STATE.CCTLibLogFile, "\nTotalCallPaths = %" PRIu64,
               GLOBAL_STATE.curPreAllocatedContextBufferIndex);
    // Peak resource usage
    dr_fprintf(GLOBAL_STATE.CCTLibLogFile, "\nPeakRSS = %zu", getPeakRSS());
}

// This function is called when the application exits
static void
Fini()
{
    CCTLIB_F_EXE_CALLBACK_FUNC(GLOBAL_STATE.callbackFuncs, finiFunc);
    // cerr<<"Fini()"<<endl;
    PrintStats();
    drmgr_unregister_bb_instrumentation_event(CCTLibBBAnalysis);
    // drmgr_unregister_bb_insertion_event(CCTLibInstrAnalysis);
    drmgr_unregister_thread_init_event(CCTLibThreadStart);
    drmgr_unregister_thread_exit_event(CCTLibThreadEnd);
    drmgr_unregister_tls_field(GLOBAL_STATE.CCTLibTlsKey);
    dr_mutex_destroy(GLOBAL_STATE.lock);
    drmgr_exit();
    drutil_exit();
    drwrap_exit();
    if (drsym_exit() != DRSYM_SUCCESS) {
        dr_log(CCTLIB_C_DR_NULL, DR_LOG_ALL, 1, "WARNING: unable to clean up symbol library\n");
    }
    dr_close_file(GLOBAL_STATE.CCTLibLogFile);
}

// init logfile
static void
InitLogFile(file_t logFile)
{
    GLOBAL_STATE.CCTLibLogFile = logFile;
}

// init IPNode store space; (Q) why mmap？share memory across threads
static void
InitBuffers()
{
    // prealloc IPNodeVec so that they all come from a continuous memory region.
    // IMPROVEME ... actually this can be as high as 24 GB since lower 3 bits are always
    // zero for pointers
    GLOBAL_STATE.preAllocatedContextBuffer =
        (IPNode *)mmap(0, CCTLIB_N_MAX_IPNODES * sizeof(IPNode), PROT_WRITE | PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // start from index 1 so that we can use 0 as empty key for the google hash table
    GLOBAL_STATE.curPreAllocatedContextBufferIndex = 1;
    // Init the string pool
    GLOBAL_STATE.preAllocatedStringPool = (char*) mmap(0, CCTLIB_N_MAX_STRING_POOL_NODES * sizeof(char), PROT_WRITE
                                            | PROT_READ, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // start from index 1 so that we can use 0 as a special value
    GLOBAL_STATE.curPreAllocatedStringPoolIndex = 1;
}


//DO_DATA_CENTRIC
#if 0
    static void
    InitShadowSpaceForDataCentric(void *addr, uint32_t accessLen, DataHandle_t *initializer)
    {
        uint64_t endAddr = (uint64_t)addr + accessLen;
        uint32_t numInited = 0;

        for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr;
            curAddr += SHADOW_PAGE_SIZE) {
    #if __cplusplus > 199711L
            DataHandle_t *status = GetOrCreateShadowAddress<0>(sm, (size_t)curAddr);
    #else
            DataHandle_t *status = GetOrCreateShadowAddress_0(sm, (size_t)curAddr);
    #endif
            int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)addr);

            for (int i = 0; (i < maxBytesInThisPage) && numInited < accessLen;
                numInited++, i++) {
                status[i] = *initializer;
            }
        }
    }

    static void
    CaptureMallocSize(size_t arg0, THREADID threadId)
    {
        // Remember the CCT node and the allocation size
        ThreadData *tData = CCTLibGetTLS(threadId);
        tData->tlsDynamicMemoryAllocationSize = arg0;
        tData->tlsDynamicMemoryAllocationPathHandle = GetContextHandle(threadId, 0);
    }

    static void
    CaptureCallocSize(size_t arg0, size_t arg1, THREADID threadId)
    {
        // Remember the CCT node and the allocation size
        ThreadData *tData = CCTLibGetTLS(threadId);
        tData->tlsDynamicMemoryAllocationSize = arg0 * arg1;
        tData->tlsDynamicMemoryAllocationPathHandle = GetContextHandle(threadId, 0);
    }

    static void
    CaptureReallocSize(void *ptr, size_t arg1, THREADID threadId)
    {
        // Remember the CCT node and the allocation size
        ThreadData *tData = CCTLibGetTLS(threadId);
        tData->tlsDynamicMemoryAllocationSize = arg1;
        tData->tlsDynamicMemoryAllocationPathHandle = GetContextHandle(threadId, 0);
    }

    static void
    CaptureMallocPointer(void *ptr, THREADID threadId)
    {
        ThreadData *tData = CCTLibGetTLS(threadId);
        DataHandle_t dataHandle;
        dataHandle.objectType = DYNAMIC_OBJECT;
        dataHandle.pathHandle = tData->tlsDynamicMemoryAllocationPathHandle;
        InitShadowSpaceForDataCentric(ptr, tData->tlsDynamicMemoryAllocationSize,
                                    &dataHandle);
    }

    // compute static variables
    // each image has a splay tree to include all static variables
    // that reside in the image. All images are linked as a link list
    static void
    compute_static_var(char *filename, IMG img)
    {
        // Elf32_Ehdr* elf_header;         /* ELF header */
        Elf *elf;               /* Our Elf pointer for libelf */
        Elf_Scn *scn = NULL;    /* Section Descriptor */
        Elf_Data *edata = NULL; /* Data Descriptor */
        GElf_Sym sym;           /* Symbol */
        GElf_Shdr shdr;         /* Section Header */
        char *base_ptr;         // ptr to our object in memory
        struct stat elf_stats;  // fstat struct
        int i, symbol_count;
        int fd = open(filename, O_RDONLY);

        if ((fstat(fd, &elf_stats))) {
            printf("bss: could not fstat, so not monitor static variables\n");
            close(fd);
            return;
        }

        if ((base_ptr = (char *)malloc(elf_stats.st_size)) == NULL) {
            printf("could not malloc\n");
            close(fd);
            dr_exit_process(-1);
        }

        if ((read(fd, base_ptr, elf_stats.st_size)) < elf_stats.st_size) {
            printf("could not read\n");
            free(base_ptr);
            close(fd);
            dr_exit_process(-1);
        }

        if (elf_version(EV_CURRENT) == EV_NONE) {
            printf("WARNING Elf Library is out of date!\n");
        }

        // elf_header = (Elf32_Ehdr*) base_ptr;    // point elf_header at our object in memory
        elf = elf_begin(fd, ELF_C_READ,
                        NULL); // Initialize 'elf' pointer to our file descriptor

        // Iterate each section until symtab section for object symbols
        while ((scn = elf_nextscn(elf, scn)) != NULL) {
            gelf_getshdr(scn, &shdr);

            if (shdr.sh_type == SHT_SYMTAB) {
                edata = elf_getdata(scn, edata);
                symbol_count = shdr.sh_size / shdr.sh_entsize;

                for (i = 0; i < symbol_count; i++) {
                    if (gelf_getsym(edata, i, &sym) == NULL) {
                        printf("gelf_getsym return NULL\n");
                        printf("%s\n", elf_errmsg(elf_errno()));
                        dr_exit_process(-1);
                    }

                    if ((sym.st_size == 0) ||
                        (ELF32_ST_TYPE(sym.st_info) != STT_OBJECT)) { // not a variable
                        continue;
                    }

                    DataHandle_t dataHandle;
                    dataHandle.objectType = STATIC_OBJECT;
                    char *symname = elf_strptr(elf, shdr.sh_link, sym.st_name);
                    dataHandle.symName = symname ? GetNextStringPoolIndex(symname) : 0;
                    InitShadowSpaceForDataCentric(
                        (void *)((IMG_LoadOffset(img)) + sym.st_value), (uint32_t)sym.st_size,
                        &dataHandle);
                }
            }
        }
    }

    static void
    ComputeVarBounds(IMG img, void *v)
    {
        char filename[PATH_MAX];
        char *result = realpath(IMG_Name(img).c_str(), filename);

        if (result == NULL) {
            fprintf(stderr, "\n failed to resolve path");
        }
        compute_static_var(filename, img);
    }

    static void
    InitDataCentric(bool doDataCentric)
    {
        // For shadow memory based approach initialize the L1 page table
        // LEVEL_1_PAGE_TABLE_SIZE
        GLOBAL_STATE.doDataCentric = doDataCentric;
        if(!doDataCentric){
            return;
        }
        // This will perform hpc_var_bounds functionality on each image load
        IMG_AddInstrumentFunction(ComputeVarBounds, 0);
        // delete image from the list at the unloading callback
        IMG_AddUnloadFunction(DeleteStaticVar, 0);
    }
    // end DO_DATA_CENTRIC #endif
#endif

static void
InitUserCallback(CCTLibCallbackFuncsPtr_t callbackFuncs){
    GLOBAL_STATE.callbackFuncs = callbackFuncs;
}

static void
InitTLSKey()
{
    // Obtain  a key for TLS storage.
    GLOBAL_STATE.CCTLibTlsKey = drmgr_register_tls_field();
    DR_ASSERT(GLOBAL_STATE.CCTLibTlsKey != -1);
}

static void
InitUserInstrumentInsCallback(IsInterestingInsFptr isInterestingIns, CCTLibInstrumentInsCallback userCallback, void *userCallbackArg)
{
    GLOBAL_STATE.isInterestingIns = isInterestingIns;
    // remember user instrumentation callback
    GLOBAL_STATE.userInstrumentationCallback = userCallback;
    GLOBAL_STATE.userInstrumentationCallbackArg = userCallbackArg;
}


#ifndef __GNUC__
#pragma endregion PrivateFunctionRegion
#endif

#ifndef __GNUC__
#pragma region CCTLibAPIFunctionRegion
#endif
/********** CCTLib APIs **********/
// API to get the handle for the current calling context
DR_EXPORT
ContextHandle_t
GetContextHandle(void *drcontext, const uint32_t slot)
{
    ThreadData *tData = CCTLibGetTLS(drcontext);
    // cerr<<"bbKey: "<<tData->tlsCurrentBBNode->bbKey<<" slot: "<<slot<<" nslots: "<<tData->tlsCurrentBBNode->nSlots<<endl;
    assert(slot < tData->tlsCurrentBBNode->nSlots);
    return tData->tlsCurrentBBNode->childCtxtStartIdx + slot;
}

#if 0
    // API to get the handle for a data object
    DR_EXPORT
    DataHandle_t
    GetDataObjectHandle(void *drcontext, void *address)
    {
        DataHandle_t dataHandle;
    //     ThreadData *tData = CCTLibGetTLS(drcontext);
    //     // if it is a stack location, set so and return
    //     if (address > tData->tlsStackEnd && address < tData->tlsStackBase) {
    //         dataHandle.objectType = STACK_OBJECT;
    //         return dataHandle;
    //     }
    // #if __cplusplus > 199711L
    //     dataHandle = *(GetOrCreateShadowAddress<0>(sm, (size_t)addr));
    // #else
    //     dataHandle = *(GetOrCreateShadowAddress_0(sm, (size_t)addr));
    // #endif
        return dataHandle;
    }
#endif

// API to print the calling context for input handle
DR_EXPORT
void
PrintFullCallingContext(ContextHandle_t handle)
{
    int depth = 0;
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          GLOBAL_STATE.CCTLibTlsKey);
    while (CCTLIB_F_IS_VALID_CONTEXT(handle) && depth++ < CCTLIB_N_MAX_CCT_PRINT_DEPTH) {
        if (handle == tData->tlsRootCtxtHndl)
            break;
        BBNode *bb = CCTLIB_F_GET_IPNODE_FROM_CONTEXT_HANDLE(handle)->parentBBNode;
        PrintAddress(
            GLOBAL_STATE.blockInterestInstrs[bb->bbKey][handle - bb->childCtxtStartIdx].first,
            GLOBAL_STATE.blockInterestInstrs[bb->bbKey][handle - bb->childCtxtStartIdx].second);
        handle = bb->callerCtxtHndl;
    }
}

// initialize the tool, register instrumentation functions and call the target program.
DR_EXPORT
int
drcctlib_init(IsInterestingInsFptr isInterestingIns, file_t logFile,
             CCTLibInstrumentInsCallback userCallback, void *userCallbackArg,  CCTLibCallbackFuncsPtr_t callbackFuncs, bool doDataCentric)
{

    // Initialize DynamoRIO
    if (!drmgr_init() || !drutil_init() || !drwrap_init())
        DR_ASSERT(false);
    if (drsym_init(0) != DRSYM_SUCCESS) {
        dr_log(CCTLIB_C_DR_NULL, DR_LOG_ALL, 1, "WARNING: unable to initialize symbol translation\n");
    }
    // Intialize CCTLib
    InitBuffers();
    InitLogFile(logFile);
    // InitDataCentric(doDataCentric);
    InitUserCallback(callbackFuncs);
    InitTLSKey();
    InitUserInstrumentInsCallback(isInterestingIns, userCallback, userCallbackArg);
    
    GLOBAL_STATE.lock = dr_mutex_create();

    drmgr_register_bb_instrumentation_event(CCTLibBBAnalysis, CCTLIB_C_DR_NULL, CCTLIB_C_DR_NULL);
    drmgr_register_module_load_event(CCTLibModuleAnalysis);
    drmgr_register_thread_init_event(CCTLibThreadStart);
    drmgr_register_thread_exit_event(CCTLibThreadEnd);
    // Register Fini to be called when the application exits
    dr_register_exit_event(Fini);


    CCTLIB_F_EXE_CALLBACK_FUNC(GLOBAL_STATE.callbackFuncs, initFunc);

    return 0;
}

#ifndef __GNUC__
#pragma endregion CCTLibAPIFunctionRegion
#endif