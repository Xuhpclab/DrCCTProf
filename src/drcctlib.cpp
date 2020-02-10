// #define __STDC_FORMAT_MACROS

#include "drcctlib.h"
#include "drcctlib_define.h"

#include "dr_api.h"
#include "drmgr.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"

#include "shadow_memory.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <string>

#include <fcntl.h>
#include <gelf.h>
#include <inttypes.h>
#include <libelf.h>
#include <limits.h>
#include <setjmp.h>
#include <signal.h>
#include <unwind.h>

#include <sys/resource.h>
#include <sys/mman.h>

#define DRCCTLIB_TEST
#ifdef DRCCTLIB_TEST
#include <drcctlib_debug.h>
#endif


using namespace std;



#if __cplusplus > 199711L

#else
#define nullptr NULL
#endif

// #define CCTLIB_USE_STACK_STATUS
#ifdef CCTLIB_USE_STACK_STATUS
    #define CALL_INITIATED (0b1)
    #define STACK_PTR_STASHED (0b10)
    #define SET_STACK_STATUS(v, flag) \
        (v = v | flag)
    #define UNSET_STACK_STATUS(v, flag) \
        (v = v & (~flag))
    #define RESET_STACK_STATUS(v) \
        (v = 0)
    #define IS_STACK_STATUS(v, flag) \
        (v & flag)
#endif

#define CCTLIB_MAXIMUM_SYMNAME 256

#ifndef __GNUC__
#    pragma region DataStructRegion
#endif


/**
 * ref "2014 - Call paths for pin tools - Chabbi, Liu, Mellor-Crummey" figure
 *2,3,4 A CCTLib BBNode logically represents a dynamorio basic block.(different
 *with Pin CCTLib)
 **/
struct BBNode {
    ContextHandle_t callerCtxtHndl;
    ContextHandle_t childCtxtStartIdx;
    uint64_t bbKey; // max of 2^32 basic blocks allowed
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

struct SerializedBBNode {
    uint64_t bbKey;
    uint32_t nSlots;
    ContextHandle_t childCtxtStartIdx;
};
struct NormalizedIP {
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
    BBNode *tlsParentThreadBBNode;
    
    // dynamorio bug:  unordered_map.insert in tls can cause crash
    unordered_map<uint64_t, ContextHandle_t> * tlsLongJmpMap; 
    uint64_t tlsLongJmpHoldBuf;

    uint32_t tlsCurSlotNo;

    // The caller that can handle the current exception
    BBNode *tlsExceptionHandlerBBNode;
    ContextHandle_t tlsExceptionHandlerCtxtHndle;

    void *tlsStackBase;
    void *tlsStackEnd;
    // DO_DATA_CENTRIC
    size_t tlsDynamicMemoryAllocationSize;
    ContextHandle_t tlsDynamicMemoryAllocationPathHandle;
} __attribute__((aligned));

// Global State
struct GlobalState {
    // Should data-centric attribution be perfomed?
    bool doDataCentric; // false  by default

    uint32_t usageMode;

    file_t logFile;

    CCTLibInstrumentInsCallback userInstrumentationCallback;
    void *userInstrumentationCallbackArg;

    IPNode *preAllocatedContextBuffer;
    uint32_t curPreAllocatedContextBufferIndex __attribute__((
        aligned(128))); // align to eliminate any false
                                             // sharing with other members

    char *preAllocatedStringPool;
    uint32_t curPreAllocatedStringPoolIndex __attribute__((
        aligned(128))); // align to eliminate any false
                                             // sharing with other members

    // Load module info
    unordered_map<module_handle_t, const module_data_t *> moduleDataMap;

    // serialization directory path
    string serializationDirectory;
    // Deserialized CCTs
    vector<ThreadData> deserializedCCTs;

    unordered_map<uint64, void *> bbShadowMap;
    unordered_map<uint64, void *> bbShadowMapInsState;

    void *lock;

    IsInterestingInsFptr isInterestingIns;

    unordered_map<uint64, vector<pair<app_pc, string>>> blockInterestInstrs;

    // key for accessing TLS storage in the threads. initialized once in main()
    /**
     * set tls field different with Pin
     * dynamorio: (drcontect, tlskey)->tData;
     * pin: (threadid, tlskey)->tData
     **/
    TLS_KEY CCTLibTlsKey __attribute__((
        aligned(128))); // align to eliminate any false
                                             // sharing with other  members
    // initial value = 0
    uint32_t numThreads __attribute__((
        aligned(128))); // align to eliminate any false
                                             // sharing with other  members
    unordered_map<uint32_t, ThreadData *> threadDataMap;
    // keys to associate parent child threads
    volatile uint64_t threadCreateCount __attribute__((
        aligned(128))); // initial value = 0  // align to eliminate
                                             // any false sharing with other  members
    volatile uint64_t threadCaptureCount __attribute__((
        aligned(128))); // initial value = 0  // align to eliminate
                                             // any false sharing with other  members
    volatile BBNode *threadCreatorBBNode __attribute__((
        aligned(128))); // align to eliminate any false
                                             // sharing with other  members
    volatile ContextHandle_t threadCreatorCtxtHndl __attribute__((
        aligned(128))); // align to eliminate any false
                                             // sharing with other  members
    volatile bool DSLock;

    CCTLibCallbackFuncStruct *callbackFuncs;
};

#ifndef __GNUC__
#    pragma endregion DataStructRegion
#endif
// thread shared global veriables
static GlobalState g_GlobalState;

static ConcurrentShadowMemory<DataHandle_t> g_DataCentricShadowMemory;

#ifndef __GNUC__
#    pragma region PrivateFunctionRegion
#endif

static inline ContextHandle_t
GetContextHandleFromIPNode(IPNode *ipNode)
{
    return ((ContextHandle_t)(
        (ipNode) ? ((ipNode)-g_GlobalState.preAllocatedContextBuffer) : 0));
}
static inline IPNode *
GetIPNodeFromContextHandle(ContextHandle_t contextHandle)
{
    return g_GlobalState.preAllocatedContextBuffer + contextHandle;
}
static inline bool
IsValidContextHandle(ContextHandle_t contextHandle)
{
    return contextHandle != 0;
}

static inline void
CCTLibCallbackFunc(CCTLibCallbackFuncStruct *funcsStructPtr,
                           CCTLibCallbackState callbackState)
{
    if (funcsStructPtr == nullptr) {
        return;
    }
    switch (callbackState) {
    case CCTLibInitCallback:
        if (funcsStructPtr->initFunc != nullptr) {
            (funcsStructPtr->initFunc)();
        }
        break;
    case CCTLibFiniCallback:
        if (funcsStructPtr->finiFunc != nullptr) {
            (funcsStructPtr->finiFunc)();
        }
        break;
    case CCTLibThreadStartCallback:
        if (funcsStructPtr->threadStartFunc != nullptr) {
            (funcsStructPtr->threadStartFunc)();
        }
        break;
    case CCTLibThreadEndCallback:
        if (funcsStructPtr->threadEndFunc != nullptr) {
            (funcsStructPtr->threadEndFunc)();
        }
        break;
    }
}

// function to get the next unique key for a basic block
static uint64_t
GetNextBBKey()
{
    static uint64_t bbKey = 0;
    uint64_t key = __sync_fetch_and_add(&bbKey, 1);

    if (key == UINT_MAX) {
        cerr << "UINT_MAX basic blocks created! Exiting..." << endl;
        dr_exit_process(-1);
    }

    return key;
}

// function to access thread-specific data
static inline ThreadData *
CCTLibGetTLS(void *drcontext)
{
    ThreadData *tData = static_cast<ThreadData *>(
        drmgr_get_tls_field(drcontext, g_GlobalState.CCTLibTlsKey));
    return tData;
}

static inline ThreadData *
CCTLibGetTLS(uint32_t threadIndex)
{
    ThreadData *tData = g_GlobalState.threadDataMap[threadIndex];
    return tData;
}

static inline ThreadData *
CCTLibGetTLS()
{
    ThreadData *tData = static_cast<ThreadData *>(
        drmgr_get_tls_field(dr_get_current_drcontext(), g_GlobalState.CCTLibTlsKey));
    return tData;
}

static inline void
UpdateCurBBAndIp(ThreadData *tData, BBNode *const bbNode, ContextHandle_t const ctxtHndle)
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

static bool
IsRootIPNode(ContextHandle_t curCtxtHndle, uint32_t *threadId)
{
    *threadId = -1;
    for (uint32_t index = 0; index < g_GlobalState.numThreads; index++) {
        ThreadData *tData = g_GlobalState.threadDataMap[index];

        if (tData->tlsRootCtxtHndl == curCtxtHndle){
            *threadId = index;
            return true;
        }
    }
    return false;
}

static inline void
TakeLock()
{
    do {
        while (g_GlobalState.DSLock)
            ;
    } while (!__sync_bool_compare_and_swap(&g_GlobalState.DSLock, 0, 1));
}

static inline void
ReleaseLock()
{
    g_GlobalState.DSLock = 0;
}

// Pauses creator thread from thread creation until the previously created child
// thread has noted its parent.
static void
ThreadCreatePoint(void *wrapcxt, void *user_data)
{
    cerr<<"ThreadCreatePoint"<<endl;
    while (1) {
        TakeLock();

        if (g_GlobalState.threadCreateCount > g_GlobalState.threadCaptureCount)
            ReleaseLock();
        else
            break;
    }
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    g_GlobalState.threadCreatorBBNode = tData->tlsCurrentBBNode;
    g_GlobalState.threadCreatorCtxtHndl = tData->tlsCurrentCtxtHndl;

    g_GlobalState.threadCreateCount++;
    ReleaseLock();
    cerr<<"EndThreadCreatePoint"<<endl;
}

// Sets the child thread's CCT's parent to its creator thread's CCT node.
static inline void
ThreadCapturePoint(ThreadData *tData)
{
    // cerr<<"ThreadCapturePoint"<<endl;
    TakeLock();
    if (g_GlobalState.threadCreateCount == g_GlobalState.threadCaptureCount) {
        // Base thread, no parent
        // fprintf(g_GlobalState.logFile, "\n ThreadCapturePoint, no parent ");
    } else {
        // This will be always 0 for flat profiles
        tData->tlsParentThreadBBNode = (BBNode *)g_GlobalState.threadCreatorBBNode;
        tData->tlsParentThreadCtxtHndl = g_GlobalState.threadCreatorCtxtHndl;
        // fprintf(g_GlobalState.logFile, "\n ThreadCapturePoint, parent BB =
        // %p, parent ip = %p", g_GlobalState.threadCreatorBBNode,
        // g_GlobalState.threadCreatorCtxtHndl);
        g_GlobalState.threadCaptureCount++;
    }
    ReleaseLock();
    // cerr<<"EndThreadCapturePoint"<<endl;
}

static inline ContextHandle_t
GetNextIPVecBuffer(uint32_t num)
{
    // Multithreaded compatible
    // ensure (oldBufIndex = g_GlobalState.curPreAllocatedContextBufferIndex)
    // g_GlobalState.curPreAllocatedContextBufferIndex = next pre allocated
    uint32_t oldBufIndex =
        __sync_fetch_and_add(&g_GlobalState.curPreAllocatedContextBufferIndex, num);

    if (oldBufIndex + num >= kMaxIPNodesNum) {
        dr_fprintf(g_GlobalState.logFile,
                   "\nPreallocated IPNodes exhausted. CCTLib couldn't fit your application in its memory. Try a smaller program.\n");
        dr_exit_process(-1);
    }

    return (ContextHandle_t)oldBufIndex;
}

static inline uint32_t __attribute__((__unused__)) GetNextStringPoolIndex(char *name)
{
    uint32_t len = strlen(name) + 1;
    uint64_t oldStringPoolIndex =
        __sync_fetch_and_add(&g_GlobalState.curPreAllocatedStringPoolIndex, len);

    if (oldStringPoolIndex + len >= kMaxStringPoolNodesNum) {
        dr_fprintf(g_GlobalState.logFile,
                   "\nPreallocated String Pool exhausted. CCTLib couldn't fit your "
                   "application "
                   "in its memory. Try by changing kMaxStringPoolNodesNum "
                   "macro.\n");
        dr_exit_process(-1);
    }

    // copy contents
    strncpy(g_GlobalState.preAllocatedStringPool + oldStringPoolIndex, name, len);
    return oldStringPoolIndex;
}

static inline void
CCTLibInitThreadData(void *drcontext, ThreadData *const tData, uint32_t threadId)
{
    BBNode *bbNode = new BBNode();
    bbNode->callerCtxtHndl = 0;
    bbNode->nSlots = 1;
    bbNode->childCtxtStartIdx = GetNextIPVecBuffer(1);
    IPNode *ipNode = GetIPNodeFromContextHandle(bbNode->childCtxtStartIdx);
    ipNode->parentBBNode = bbNode;
    ipNode->calleeBBNodes = nullptr;

    tData->tlsThreadId = threadId;
    tData->tlsRootBBNode = bbNode;
    tData->tlsRootCtxtHndl = bbNode->childCtxtStartIdx;
    UpdateCurBBAndIp(tData, bbNode);
    tData->tlsParentThreadCtxtHndl = 0;
    tData->tlsParentThreadBBNode = nullptr;
#ifdef CCTLIB_USE_STACK_STATUS
    RESET_STACK_STATUS(tData->tlsStackStatus);
    SET_STACK_STATUS(tData->tlsStackStatus, CALL_INITIATED);
#else
    tData->tlsInitiatedCall = true;
#endif

    tData->tlsLongJmpMap = new unordered_map<uint64_t, ContextHandle_t>();
    tData->tlsCurSlotNo = 0;

    // Set stack sizes if data-centric is needed
    if (g_GlobalState.doDataCentric) {
        uint64_t s = (uint64_t)reg_get_value(DR_REG_RSP, (dr_mcontext_t *)drcontext);
        tData->tlsStackBase = (void *)s;
        struct rlimit rlim;

        if (getrlimit(RLIMIT_STACK, &rlim)) {
            cerr << "\n Failed to getrlimit()\n";
            dr_exit_process(-1);
        }

        if (rlim.rlim_cur == RLIM_INFINITY) {
            cerr << "\n Need a finite stack size. Dont use unlimited.\n";
            dr_exit_process(-1);
        }

        tData->tlsStackEnd = (void *)(s - rlim.rlim_cur);
    }
}


static void
CCTLibThreadStart(void *drcontext)
{
    uint32_t threadId = -1;
    dr_mutex_lock(g_GlobalState.lock);
    threadId = g_GlobalState.numThreads;
    g_GlobalState.numThreads++;
    dr_mutex_unlock(g_GlobalState.lock);

    void *tData = dr_thread_alloc(drcontext, sizeof(ThreadData));
    DR_ASSERT(tData != NULL);

    CCTLibInitThreadData(drcontext, (ThreadData *)tData, threadId);
    g_GlobalState.threadDataMap[threadId] = (ThreadData *)tData;
    drmgr_set_tls_field(drcontext, g_GlobalState.CCTLibTlsKey, tData);
    ThreadCapturePoint((ThreadData *)tData);

    CCTLibCallbackFunc(g_GlobalState.callbackFuncs, CCTLibThreadStartCallback);
}

static void
CCTLibThreadEnd(void *drcontext)
{
    CCTLibCallbackFunc(g_GlobalState.callbackFuncs, CCTLibThreadEndCallback);
    ThreadData *tData =
        (ThreadData *)drmgr_get_tls_field(drcontext, g_GlobalState.CCTLibTlsKey);
    g_GlobalState.threadDataMap.erase(tData->tlsThreadId);
    delete tData->tlsLongJmpMap;
    dr_thread_free(drcontext, tData, sizeof(ThreadData));
}

static void
AtCall(uint slot)
{
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          g_GlobalState.CCTLibTlsKey);
#ifdef CCTLIB_USE_STACK_STATUS
    SET_STACK_STATUS(tData->tlsStackStatus, CALL_INITIATED);
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
                                                          g_GlobalState.CCTLibTlsKey);
    // If we reach the root trace, then fake the call
    if (tData->tlsCurrentBBNode->callerCtxtHndl == tData->tlsRootCtxtHndl) {
#ifdef CCTLIB_USE_STACK_STATUS
        SET_STACK_STATUS(tData->tlsStackStatus, CALL_INITIATED);
#else
        tData->tlsInitiatedCall = true;
#endif
    }
    tData->tlsCurrentCtxtHndl = tData->tlsCurrentBBNode->callerCtxtHndl;
    UpdateCurBBOnly(
        tData,
        GetIPNodeFromContextHandle(tData->tlsCurrentCtxtHndl)->parentBBNode);
}

static void
RememberSlotNoInTLS(uint slot)
{
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          g_GlobalState.CCTLibTlsKey);
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

static inline bool
IsCallIns(instr_t *ins)
{
    if (instr_is_call_direct(ins) || instr_is_call_indirect(ins)) {
        return true;
    }
    return false;
}

static inline uint32_t
GetNumInterestingInsInBB(instrlist_t *bb)
{
    uint32_t count = 0;
    instr_t *start = instrlist_first_app(bb);
    for (instr_t *ins = start; ins != NULL; ins = instr_get_next_app(ins)) {
        if (IsCallOrRetIns(ins) || g_GlobalState.isInterestingIns(ins)) {
            count++;
        }
    }
    return count;
}

static BBSplay *
UpdateSplayTree(BBSplay *root, uint32_t newKey)
{
    if (root != nullptr) {
        BBSplay *dummyNode = new BBSplay();
        BBSplay *ltreeMaxNode, *rtreeMinNode, *tempNode;
        ltreeMaxNode = rtreeMinNode = dummyNode;
        while (newKey != root->key) {
            if (newKey < root->key) {
                if (root->left == nullptr) {
                    BBSplay *newRoot = new BBSplay();
                    newRoot->key = newKey;
                    root->left = newRoot;
                }
                if (newKey < root->left->key) {
                    tempNode = root->left;
                    root->left = tempNode->right;
                    tempNode->right = root;
                    root = tempNode;
                    if (root->left == nullptr) {
                        BBSplay *newRoot = new BBSplay();
                        newRoot->key = newKey;
                        root->left = newRoot;
                    }
                }
                rtreeMinNode->left = root;
                rtreeMinNode = root;
                root = root->left;
            } else if (newKey > root->key) {
                if (root->right == nullptr) {
                    BBSplay *newRoot = new BBSplay();
                    newRoot->key = newKey;
                    root->right = newRoot;
                }
                if (newKey > root->right->key) {
                    tempNode = root->right;
                    root->right = tempNode->left;
                    tempNode->left = root;
                    root = tempNode;
                    if (root->right == nullptr) {
                        BBSplay *newRoot = new BBSplay();
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
        BBSplay *newRoot = new BBSplay();
        newRoot->key = newKey;
        root = newRoot;
    }
    return root;
}

static void
AtBBEntry(uint newKey, uint numInstrs)
{
    ThreadData *tData = (ThreadData *)drmgr_get_tls_field(dr_get_current_drcontext(),
                                                          g_GlobalState.CCTLibTlsKey);
#ifdef CCTLIB_USE_STACK_STATUS
    // If the stack pointer is stashed, reset the tlsCurrentBbNode to the root
    if (IS_STACK_STATUS(tData->tlsStackStatus, STACK_PTR_STASHED)) {
        tData->tlsCurrentCtxtHndl = tData->tlsRootCtxtHndl;
    } else if (!IS_STACK_STATUS(tData->tlsStackStatus,
                                         CALL_INITIATED)) {
        // if landed here w/o a call instruction, then let's make this bb a sibling.
        // The trick to do it is to go to the parent BbNode and make this bb a child
        // of it
        tData->tlsCurrentCtxtHndl = tData->tlsCurrentBBNode->callerCtxtHndl;
    } else {
        // tlsCurrentCtxtHndl must be pointing to the call IP in the parent bb
    }
    RESET_STACK_STATUS(tData->tlsStackStatus);
#else
    if (!tData->tlsInitiatedCall) {
        tData->tlsCurrentCtxtHndl = tData->tlsCurrentBBNode->callerCtxtHndl;
    } else {
        tData->tlsInitiatedCall = false;
    }
#endif

    IPNode *curParent =
        GetIPNodeFromContextHandle(tData->tlsCurrentCtxtHndl);
    BBSplay *newTreeRoot = UpdateSplayTree(curParent->calleeBBNodes, newKey);
    BBNode *treeRootBBNode = newTreeRoot->value;
    if (treeRootBBNode == nullptr) {
        treeRootBBNode = new BBNode();
        treeRootBBNode->callerCtxtHndl = tData->tlsCurrentCtxtHndl;
        treeRootBBNode->bbKey = (uint64_t)newKey;
        if (numInstrs) {
            treeRootBBNode->childCtxtStartIdx = GetNextIPVecBuffer(numInstrs);
            treeRootBBNode->nSlots = numInstrs;
            IPNode *child = GetIPNodeFromContextHandle(
                treeRootBBNode->childCtxtStartIdx);
            for (uint i = 0; i < numInstrs; ++i) {
                child[i].parentBBNode = treeRootBBNode;
                child[i].calleeBBNodes = nullptr;
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
                                                            g_GlobalState.CCTLibTlsKey);
        SET_STACK_STATUS(tData->tlsStackStatus, STACK_PTR_STASHED);
    }

    static bool
    TrashesStackPtr(instr_t *instr)
    {
        bool result = false;
        bool read = false;
        bool write = false;
        bool isImplicit = false;
        // stack ptr is modified
        int numReadDsts = instr_num_srcs(instr);
        for (int i = 0; i < numReadDsts; i++) {
            opnd_t opnd = instr_get_src(instr, i);
            if (opnd_is_reg(opnd)) {
                if (opnd_get_reg(opnd) == DR_REG_ESP || opnd_get_reg(opnd) == DR_REG_RSP) {
                    read = true;
                    break;
                }
            }
        }
        int numWriteDsts = instr_num_dsts(instr);
        for (int i = 0; i < numWriteDsts; i++) {
            opnd_t opnd = instr_get_dst(instr, i);
            if (opnd_is_reg(opnd)) {
                if (opnd_get_reg(opnd) == DR_REG_ESP || opnd_get_reg(opnd) == DR_REG_RSP) {
                    write = true;
                    break;
                }
            }
        }

        /*

        */
        if (!read && write && !isImplicit) {
            char disassem[80];
            instr_disassemble_to_buffer(dr_get_current_drcontext(), instr, disassem, 80);
            string code(disassem);
            cerr << code << endl;
            result = true;
        }
        return result;
    }
#endif

static inline Context_t
GetContext(ContextHandle_t curCtxtHndle, app_pc addr, string code)
{
    drsym_error_t symres;
    drsym_info_t sym;
    char name[CCTLIB_MAXIMUM_SYMNAME];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        Context_t context = { "badIp" /*functionName*/,
                              "" /*filePath */,
                              code /*disassembly*/,
                              curCtxtHndle /*ctxtHandle*/,
                              0 /*lineNo*/,
                              addr /*ip*/ };
        return context;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = CCTLIB_MAXIMUM_SYMNAME;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            Context_t context = { 
                sym.name /*functionName*/,
                data->full_path,
                code /*disassembly*/,
                curCtxtHndle /*ctxtHandle*/,
                0 /*lineNo*/,
                addr /*ip*/ 
            };
            dr_free_module_data(data);
            return context;
        } else {
            Context_t context = { 
                sym.name /*functionName*/, 
                data->full_path,
                code /*disassembly*/,
                curCtxtHndle /*ctxtHandle*/,
                sym.line /*lineNo*/,
                addr /*ip*/ 
            };
            dr_free_module_data(data);
            return context;
        }
    } else {
        Context_t context = {
            "<noname>",
            data->full_path,
            code /*disassembly*/,
            curCtxtHndle /*ctxtHandle*/,
            0 /*lineNo*/,
            addr /*ip*/
        };
        dr_free_module_data(data);
        return context;
    }
}

static inline Context_t
GetContext(ContextHandle_t curCtxtHndle){
    BBNode *bb = GetIPNodeFromContextHandle(curCtxtHndle)->parentBBNode;
    return GetContext(
                curCtxtHndle,
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .first,
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .second);
}

static inline bool
IsAppInsContextHandle(ContextHandle_t curCtxtHndle){
    BBNode *bb = GetIPNodeFromContextHandle(curCtxtHndle)->parentBBNode;
    module_data_t *data;
    data = dr_lookup_module(g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .first);
#ifdef DRCCTLIB_TEST
    // cerr<<data->full_path<<endl;
#endif
    char appPath[] = "/home/dolanwm/Github/drcctlib/appsamples/build/sample1";
    return strcmp(data->full_path, appPath) == 0;
}

static void
PrintContext(app_pc addr, string code)
{
    drsym_error_t symres;
    drsym_info_t sym;
    char name[CCTLIB_MAXIMUM_SYMNAME];
    char file[MAXIMUM_PATH];
    module_data_t *data;
    data = dr_lookup_module(addr);
    if (data == NULL) {
        dr_fprintf(g_GlobalState.logFile, " " PFX " ? ??:0\n", addr);
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = CCTLIB_MAXIMUM_SYMNAME;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                  DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
        const char *modname = dr_module_preferred_name(data);
        if (modname == NULL)
            modname = "<noname>";
        dr_fprintf(g_GlobalState.logFile, " " PFX ":%s, %s!%s+" PIFX, addr, code.c_str(),
                   modname, sym.name, addr - data->start - sym.start_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            dr_fprintf(g_GlobalState.logFile, " ??:0\n");
        } else {
            dr_fprintf(g_GlobalState.logFile, " %s:%" UINT64_FORMAT_CODE "+" PIFX "\n",
                       sym.file, sym.line, sym.line_offs);
        }
    } else
        dr_fprintf(g_GlobalState.logFile, " " PFX " ? ??:0\n", addr);
    dr_free_module_data(data);
}


static inline void
SetInsState(char* insStateFlagPtr, CCTLibInsState state){
    *insStateFlagPtr = *insStateFlagPtr | state;
}

static inline bool
IsInsContainState(char insStateFlag, CCTLibInsState state){
    return (insStateFlag & state) > 0;
}

static void
PopulateIPReverseMapAndAccountBbInstructions(void *drcontext, instrlist_t *bb,
                                             instr_t *start, uint64_t bbKey,
                                             uint32_t numInterestingInstInBb)
{
    // +1 to hold the number of slots as a metadata and ++1 to hold module id
    uint64_t *ipShadow =
        (uint64_t *)malloc((2 + numInterestingInstInBb) * sizeof(uint64_t));
    char *insStateShadow = 
        (char *)malloc((numInterestingInstInBb) * sizeof(char *));

    // Record the number of instructions in the bb as the first entry
    ipShadow[0] = numInterestingInstInBb;
    // Record the module id as 2nd entry
    ;
    ipShadow[1] = (uint64_t)(dr_lookup_module(instr_get_app_pc(start)));
    uint32_t slot = 0;
    g_GlobalState.bbShadowMap[bbKey] = &ipShadow[2]; // 0th entry is 2 behind
    g_GlobalState.bbShadowMapInsState[bbKey] = insStateShadow;

    for (instr_t *instr = start; instr != NULL;
         instr = instr_get_next_app(instr)) {
        if (IsCallOrRetIns(instr) || g_GlobalState.isInterestingIns(instr)) {
            app_pc curPc = instr_get_app_pc(instr);
            char disassem[80];
            instr_disassemble_to_buffer(dr_get_current_drcontext(), instr, disassem, 80);
            string code(disassem);
            // cerr<<code<<endl;
            g_GlobalState.blockInterestInstrs[bbKey].push_back({ curPc, code });
            ipShadow[slot + 2] = (uint64_t)curPc;
            dr_insert_clean_call(drcontext, bb, instr, (void *)RememberSlotNoInTLS, false,
                                 1, OPND_CREATE_INT32(slot));
            dr_insert_clean_call(drcontext, bb, instr, (void *)RememberSlotNoInTLS, false,
                                 1, OPND_CREATE_INT32(slot));
        }

        if (g_GlobalState.isInterestingIns(instr)) {
            SetInsState(&insStateShadow[slot], UserInterestingIns);
        }
        if (instr_is_call_direct(instr)) {
            SetInsState(&insStateShadow[slot], InstrIsCallDirect);
        }
        if (instr_is_call_indirect(instr)) {
            SetInsState(&insStateShadow[slot], InstrIsCallInDirect);
        }
        if (instr_is_return(instr)) {
            SetInsState(&insStateShadow[slot], InstrIsReturn);
        }

        if (instr_is_call_direct(instr)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)AtCall, false, 1,
                                 OPND_CREATE_INT32(slot));
            if (g_GlobalState.userInstrumentationCallback) {
                if (g_GlobalState.isInterestingIns(instr)) {
                    g_GlobalState.userInstrumentationCallback(
                        drcontext, bb, instr,
                        g_GlobalState.userInstrumentationCallbackArg, slot);
                }
            }
            slot++;
        } else if (instr_is_call_indirect(instr)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)AtCall, false, 1,
                                 OPND_CREATE_INT32(slot));
            if (g_GlobalState.userInstrumentationCallback) {
                if (g_GlobalState.isInterestingIns(instr)) {
                    g_GlobalState.userInstrumentationCallback(
                        drcontext, bb, instr,
                        g_GlobalState.userInstrumentationCallbackArg, slot);
                }
            }
            slot++;
        } else if (instr_is_return(instr)) {
            if (g_GlobalState.userInstrumentationCallback) {
                if (g_GlobalState.isInterestingIns(instr)) {
                    g_GlobalState.userInstrumentationCallback(
                        drcontext, bb, instr,
                        g_GlobalState.userInstrumentationCallbackArg, slot);
                }
            }
            dr_insert_clean_call(drcontext, bb, instr, (void *)AtReturn, false, 0);
            slot++;
        } else if (g_GlobalState.isInterestingIns(instr)) {
            if (g_GlobalState.userInstrumentationCallback) {
                g_GlobalState.userInstrumentationCallback(
                    drcontext, bb, instr, g_GlobalState.userInstrumentationCallbackArg,
                    slot);
            }
            slot++;
        }

        

#ifdef CCTLIB_USE_STACK_STATUS
        if (TrashesStackPtr(instr)) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)SetCallStackPtrStashFlag,
                                 false, 0);
        }
#endif
    }
}

static dr_emit_flags_t
CCTLibBBAnalysis(void *drcontext, void *tag, instrlist_t *bb, bool for_bb,
                 bool translating, OUT void **user_data)
{
    uint32_t numInstrs = GetNumInterestingInsInBB(bb);
    // if(numInstrs <= 0){
    //     return DR_EMIT_DEFAULT;
    // }
    uint64_t bbKey = GetNextBBKey();
    instr_t *start = instrlist_first_app(bb);
    dr_insert_clean_call(drcontext, bb, start, (void *)AtBBEntry, false, 2,
                         OPND_CREATE_INT64(bbKey), OPND_CREATE_INT32(numInstrs));
    PopulateIPReverseMapAndAccountBbInstructions(drcontext, bb, start, bbKey, numInstrs);
    return DR_EMIT_DEFAULT;
}

// static bool
// CCTLibEnumerateSymbolsCallBack(const char *name, size_t modoffs, void *data)
// {
//     module_data_t *info = (module_data_t *)data;
//     if(strcmp(dr_module_preferred_name(info), "sample1") == 0){
//         cerr << dr_module_preferred_name(info) << ":" << name << ":" << (char *)info->start
//          << modoffs << endl;
//     }
    
//     return true;
// }

static void
CaptureSigSetJmpCtxt(void *wrapcxt, void **user_data)
{
    uint64_t bufAddr = (uint64_t)drwrap_get_arg(wrapcxt, 0);
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    (*(tData->tlsLongJmpMap))[bufAddr] = tData->tlsCurrentBBNode->callerCtxtHndl;
}

static void
HoldLongJmpBuf(void *wrapcxt, void **user_data)
{
    uint64_t bufAddr = (uint64_t)drwrap_get_arg(wrapcxt, 0);
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    tData->tlsLongJmpHoldBuf = bufAddr;
}

static void
RestoreSigLongJmpCtxt(void *wrapcxt, void *user_data)
{
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    DR_ASSERT(tData->tlsLongJmpHoldBuf);
    tData->tlsCurrentCtxtHndl = (*(tData->tlsLongJmpMap)) [tData->tlsLongJmpHoldBuf];
    UpdateCurBBOnly(
        tData,
        GetIPNodeFromContextHandle(tData->tlsCurrentCtxtHndl)->parentBBNode);
    tData->tlsLongJmpHoldBuf =
        0; // reset so that next time we can check if it was set correctly.
}

static bool
IsIpPresentInBB(_Unwind_Ptr exceptionCallerReturnAddrIP, BBNode *bbNode, uint32_t *ipSlot)
{
    uint64_t *ipShadow = (uint64_t *)g_GlobalState.bbShadowMap[bbNode->bbKey];
    char *insStateFlagShadow = (char *)g_GlobalState.bbShadowMapInsState[bbNode->bbKey];
    _Unwind_Ptr ipDirectCall =
        X86_DIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(exceptionCallerReturnAddrIP);
    _Unwind_Ptr ipIndirectCall = X86_INDIRECT_CALL_SITE_ADDR_FROM_RETURN_ADDR(
        exceptionCallerReturnAddrIP);

    for (uint32_t i = 0; i < bbNode->nSlots; i++) {
        // printf("\n serching = %p", tracesIPs[i]);
        // instr_t *instr = (instr_t *)ipShadow[i];
        // uint64_t addr = (uint64_t)instr_get_app_pc(instr);
        uint64_t addr  = ipShadow[i];
        char stateFlag = insStateFlagShadow[i];

        if (addr == ipDirectCall && IsInsContainState(stateFlag, InstrIsCallDirect)){
#ifdef DRCCTLIB_TEST
            // cerr << "ipDirectCall" << g_GlobalState.blockInterestInstrs[bbNode->bbKey][i].second << endl;
            // cerr << "addr:" << addr << " ipDirectCall:" << ipDirectCall
            //      << " ipIndirectCall:" << ipIndirectCall << endl;
#endif
            *ipSlot = i;
            return true;
        }
        if (addr == ipIndirectCall && IsInsContainState(stateFlag, InstrIsCallInDirect)){
#ifdef DRCCTLIB_TEST
            // cerr << "ipIndirectCall" << g_GlobalState.blockInterestInstrs[bbNode->bbKey][i].second << endl;
            // cerr << "addr:" << addr << " ipDirectCall:" << ipDirectCall
            //      << " ipIndirectCall:" << ipIndirectCall << endl;
#endif
            *ipSlot = i;
            return true;
        }
    }
    return false;
}

static BBNode *
FindNearestCallerCoveringIP(_Unwind_Ptr exceptionCallerReturnAddrIP, uint32_t *ipSlot,
                            ThreadData *tData)
{
    BBNode *curBBNode = tData->tlsCurrentBBNode;
    
    while (true) {
        // cerr << "bbKey" << curBBNode->bbKey << endl;
        // break if we have finished looking at the root
        if (curBBNode == tData->tlsRootBBNode) {
            cerr << "CallerCoveringIP == tData->tlsRootBBNode" << endl;
            // dr_exit_process(-1);
            break;
        }
        if (IsIpPresentInBB(exceptionCallerReturnAddrIP, curBBNode, ipSlot)) {
            break;
        }
        curBBNode = GetIPNodeFromContextHandle(curBBNode->callerCtxtHndl)
                        ->parentBBNode;
    }
    return curBBNode;
}

#ifdef DRCCTLIB_TEST
class TestClass{
    public:
        int classIntValue;
};

struct TestWarpcontentArgs {
    int intValue;
    char *charPtrValue;
    vector<int> verctorValue;
    TestClass* userDefineClassPtrValue;
};

static void
DRCCTLibTestWarp(void *wrapcxt, void **user_data)
{
    cerr << "DRCCTLibTestWarp" << endl;
    TestWarpcontentArgs* firstArgs = (TestWarpcontentArgs*)drwrap_get_arg(wrapcxt, 0);

    TestWarpcontentArgs* secondArgs = ((TestWarpcontentArgs*)drwrap_get_arg(wrapcxt, 1));
    cerr <<"DRCCTLibTestWarp:"<< firstArgs->userDefineClassPtrValue->classIntValue << endl;
    cerr <<"DRCCTLibTestWarp:"<< secondArgs->userDefineClassPtrValue->classIntValue << endl;
    
    cerr << "Finish DRCCTLibTestWarp" << endl;
}

static void
DRCCTLibTestWarpResult(void *wrapcxt, void *user_data)
{
    cerr << "DRCCTLibTestWarpResult" << endl;
    int result = (int)(ptr_int_t)drwrap_get_retval(wrapcxt);
    cerr <<"DRCCTLibTestWarpResult:"<< result << endl;
    
    cerr << "Finish DRCCTLibTestWarpResult" << endl;
}

#endif

static void
CaptureCallerThatCanHandleException(void *wrapcxt, void **user_data)
{
    cerr << "CaptureCallerThatCanHandleException" << endl;
    _Unwind_Context* exceptionCallerContext = (_Unwind_Context*)drwrap_get_arg(wrapcxt, 0);
        // _Unwind_Context * firstArgs;
    _Unwind_Ptr exceptionCallerReturnAddrIP = _Unwind_GetIP(exceptionCallerContext);

    cerr << exceptionCallerReturnAddrIP << endl;
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    // Walk the CCT chain staring from tData->tlsCurrentBBNode looking for the
    // nearest one that has targeIp in the range.
    // Record the caller that can handle the exception.
    uint32_t ipSlot = 0;
    tData->tlsExceptionHandlerBBNode =
        FindNearestCallerCoveringIP(exceptionCallerReturnAddrIP, &ipSlot, tData);
    tData->tlsExceptionHandlerCtxtHndle =
        tData->tlsExceptionHandlerBBNode->childCtxtStartIdx + ipSlot;
    cerr << "Finish CaptureCallerThatCanHandleException" << endl;
}


static void
SetCurBBNodeAfterException(void *wrapcxt, void *user_data)
{
    cerr << "SetCurBBNodeAfterException" << endl;
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    cerr << "Reach Here" << endl;
    // Record the caller that can handle the exception.
    UpdateCurBBAndIp(tData, tData->tlsExceptionHandlerBBNode,
                     tData->tlsExceptionHandlerCtxtHndle);
}

static void
SetCurBBNodeAfterExceptionIfContextIsInstalled(void *wrapcxt, void *user_data)
{
    cerr << "SetCurBBNodeAfterExceptionIfContextIsInstalled" << endl;
    void * retval = drwrap_get_retval(wrapcxt);
    if(retval == NULL) {
        cerr << "?????" << endl;
    }
    int returncode = (int)(ptr_int_t)retval;
    cerr << "returncode : " << returncode << endl;
    // if the return value is _URC_INSTALL_CONTEXT then we will reset the shadow
    // stack, else NOP Commented ... caller ensures it is inserted only at the
    // end. if(retVal != _URC_INSTALL_CONTEXT)
    //    return;
    if (returncode == _Unwind_Reason_Code::_URC_INSTALL_CONTEXT) {
        ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
        // Record the caller that can handle the exception.
        UpdateCurBBAndIp(tData, tData->tlsExceptionHandlerBBNode,
                         tData->tlsExceptionHandlerCtxtHndle);
    }
}

// DO_DATA_CENTRIC
static void
InitShadowSpaceForDataCentric(void *addr, uint32_t accessLen, DataHandle_t *initializer)
{
    // cerr << "InitShadowSpaceForDataCentric" << endl;
    uint64_t endAddr = (uint64_t)addr + accessLen;
    uint32_t numInited = 0;

    for (uint64_t curAddr = (uint64_t)addr; curAddr < endAddr;
         curAddr += SHADOW_PAGE_SIZE) {
#if __cplusplus > 199711L
        DataHandle_t *status =
            GetOrCreateShadowAddress<0>(g_DataCentricShadowMemory, (size_t)curAddr);
#else
        DataHandle_t *status =
            GetOrCreateShadowAddress_0(g_DataCentricShadowMemory, (size_t)curAddr);
#endif
        int maxBytesInThisPage = SHADOW_PAGE_SIZE - PAGE_OFFSET((uint64_t)addr);

        for (int i = 0; (i < maxBytesInThisPage) && numInited < accessLen;
             numInited++, i++) {
            status[i] = *initializer;
        }
    }
}

static void
CaptureMallocSize(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    tData->tlsDynamicMemoryAllocationSize = (size_t)drwrap_get_arg(wrapcxt, 0);
    tData->tlsDynamicMemoryAllocationPathHandle =
        tData->tlsCurrentBBNode->childCtxtStartIdx;
}

static void
CaptureMallocPointer(void *wrapcxt, void *user_data)
{
    void *ptr = drwrap_get_retval(wrapcxt);
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    DataHandle_t dataHandle;
    dataHandle.objectType = DYNAMIC_OBJECT;
    dataHandle.pathHandle = tData->tlsDynamicMemoryAllocationPathHandle;
    InitShadowSpaceForDataCentric(ptr, tData->tlsDynamicMemoryAllocationSize,
                                  &dataHandle);
}

static void
CaptureCallocSize(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    tData->tlsDynamicMemoryAllocationSize =
        (size_t)drwrap_get_arg(wrapcxt, 0) * (size_t)drwrap_get_arg(wrapcxt, 1);
    tData->tlsDynamicMemoryAllocationPathHandle =
        tData->tlsCurrentBBNode->childCtxtStartIdx;
}

static void
CaptureReallocSize(void *wrapcxt, void **user_data)
{
    // Remember the CCT node and the allocation size
    ThreadData *tData = CCTLibGetTLS((void *)drwrap_get_drcontext(wrapcxt));
    tData->tlsDynamicMemoryAllocationSize = (size_t)drwrap_get_arg(wrapcxt, 1);
    tData->tlsDynamicMemoryAllocationPathHandle =
        tData->tlsCurrentBBNode->childCtxtStartIdx;
}

static void
CaptureFree(void *wrapcxt, void **user_data)
{
}

// compute static variables
// each image has a splay tree to include all static variables
// that reside in the image. All images are linked as a link list
static void
ComputeStaticVar(char *filename, const module_data_t *info)
{
    // cerr << "ComputeStaticVar" << endl;
    Elf *elf; /* Our Elf pointer for libelf */

    Elf_Scn *scn = NULL;    /* Section Descriptor */
    Elf_Data *edata = NULL; /* Data Descriptor */
    GElf_Sym sym;           /* Symbol */
    GElf_Shdr shdr;         /* Section Header */

    int i, symbol_count;
    int fd = open(filename, O_RDONLY);

    if (elf_version(EV_CURRENT) == EV_NONE) {
        printf("WARNING Elf Library is out of date!\n");
    }

    // in memory
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
                cerr<<dataHandle.symName<<endl;
                InitShadowSpaceForDataCentric(
                    (void *)((uint64_t)(info->start) + sym.st_value),
                    (uint32_t)sym.st_size, &dataHandle);
            }
        }
    }
}

static void
ComputeVarBounds(void *drcontext, const module_data_t *info, bool loaded)
{
    // cerr << "ComputeVarBounds" << endl;
    char filename[PATH_MAX];
    char *result = realpath(info->full_path, filename);

    if (result == NULL) {
        cerr<<info->full_path<<"----" << "failed to resolve path" << endl;
    }
    ComputeStaticVar(filename, info);
}

static void
DeleteStaticVar(void *drcontext, const module_data_t *info)
{
}

static void
InitDataCentric(bool doDataCentric)
{
    // cerr << "InitDataCentric" << endl;
    // For shadow memory based approach initialize the L1 page table
    // LEVEL_1_PAGE_TABLE_SIZE
    g_GlobalState.doDataCentric = doDataCentric;
    if (!doDataCentric) {
        return;
    }
    // This will perform hpc_var_bounds functionality on each image load
    drmgr_register_module_load_event(ComputeVarBounds);
    // delete image from the list at the unloading callback
    drmgr_register_module_unload_event(DeleteStaticVar);
}
// end DO_DATA_CENTRIC #endif
static inline app_pc
GetInternalFunctionEntry(const module_data_t *info, string functionName){
    app_pc functionEntry;
    size_t offs;
    if (drsym_lookup_symbol(info->full_path, functionName.c_str(), &offs, DRSYM_DEMANGLE) == DRSYM_SUCCESS) {
        functionEntry = offs + info->start;
    }
    else {
        functionEntry = NULL;
    }
    return functionEntry;
}

static inline app_pc
GetExternalFunctionEntry(const module_data_t *info, string functionName){
    return (app_pc)dr_get_proc_address(info->handle, functionName.c_str());
}

static void
CCTLibModuleAnalysis(void *drcontext, const module_data_t *info, bool loaded)
{
    // cerr<<"===========CCTLibModuleAnalysis"<<endl;
    // cerr << dr_module_preferred_name(info) << endl;
    // drsym_enumerate_symbols(info->full_path, CCTLibEnumerateSymbolsCallBack, (void *)info,
    //                         0);
    g_GlobalState.moduleDataMap[info->handle] = info;

    app_pc pthreadCreateEntry =
        (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_PTHREAD_CREATE);
    if (pthreadCreateEntry != NULL) {
        cerr<<"+++CCTLIB_STR_PTHREAD_CREATE/ThreadCreatePoint"<<endl;
        drwrap_wrap(pthreadCreateEntry, NULL, ThreadCreatePoint);
    }

    // Look for setjmp and longjmp routines present in libc.so.x file only
    if (strstr(dr_module_preferred_name(info), "libc.so")) {
        app_pc setjmpEntry = (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_SETJMP);
        if (setjmpEntry != NULL) {
            cerr<<"+++CCTLIB_STR_SETJMP/CaptureSigSetJmpCtxt"<<endl;
            drwrap_wrap(setjmpEntry, CaptureSigSetJmpCtxt, NULL);
        }
        app_pc longjmpEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_LONGJMP);
        if (longjmpEntry != NULL) {
            cerr<<"+++CCTLIB_STR_LONGJMP/HoldLongJmpBuf&RestoreSigLongJmpCtxt"<<endl;
            drwrap_wrap(longjmpEntry, HoldLongJmpBuf, RestoreSigLongJmpCtxt);
        }
        app_pc sigsetjmpEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_SIGSETJMP);
        if (sigsetjmpEntry != NULL) {
            cerr<<"+++CCTLIB_STR_SIGSETJMP/CaptureSigSetJmpCtxt"<<endl;
            drwrap_wrap(sigsetjmpEntry, CaptureSigSetJmpCtxt, NULL);
        }
        app_pc siglongjmpEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_SIGLONGJMP);
        if (siglongjmpEntry != NULL) {
            cerr<<"+++CCTLIB_STR_SIGLONGJMP/HoldLongJmpBuf&RestoreSigLongJmpCtxt"<<endl;
            drwrap_wrap(siglongjmpEntry, HoldLongJmpBuf, RestoreSigLongJmpCtxt);
        }
    }

    // Look for unwinding related routines present in libc.so.x file only
    // For new DW2 exception handling, we need to reset the shadow stack to the
    // current handler in the following functions:
    // 1. _Unwind_Reason_Code _Unwind_RaiseException ( struct _Unwind_Exception
    // *exception_object );
    // 2. _Unwind_Reason_Code _Unwind_ForcedUnwind ( struct _Unwind_Exception
    // *exception_object, _Unwind_Stop_Fn stop, void *stop_parameter );
    // 3. void _Unwind_Resume (struct _Unwind_Exception *exception_object); ***
    // INSTALL UNCONDITIONALLY, SINCE THIS NEVER RETURNS ***
    // 4. _Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE _Unwind_Resume_or_Rethrow
    // (struct _Unwind_Exception *exc) *** I AM NOT IMPLEMENTING THIS UNTILL I HIT
    // A CODE THAT NEEDS IT ***

    // These functions call "uw_install_context" at the end of the routine just
    // before returning, which overwrite the return address. uw_install_context
    // itself is a static function inlined or macroed. So we would rely on the
    // more externally visible functions. There are multiple returns in these
    // (_Unwind_RaiseException, _Unwind_ForcedUnwind, _Unwind_Resume_or_Rethrow)
    // functions. Only if the return value is "_URC_INSTALL_CONTEXT" shall we
    // reset the shadow stack.
    if (strstr(dr_module_preferred_name(info), "libgcc_s.so")) {
        app_pc unwindSetIpEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_UNWIND_SETIP);
        if (unwindSetIpEntry != NULL) {
            cerr<<"+++CCTLIB_STR_UNWIND_SETIP/CaptureCallerThatCanHandleException"<<endl;
            drwrap_wrap(unwindSetIpEntry, CaptureCallerThatCanHandleException,
                        NULL);
        }

        app_pc unwindResumeEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_UNWIND_RESUME);
        if (unwindResumeEntry != NULL) {
            cerr<<"+++CCTLIB_STR_UNWIND_RESUME/SetCurBBNodeAfterException"<<endl;
            drwrap_wrap(unwindResumeEntry, NULL, SetCurBBNodeAfterException);
        }

        app_pc unwindRaiseExceptionEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_UNWIND_RAISEEXCEPTION);
        if (unwindRaiseExceptionEntry != NULL) {
            cerr<<"+++CCTLIB_STR_UNWIND_RAISEEXCEPTION/SetCurBBNodeAfterExceptionIfContextIsInstalled"<<endl;
            drwrap_wrap(unwindRaiseExceptionEntry, NULL,
                        SetCurBBNodeAfterExceptionIfContextIsInstalled);
        }

        app_pc unwindForceUnwindEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_UNWIND_FORCEUNWIND);
        if (unwindForceUnwindEntry != NULL) {
            cerr<<"+++CCTLIB_STR_UNWIND_FORCEUNWIND/SetCurBBNodeAfterExceptionIfContextIsInstalled"<<endl;
            drwrap_wrap(unwindForceUnwindEntry, NULL,
                        SetCurBBNodeAfterExceptionIfContextIsInstalled);
        }
    }
#ifdef DRCCTLIB_TEST
    if (strstr(dr_module_preferred_name(info), "sample1")){
        app_pc testWarpEntry = GetInternalFunctionEntry(info, "TestWarp");
        if (testWarpEntry != NULL) {
            cerr<<"+++TestWarp/DRCCTLibTestWarp"<<endl;
            drwrap_wrap(testWarpEntry, DRCCTLibTestWarp,
                        DRCCTLibTestWarpResult);
        }
        else {
            cerr<<"+++can not find TestWarp"<<endl;
        }
    }
#endif

    // if data centric is enabled, capture allocation routines
    if (g_GlobalState.doDataCentric) {
        app_pc mallocEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_MALLOC_FN_NAME);
        if (mallocEntry != NULL) {
            cerr<<"+++CCTLIB_STR_MALLOC_FN_NAME/CaptureMallocSize&CaptureMallocPointer"<<endl;
            drwrap_wrap(mallocEntry, CaptureMallocSize, CaptureMallocPointer);
        }

        app_pc callocEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_CALLOC_FN_NAME);
        if (callocEntry != NULL) {
            cerr<<"+++CCTLIB_STR_CALLOC_FN_NAME/CaptureMallocSize&CaptureMallocPointer"<<endl;
            drwrap_wrap(callocEntry, CaptureCallocSize, CaptureMallocPointer);
        }

        app_pc reallocEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_REALLOC_FN_NAME);
        if (reallocEntry != NULL) {
            cerr<<"+++CCTLIB_STR_REALLOC_FN_NAME/CaptureMallocSize&CaptureMallocPointer"<<endl;
            drwrap_wrap(reallocEntry, CaptureReallocSize, CaptureMallocPointer);
        }

        app_pc freeEntry =
            (app_pc)dr_get_proc_address(info->handle, CCTLIB_STR_FREE_FN_NAME);
        if (freeEntry != NULL) {
            cerr<<"+++CCTLIB_STR_FREE_FN_NAME/CaptureFree"<<endl;
            drwrap_wrap(freeEntry, CaptureFree, NULL);
        }
    }
}




// static inline instr_t *
// GetInstrptrFromContext(ContextHandle_t ctxtHndle)
// {
//     BBNode *bbNode = GetIPNodeFromContextHandle(ctxtHndle)->parentBBNode;
//     DR_ASSERT(ctxtHndle >= bbNode->childCtxtStartIdx);
//     DR_ASSERT(ctxtHndle < bbNode->childCtxtStartIdx + bbNode->nSlots);
//     // what is my slot id ?
//     uint32_t slotNo = ctxtHndle - bbNode->childCtxtStartIdx;

//     uint64_t *ipShadow = (uint64_t *)g_GlobalState.bbShadowMap[bbNode->bbKey];
//     return (instr_t *)ipShadow[slotNo];
// }

// static inline module_data_t *
// GetModuleptrFromContext(ContextHandle_t ctxtHndle)
// {
//     BBNode *bbNode = GetIPNodeFromContextHandle(ctxtHndle)->parentBBNode;
//     DR_ASSERT(ctxtHndle >= bbNode->childCtxtStartIdx);
//     DR_ASSERT(ctxtHndle < bbNode->childCtxtStartIdx + bbNode->nSlots);
//     uint64_t *ipShadow = (uint64_t *)g_GlobalState.bbShadowMap[bbNode->bbKey];

//     return (module_data_t *)ipShadow[-1];
// }

static size_t
GetPeakRSS()
{
    struct rusage rusage;
    getrusage(RUSAGE_SELF, &rusage);
    return (size_t)(rusage.ru_maxrss);
}

static void
PrintStats()
{
    dr_fprintf(g_GlobalState.logFile, "\nTotalCallPaths = %" PRIu64,
               g_GlobalState.curPreAllocatedContextBufferIndex);
    // Peak resource usage
    dr_fprintf(g_GlobalState.logFile, "\nPeakRSS = %zu", GetPeakRSS());
}

static dr_signal_action_t
OnSig(void *drcontext, dr_siginfo_t *siginfo)
{
    ThreadData *tData = CCTLibGetTLS(drcontext);

#ifdef CCTLIB_USE_STACK_STATUS
    SET_STACK_STATUS(tData->tlsStackStatus, CALL_INITIATED);
#else
    tData->tlsInitiatedCall = true;
#endif
    return DR_SIGNAL_DELIVER;
}

// This function is called when the application exits
static void
Fini()
{

    CCTLibCallbackFunc(g_GlobalState.callbackFuncs, CCTLibFiniCallback);

    if (g_GlobalState.doDataCentric) {
        drmgr_unregister_module_load_event(ComputeVarBounds);
        drmgr_unregister_module_unload_event(DeleteStaticVar);
    }

    drmgr_unregister_bb_instrumentation_event(CCTLibBBAnalysis);
    drmgr_unregister_module_load_event(CCTLibModuleAnalysis);

    drmgr_unregister_signal_event(OnSig);

    drmgr_unregister_thread_init_event(CCTLibThreadStart);
    drmgr_unregister_thread_exit_event(CCTLibThreadEnd);

    drmgr_unregister_tls_field(g_GlobalState.CCTLibTlsKey);
    dr_mutex_destroy(g_GlobalState.lock);
    drmgr_exit();
    drutil_exit();
    drwrap_exit();
    if (drsym_exit() != DRSYM_SUCCESS) {
        dr_log(NULL, DR_LOG_ALL, 1,
               "WARNING: unable to clean up symbol library\n");
    }

    PrintStats();

    dr_close_file(g_GlobalState.logFile);
}

// init logfile
static void
InitLogFile(file_t logFile)
{
    g_GlobalState.logFile = logFile;
}

// init IPNode store space; (Q) why mmap？share memory across threads
static void
InitBuffers()
{
    // prealloc IPNodeVec so that they all come from a continuous memory region.
    // IMPROVEME ... actually this can be as high as 24 GB since lower 3 bits are
    // always zero for pointers
    g_GlobalState.preAllocatedContextBuffer =
        (IPNode *)mmap(0, kMaxIPNodesNum * sizeof(IPNode), PROT_WRITE | PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // start from index 1 so that we can use 0 as empty key for the google hash
    // table
    g_GlobalState.curPreAllocatedContextBufferIndex = 1;
    // Init the string pool
    g_GlobalState.preAllocatedStringPool = (char *)mmap(
        0, kMaxStringPoolNodesNum * sizeof(char), PROT_WRITE | PROT_READ,
        MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    // start from index 1 so that we can use 0 as a special value
    g_GlobalState.curPreAllocatedStringPoolIndex = 1;
}

static void
InitUserCallback(CCTLibCallbackFuncStruct *callbackFuncs)
{
    g_GlobalState.callbackFuncs = callbackFuncs;
}

static void
InitTLSKey()
{
    // Obtain  a key for TLS storage.
    g_GlobalState.CCTLibTlsKey = drmgr_register_tls_field();
    DR_ASSERT(g_GlobalState.CCTLibTlsKey != -1);
}

static void
InitUserInstrumentInsCallback(IsInterestingInsFptr isInterestingIns,
                              CCTLibInstrumentInsCallback userCallback,
                              void *userCallbackArg)
{
    g_GlobalState.isInterestingIns = isInterestingIns;
    // remember user instrumentation callback
    g_GlobalState.userInstrumentationCallback = userCallback;
    g_GlobalState.userInstrumentationCallbackArg = userCallbackArg;
}

static void
PrintFullCallingContextInSitu(ContextHandle_t curCtxtHndle)
{
    int depth = 0;

    // Dont print if the depth is more than kMaxCCTPrintDepth since files
    // become too large
    while (IsValidContextHandle(curCtxtHndle) &&
           (depth++ < kMaxCCTPrintDepth)) {
        uint32_t threadId = -1;

        if (IsRootIPNode(curCtxtHndle, &threadId)) {
            // if the thread has a parent, recur over it.
            ContextHandle_t parentThreadCtxtHndl =
                CCTLibGetTLS(threadId)->tlsParentThreadCtxtHndl;
            dr_fprintf(g_GlobalState.logFile, "THREAD[" PFX "]_ROOT_CTXT", threadId);
            if (parentThreadCtxtHndl) {
                PrintFullCallingContextInSitu(parentThreadCtxtHndl);
            }
            break;
        } else {
            BBNode *bb =
                GetIPNodeFromContextHandle(curCtxtHndle)->parentBBNode;
            PrintContext(
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .first,
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .second);
            curCtxtHndle = bb->callerCtxtHndl;
            if (depth >= kMaxCCTPrintDepth) {
                dr_fprintf(g_GlobalState.logFile,
                           "Truncated call path (due to deep call chain)");
            }
        }
    }
}

static void
GetFullCallingContextInSitu(ContextHandle_t curCtxtHndle, vector<Context_t> &contextVec)
{
    int depth = 0;


    while (IsValidContextHandle(curCtxtHndle) &&
           (depth++ < kMaxCCTPathDepth)) {
        uint32_t threadId = -1;

        if (IsRootIPNode(curCtxtHndle, &threadId)) {
            // if the thread has a parent, recur over it.
            ContextHandle_t parentThreadCtxtHndl =
                CCTLibGetTLS(threadId)->tlsParentThreadCtxtHndl;
            /* could have use to_string() in c++11 */
            stringstream tCtxStr;
            tCtxStr << threadId;

            Context_t ctxt = { "THREAD[" + tCtxStr.str() + "]_ROOT_CTXT" /*functionName*/,
                               "" /*filePath */,
                               "" /*disassembly*/,
                               curCtxtHndle /*ctxtHandle*/,
                               0 /*lineNo*/,
                               0 /*ip*/ };
            contextVec.push_back(ctxt);

            if (parentThreadCtxtHndl) {
                GetFullCallingContextInSitu(parentThreadCtxtHndl, contextVec);
            }
            break;
        } else {
            BBNode *bb =
            GetIPNodeFromContextHandle(curCtxtHndle)->parentBBNode;
            Context_t ctxt = GetContext(
                curCtxtHndle,
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .first,
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .second);
            contextVec.push_back(ctxt);
            curCtxtHndle = bb->callerCtxtHndl;
            if (depth >= kMaxCCTPathDepth) {
                Context_t ctxt =
                    { "Truncated call path (due to deep call chain)" /*functionName*/,
                      "" /*filePath */,
                      "" /*disassembly*/,
                      curCtxtHndle /*ctxtHandle*/,
                      0 /*lineNo*/,
                      0 /*ip*/ };
                contextVec.push_back(ctxt);
            }
        }
    }
}

#ifndef __GNUC__
#    pragma endregion PrivateFunctionRegion
#endif

#ifndef __GNUC__
#    pragma region UnfinishFunctionRegion
#endif

#if 0
    // Visit all nodes of the splay tree of child traces.
    static void VisitAllNodesOfSplayTree(TraceSplay *node, FILE *const fp)
    {
        // process self
        SerializeCCTNode(node->value, fp);

        // visit left
        if (node->left)
            VisitAllNodesOfSplayTree(node->left, fp);

        // visit right
        if (node->right)
            VisitAllNodesOfSplayTree(node->right, fp);
    }

    static uint32_t NO_MORE_TRACE_NODES_IN_SPLAY_TREE = UINT_MAX;

    static void SerializeCCTNode(TraceNode *traceNode, FILE *const fp)
    {
        SerializedTraceNode serializedTraceNode = {traceNode->traceKey, traceNode->nSlots, traceNode->childCtxtStartIdx};
        fwrite(&serializedTraceNode, sizeof(SerializedTraceNode), 1, fp);

        // Iterate over all IPNodes
        IPNode *ipNode = GET_IPNODE_FROM_CONTEXT_HANDLE(traceNode->childCtxtStartIdx);
        for (uint32_t i = 0; i < traceNode->nSlots; i++)
        {
            if ((ipNode[i]).calleeTraceNodes == NULL)
            {
                fwrite(&NO_MORE_TRACE_NODES_IN_SPLAY_TREE, sizeof(NO_MORE_TRACE_NODES_IN_SPLAY_TREE), 1, fp);
            }
            else
            {
                // Iterate over all decendent TraceNode of traceNode->childCtxtStartIdx[i]
                VisitAllNodesOfSplayTree((ipNode[i]).calleeTraceNodes, fp);
                fwrite(&NO_MORE_TRACE_NODES_IN_SPLAY_TREE, sizeof(NO_MORE_TRACE_NODES_IN_SPLAY_TREE), 1, fp);
            }
        }
    }

    static TraceNode *DeserializeCCTNode(ContextHandle_t parentCtxtHndl, FILE *const fp)
    {
        uint32_t noMoreTrace;

        if (fread(&noMoreTrace, sizeof(noMoreTrace), 1, fp) != 1)
        {
            fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
            PIN_ExitProcess(-1);
        }

        if (noMoreTrace == NO_MORE_TRACE_NODES_IN_SPLAY_TREE)
        {
            return NULL;
        }

        // go back 4 bytes;
        fseek(fp, -sizeof(noMoreTrace), SEEK_CUR);
        SerializedTraceNode serializedTraceNode;

        if (fread(&serializedTraceNode, sizeof(SerializedTraceNode), 1, fp) != 1)
        {
            fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
            PIN_ExitProcess(-1);
        }

        TraceNode *traceNode = new TraceNode();
        traceNode->traceKey = serializedTraceNode.traceKey;
        traceNode->nSlots = serializedTraceNode.nSlots;
        traceNode->childCtxtStartIdx = serializedTraceNode.childCtxtStartIdx;
        traceNode->callerCtxtHndl = parentCtxtHndl;

        // Iterate over all IPNodes
        IPNode *ipNode = GET_IPNODE_FROM_CONTEXT_HANDLE(traceNode->childCtxtStartIdx);
        for (uint32_t i = 0; i < traceNode->nSlots; i++)
        {
            ipNode[i].parentTraceNode = traceNode;

            while (1)
            {
                TraceNode *childTrace = DeserializeCCTNode(traceNode->childCtxtStartIdx + i, fp);

                if (childTrace == NULL)
                    break;

                // add childTrace to the splay tree at traceNode->childCtxtStartIdx[i]
                TraceSplay *newNode = new TraceSplay();
                newNode->key = childTrace->traceKey;
                newNode->value = childTrace;

                // if no children
                IPNode *childIPNode = GET_IPNODE_FROM_CONTEXT_HANDLE(traceNode->childCtxtStartIdx + i);
                if (childIPNode->calleeTraceNodes == NULL)
                {
                    childIPNode->calleeTraceNodes = newNode;
                    newNode->left = NULL;
                    newNode->right = NULL;
                }
                else
                {
                    TraceSplay *found = splay(childIPNode->calleeTraceNodes, childTrace->traceKey);

                    if (childTrace->traceKey < found->key)
                    {
                        newNode->left = found->left;
                        newNode->right = found;
                        found->left = NULL;
                    }
                    else
                    { // addr > addr of found
                        newNode->left = found;
                        newNode->right = found->right;
                        found->right = NULL;
                    }
                }
            }
        }

        return traceNode;
    }

    static void SerializeAllCCTs()
    {
        for (uint32_t id = 0; id < GLOBAL_STATE.numThreads; id++)
        {
            ThreadData *tData = CCTLibGetTLS(id);
            std::stringstream cctMapFilePath;
            cctMapFilePath << GLOBAL_STATE.serializationDirectory << SERIALIZED_CCT_FILE_PREFIX << id << SERIALIZED_CCT_FILE_SUFFIX;
            FILE *fp = fopen(cctMapFilePath.str().c_str(), "wb");

            if (fp == NULL)
            {
                fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", cctMapFilePath.str().c_str(), __LINE__);
                PIN_ExitProcess(-1);
            }

            //record thread id
            uint32_t threadId = tData->tlsThreadId;
            fwrite(&threadId, sizeof(tData->tlsThreadId), 1, fp);
            // record path of the parent
            ContextHandle_t parentCtxtHndl = tData->tlsParentThreadCtxtHndl;
            fwrite(&parentCtxtHndl, sizeof(ContextHandle_t), 1, fp);
            SerializeCCTNode(tData->tlsRootTraceNode, fp);
            fclose(fp);
        }
    }

    // return the filenames of all files that have the specified extension
    // in the specified directory and all subdirectories
    static void GetAllFilesInDirWithExtn(const boostFS::path &root, const string &ext, vector<boostFS::path> &ret)
    {
        if (!boostFS::exists(root))
            return;

        if (boostFS::is_directory(root))
        {
            boostFS::directory_iterator it(root);
            boostFS::directory_iterator endit;

            while (it != endit)
            {
                if (boostFS::is_regular_file(*it) && it->path().extension() == ext)
                {
                    ret.push_back(boostFS::system_complete(it->path()));
                }

                ++it;
            }
        }
    }

    static void DeserializeAllCCTs()
    {
        // Get all files with
        vector<boostFS::path> serializedCCTFiles;
        GetAllFilesInDirWithExtn(g_GlobalState.serializationDirectory, SERIALIZED_CCT_FILE_EXTN, serializedCCTFiles);

        for (uint32_t id = 0; id < serializedCCTFiles.size(); id++)
        {
            std::stringstream cctMapFilePath;
            cctMapFilePath << serializedCCTFiles[id].native();
            //fprintf(stderr, "\nexists = %d\n",boostFS::exists(serializedCCTFiles[id]));
            FILE *fp = fopen(cctMapFilePath.str().c_str(), "rb");

            if (fp == NULL)
            {
                perror("fopen:");
                fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", cctMapFilePath.str().c_str(), __LINE__);
                PIN_ExitProcess(-1);
            }

            // Get thread id
            uint32_t threadId;

            if (fread(&threadId, sizeof(threadId), 1, fp) != 1)
            {
                fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
                PIN_ExitProcess(-1);
            }

            // record path of the parent
            ContextHandle_t parentCtxtHndl;

            if (fread(&parentCtxtHndl, sizeof(ContextHandle_t), 1, fp) != 1)
            {
                fprintf(stderr, "\n Failed to read at line %d\n", __LINE__);
                PIN_ExitProcess(-1);
            }

            TraceNode *rootTrace = DeserializeCCTNode(parentCtxtHndl, fp);
    #    ifndef NDEBUG
            // we should be at the end of file now
            uint8_t dummy;
            assert(fread(&dummy, sizeof(uint8_t), 1, fp) == 0);
    #    endif
            fclose(fp);
            // Add a ThreadData record to GLOBAL_STATE.deserializedCCTs
            ThreadData tData;
            //bzero(&tData, sizeof(tData));
            tData.tlsThreadId = threadId;
            tData.tlsParentThreadCtxtHndl = parentCtxtHndl;
            tData.tlsRootTraceNode = rootTrace;
            tData.tlsRootCtxtHndl = rootTrace->childCtxtStartIdx;
            GLOBAL_STATE.deserializedCCTs.push_back(tData);
            // Update the number of threads
            GLOBAL_STATE.numThreads++;
        }
    }

    static void DeserializeBBIps()
    {
        string traceMapFilePath = GLOBAL_STATE.serializationDirectory + SERIALIZED_SHADOW_TRACE_IP_FILE_SUFFIX;
        FILE *fp = fopen(traceMapFilePath.c_str(), "rb");

        if (fp == NULL)
        {
            fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", traceMapFilePath.c_str(), __LINE__);
            PIN_ExitProcess(-1);
        }

        unordered_map<uint32_t, void *>::iterator it;
        //fprintf(fp, "TraceKey:NumSlots:ModuleId:[ip1][ip2]..[ipNumSlots]");
        uint32_t traceKey;

        while (fread(&traceKey, sizeof(traceKey), 1, fp) == 1)
        {
            // read num entries
            ADDRINT numSlots;

            if (fread(&numSlots, sizeof(ADDRINT), 1, fp) != 1)
            {
                fprintf(stderr, "\n Failed to read in line %d. Exiting\n", __LINE__);
                PIN_ExitProcess(-1);
            }

            // allocate the shadow ips
            ADDRINT *array = (ADDRINT *)malloc((numSlots + 2) * sizeof(ADDRINT));
            array[0] = numSlots;

            // read remaining entires
            if (fread(&array[1], sizeof(ADDRINT), numSlots + 1, fp) != (numSlots + 1))
            {
                fprintf(stderr, "\n Failed to read in line %d. Exiting\n", __LINE__);
                PIN_ExitProcess(-1);
            }

            // Insert into the shadow map
            GLOBAL_STATE.traceShadowMap[traceKey] = (void *)(&array[2]); // 2 because first 2 entries are behind as in runtime.
        }

        fclose(fp);
    }

    static void DeserializeMouleInfo()
    {
        string moduleFilePath = GLOBAL_STATE.serializationDirectory + SERIALIZED_MODULE_MAP_SUFFIX;
        FILE *fp = fopen(moduleFilePath.c_str(), "r");

        if (fp == NULL)
        {
            perror("Error");
            fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", moduleFilePath.c_str(), __LINE__);
            PIN_ExitProcess(-1);
        }

        // read header and thow it away
        uint32_t moduleId;
        ADDRINT offset;
        char path[MAX_FILE_PATH];
        //fprintf(fp, "ModuleId\tModuleFile\tLoadOffset");
        fscanf(fp, "%s%s%s", path, path, path);

        while (EOF != fscanf(fp, "%u%s%p", &moduleId, path, (void **)&offset))
        {
            ModuleInfo minfo;
            minfo.moduleName = path;
            minfo.imgLoadOffset = offset;
            GLOBAL_STATE.ModuleInfoMap[moduleId] = minfo;
        }

        fclose(fp);
    }

    static void DeserializeMetadata(string directoryForSerializationFiles)
    {
        g_GlobalState.serializationDirectory = directoryForSerializationFiles;
        DeserializeAllCCTs();
        DeserializeBBIps();
        DeserializeMouleInfo();
    }

    static void SerializeMouleInfo()
    {
        string moduleFilePath = GLOBAL_STATE.serializationDirectory + SERIALIZED_MODULE_MAP_SUFFIX;
        FILE *fp = fopen(moduleFilePath.c_str(), "w");

        if (fp == NULL)
        {
            perror("Error:");
            fprintf(stderr, "\n Failed to open %s in line %d. Exiting\n", moduleFilePath.c_str(), __LINE__);
            PIN_ExitProcess(-1);
        }

        unordered_map<UINT32, ModuleInfo>::iterator it;
        fprintf(fp, "ModuleId\tModuleFile\tLoadOffset");

        for (it = GLOBAL_STATE.ModuleInfoMap.begin(); it != GLOBAL_STATE.ModuleInfoMap.end(); ++it)
        {
            fprintf(fp, "\n%u\t%s\t%p", it->first, (it->second).moduleName.c_str(), (void *)((it->second).imgLoadOffset));
        }

        fclose(fp);
    }

    DR_EXPORT
    int drcctlib_init_for_postmortem_analysis(file_t logFile, string serializedFilesDirectory)
    {

        g_GlobalState.usageMode = CCTLibUsageMode::PostmorteMode;
        // Initialize Symbols, we need them to report functions and lines
        if (drsym_init(0) != DRSYM_SUCCESS)
        {
            dr_log(NULL, DR_LOG_ALL, 1,
                "WARNING: unable to initialize symbol translation\n");
        }
        disassemble_set_syntax(DR_DISASM_INTEL);
        // Intialize
        InitBuffers();
        InitLogFile(logFile);
        InitTLSKey();

        DeserializeMetadata(serializedFilesDirectory);
        return 0;
    }

    DR_EXPORT
    void SerializeMetadata(string directoryForSerializationFiles)
    {
        if (directoryForSerializationFiles != "")
        {
            GLOBAL_STATE.serializationDirectory = directoryForSerializationFiles;
        }
        else
        {
            // construct one
            std::stringstream ss;
            char hostname[MAX_FILE_PATH];
            gethostname(hostname, MAX_FILE_PATH);
            pid_t pid = getpid();
            ss << CCTLIB_SERIALIZATION_DEFAULT_DIR_NAME << hostname << "-" << pid;
            GLOBAL_STATE.serializationDirectory = ss.str();
        }

        // create directory
        string cmd = "mkdir -p " + GLOBAL_STATE.serializationDirectory;
        int result = system(cmd.c_str());

        if (result != 0)
        {
            fprintf(stderr, "\n failed to call system()");
        }

        SerializeAllCCTs();
        SerializeMouleInfo();
        SerializeTraceIps();
    }

    DR_EXPORT
    bool IsSameSourceLine(ContextHandle_t ctxt1, ContextHandle_t ctxt2) // unfinish
    {
        if (ctxt1 == ctxt2)
            return true;

        ADDRINT ip1 = GetIPFromInfo(ctxt1);
        ADDRINT ip2 = GetIPFromInfo(ctxt2);

        if (ip1 == ip2)
            return true;

        uint32_t lineNo1, lineNo2;
        string filePath1, filePath2;

        PIN_GetSourceLocation(ip1, NULL, (INT32 *)&lineNo1, &filePath1);
        PIN_GetSourceLocation(ip2, NULL, (INT32 *)&lineNo2, &filePath2);

        if (filePath1 == filePath2 && lineNo1 == lineNo2)
            return true;
        return false;
    }

    static int // unfinish
    GetInstructionLength(uint32_t ip)
    {
        // Get the instruction in a string
        _decoded_inst_t xedd;
        /// XED state
        xed_decoded_inst_zero_set_mode(&xedd, &g_GlobalState.cct_xed_state);

        if (XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t *)(ip), 15))
        {
            return xed_decoded_inst_get_length(&xedd);
        }
        else
        {
            assert(0 && "failed to disassemble instruction");
            return 0;
        }
    }

    static void // unfinish
    GetNormalizedIpVectorClippedToMainOneAheadIp(vector<NormalizedIP> &ctxt,
                                                ContextHandle_t curCtxtHndle)
    {
        int depth = 0;
        // Dont print if the depth is more than kMaxCCTPrintDepth since
        // files become too large
        while (IsValidContextHandle(curCtxtHndle) &&
            (depth++ < kMaxCCTPrintDepth))
        {
            int threadId = 0;
            if ((threadId = IsRootIPNode(curCtxtHndle)) != NOT_ROOT_CTX)
            {
                // if the thread has a parent, recur over it.
                ContextHandle_t parentThreadCtxtHndl =
                    CCTLibGetTLS(threadId)->tlsParentThreadCtxtHndl;
                if (parentThreadCtxtHndl)
                {
                    fprintf(stderr,
                            "\n Multi threading not supported for this prototype feature. "
                            "Exiting\n");
                    dr_exit_process(-1);
                }
                break;
            }
            else
            {
                BBNode *bbNode =
                    GetIPNodeFromContextHandle(curCtxtHndle)->parentBBNode;
                // what is my slot id ?
                uint32_t slotNo = curCtxtHndle - bbNode->childCtxtStartIdx;

                uint32_t *ptr = (uint32_t *)g_GlobalState.bbShadowMap[bbNode->bbKey];
                UINT32 moduleId = ptr[-1]; // module id is stored one behind.
                uint32_t ip = ptr[slotNo];
                ip += GetInstructionLength(ip);
                NormalizedIP nip;
                nip.lm_id = moduleId;
                nip.offset = ip - g_GlobalState.ModuleInfoMap[moduleId].imgLoadOffset;
                ctxt.push_back(nip);

                // if we are already in main, we are done
                RTN r = RTN_FindByAddress(ip);
                if (RTN_Invalid() != r && RTN_Name(r) == "main")
                    return;
            }
            curCtxtHndle = GetIPNodeFromContextHandle(curCtxtHndle)
                            ->parentBBNode->callerCtxtHndl;
        }
    }

    DR_EXPORT
    void LogContexts(iostream &ios, ContextHandle_t ctxt1,
                    ContextHandle_t ctxt2) // unfinish
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

#endif

#ifndef __GNUC__
#    pragma endregion UnfinishFunctionRegion
#endif

#ifndef __GNUC__
#    pragma region CCTLibAPIFunctionRegion
#endif
/********** CCTLib APIs **********/
// API to get the handle for the current calling context

DR_EXPORT
ContextHandle_t
GetContextHandle(void *drcontext, const uint32_t slot)
{
    ThreadData *tData = CCTLibGetTLS(drcontext);
    // cerr<<"bbKey: "<<tData->tlsCurrentBBNode->bbKey<<" slot: "<<slot<<" nslots:
    // "<<tData->tlsCurrentBBNode->nSlots<<endl;
    DR_ASSERT(slot < tData->tlsCurrentBBNode->nSlots);
    return tData->tlsCurrentBBNode->childCtxtStartIdx + slot;
}

// API to get the handle for a data object
DR_EXPORT
DataHandle_t
GetDataObjectHandle(void *drcontext, void *address)
{
    DataHandle_t dataHandle;
    ThreadData *tData = CCTLibGetTLS(drcontext);
    // if it is a stack location, set so and return
    if (address > tData->tlsStackEnd && address < tData->tlsStackBase) {
        dataHandle.objectType = STACK_OBJECT;
        return dataHandle;
    }
#if __cplusplus > 199711L
    dataHandle = *(GetOrCreateShadowAddress<0>(g_DataCentricShadowMemory,
                                               (size_t)(uint64_t)address));
#else
    dataHandle = *(
        GetOrCreateShadowAddress_0(g_DataCentricShadowMemory, (size_t)(uint64_t)address));
#endif
    return dataHandle;
}

DR_EXPORT
char *
GetStringFromStringPool(const uint32_t index)
{
    return g_GlobalState.preAllocatedStringPool + index;
}

// API to print the calling context for input handle
DR_EXPORT
void
PrintFullCallingContext(ContextHandle_t handle)
{
    if (g_GlobalState.usageMode == PostmorteMode) {
        cerr << "unfinish PostmorteMode" << endl;
        dr_exit_process(-1);
    } else if (g_GlobalState.usageMode == CollectionMode) {
        PrintFullCallingContextInSitu(handle);
    }
}

DR_EXPORT
void
PrintContextMessage(ContextHandle_t curCtxtHndle)
{
    BBNode *bb = GetIPNodeFromContextHandle(curCtxtHndle)->parentBBNode;
    Context_t curContext = GetContext(
                curCtxtHndle,
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .first,
                g_GlobalState
                    .blockInterestInstrs[bb->bbKey][curCtxtHndle - bb->childCtxtStartIdx]
                    .second);
    dr_fprintf(g_GlobalState.logFile, "[%s](%s)%" PRIu64 ":\"(%" PRIu64 ")%s\"\n",
               curContext.filePath.c_str(), curContext.functionName.c_str(),
               curContext.lineNo, (uint64_t)curContext.ip,
               curContext.disassembly.c_str());
}

DR_EXPORT
void
PrintFullCallingContextIfIsAppIns(ContextHandle_t curCtxtHndle)
{
    if(IsAppInsContextHandle(curCtxtHndle)){
        dr_fprintf(g_GlobalState.logFile, "new context\n");
        PrintContextMessage(curCtxtHndle);
        vector<Context_t> contextVec;
        GetFullCallingContext(curCtxtHndle, contextVec);
        string line = "";
        for (uint32_t i = 0; i < contextVec.size(); i++) {
            line += "---";
            dr_fprintf(g_GlobalState.logFile, "[%u]%s[%s:%" PRIu64 "][%" PRIu64 "](%s)\"%s\"\n", i + 1,
                       line.c_str(), contextVec[i].functionName.c_str(),
                       contextVec[i].lineNo, (uint64_t)(contextVec[i].ip), contextVec[i].disassembly.c_str(),
                       contextVec[i].filePath.c_str());
        }
    }
}

DR_EXPORT
void
GetFullCallingContext(ContextHandle_t curCtxtHndle, vector<Context_t> &contextVec)
{
    if (g_GlobalState.usageMode == PostmorteMode) {
        cerr << "unfinish PostmorteMode" << endl;
        dr_exit_process(-1);
    } else if (g_GlobalState.usageMode == CollectionMode) {
        GetFullCallingContextInSitu(curCtxtHndle, contextVec);
    }
}

DR_EXPORT
bool
HaveSameCallerPrefix(ContextHandle_t ctxt1, ContextHandle_t ctxt2)
{
    if (ctxt1 == ctxt2)
        return true;
    ContextHandle_t t1 =
        GetIPNodeFromContextHandle(ctxt1)->parentBBNode->callerCtxtHndl;
    ContextHandle_t t2 =
        GetIPNodeFromContextHandle(ctxt2)->parentBBNode->callerCtxtHndl;
    return t1 == t2;
}

// initialize the tool, register instrumentation functions and call the target
// program.
DR_EXPORT
int
drcctlib_init(IsInterestingInsFptr isInterestingIns, file_t logFile,
              CCTLibInstrumentInsCallback userCallback, void *userCallbackArg,
              CCTLibCallbackFuncStruct *callbackFuncs, bool doDataCentric)
{
    dr_log(NULL, DR_LOG_ALL, 1, "start drcctlib_init\n");
    g_GlobalState.usageMode = CollectionMode;
    // Initialize DynamoRIO
    if (!drmgr_init() || !drutil_init() || !drwrap_init()) {
        DR_ASSERT(false);
    }
    if (drsym_init(0) != DRSYM_SUCCESS) {
        dr_log(NULL, DR_LOG_ALL, 1,
               "WARNING: unable to initialize symbol translation\n");
    }
    disassemble_set_syntax(DR_DISASM_INTEL);
    if(!drwrap_set_global_flags(DRWRAP_SAFE_READ_RETADDR) || !drwrap_set_global_flags(DRWRAP_SAFE_READ_ARGS)){
        DR_ASSERT(false);
    }

    // Intialize CCTLib
    InitBuffers();
    InitLogFile(logFile);
    InitUserCallback(callbackFuncs);
    InitTLSKey();
    InitUserInstrumentInsCallback(isInterestingIns, userCallback, userCallbackArg);
    InitDataCentric(doDataCentric);

    g_GlobalState.lock = dr_mutex_create();

    drmgr_register_signal_event(OnSig);

    drmgr_register_bb_instrumentation_event(CCTLibBBAnalysis, NULL,
                                            NULL);
    drmgr_register_module_load_event(CCTLibModuleAnalysis);

    drmgr_register_thread_init_event(CCTLibThreadStart);
    drmgr_register_thread_exit_event(CCTLibThreadEnd);

    dr_register_exit_event(Fini);

    CCTLibCallbackFunc(g_GlobalState.callbackFuncs, CCTLibInitCallback);

    return 0;
}

#ifndef __GNUC__
#    pragma endregion CCTLibAPIFunctionRegion
#endif