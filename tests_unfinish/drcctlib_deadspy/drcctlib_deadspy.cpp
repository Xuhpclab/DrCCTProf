#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <sys/resource.h>
#include <inttypes.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drcctlib.h"
#include "drwrap.h"
#include "drsyms.h"
#include "dr_tools.h"
#include "drutil.h"

#include "drreg.h"
#include "shadow_memory.h"

using namespace std;

// Assuming 128 byte line size.
#define CACHE_LINE_SIZE (128)
// #define MAX_SYM_RESULT 256

#define DECODE_DEAD(data) static_cast<ContextHandle_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<ContextHandle_t>( (data)  & 0x00000000ffffffff))

//++++++++ used for deadSpy  ++++++++/
ConcurrentShadowMemory<uint8_t, ContextHandle_t> shadowMem;
unordered_map<uint64,uint64> deadWrites;
uint64 totBytesWrite;
uint64 totBytesDead;
file_t gTraceFile;

struct RedundancyData {
    ContextHandle_t dead;
    ContextHandle_t kill;
    uint64 frequency;
};

struct DeadspyThreadData {
    //++++++++ data used for deadSpy
    //unordered_map<uint64,uint64> deadWrites;
    uint64 bytesWrite;
    uint64 bytesDead;
    //++++++++
} __attribute__((aligned));

struct DEADSPY_GLOBAL_STATE {
    file_t logFile;
    void *lock;
    // key for accessing TLS storage in the threads. initialized once in main()
    int DeadSpyTlsKey __attribute__((aligned(CACHE_LINE_SIZE))); // align to eliminate any false sharing with other  members
} static DS_GLOBAL_STATE;

static inline bool RedundancyCompare(struct RedundancyData first, struct RedundancyData second) {
    return first.frequency > second.frequency ? true:false;
}
#define MAX_REDUNDANT_CONTEXTS_TO_LOG 100
static void PrintRedundancyPairs(thread_id_t threadId, DeadspyThreadData* tdata) {
    vector<RedundancyData> tmpList;
    vector<RedundancyData>::iterator tmpIt;

    uint64_t grandTotalRedundantBytes = 0;
    dr_fprintf(gTraceFile, "*************** Dump Data from Thread %d ****************\n", threadId);

    for (unordered_map<uint64, uint64>::iterator it = deadWrites.begin(); it != deadWrites.end(); ++it) {
        ContextHandle_t dead = DECODE_DEAD((*it).first);
        ContextHandle_t kill = DECODE_KILL((*it).first);

        for(tmpIt = tmpList.begin();tmpIt != tmpList.end(); ++tmpIt){
            bool ct1 = false;
            if(dead == 0 || ((*tmpIt).dead) == 0){
                if(dead == 0 && ((*tmpIt).dead) == 0)
                    ct1 = true;
            }else{
                ct1 = dead == (*tmpIt).dead; //IsSameSourceLine(dead,(*tmpIt).dead);
            }
            bool ct2 = kill == (*tmpIt).kill; //IsSameSourceLine(kill,(*tmpIt).kill);
            if(ct1 && ct2){
                (*tmpIt).frequency += (*it).second;
                grandTotalRedundantBytes += (*it).second;
                break;
            }
        }
        if(tmpIt == tmpList.end()){
            RedundancyData tmp = { dead, kill, (*it).second};
            tmpList.push_back(tmp);
            grandTotalRedundantBytes += tmp.frequency;
        }
    }  

    std::sort(tmpList.begin(), tmpList.end(), RedundancyCompare);
    int cntxtNum = 0;
    for (vector<RedundancyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            dr_fprintf(gTraceFile, "\n======= (%f) %% ======\n", (*listIt).frequency * 100.0 / grandTotalRedundantBytes);
            if ((*listIt).dead == 0) {
                dr_fprintf(gTraceFile, "\n Prepopulated with  by OS\n");
            } else {
                PrintFullCallingContext((*listIt).dead);
            }
            dr_fprintf(gTraceFile, "\n---------------------Redundantly written by---------------------------\n");
            PrintFullCallingContext((*listIt).kill);
        }
        else {
            break;
        }
        cntxtNum++;
    }
}
//++++++++  ++++++++/

/*   The rest are dealing with dead write detection    */
#define IS_ACCESS_WITHIN_PAGE_BOUNDARY(accessAddr, accessLen)  (PAGE_OFFSET((accessAddr)) <= (PAGE_OFFSET_MASK - (accessLen)))
#define READ_ACCESS 0
#define WRITE_ACCESS 1
#define MAKE_CONTEXT_PAIR(a,b) (((uint64)(a) << 32) | ((uint64)(b)))

//---- read write representative ----//
#define READ_ACTION (0)

#define ONE_BYTE_WRITE_ACTION (0xff)
#define TWO_BYTE_WRITE_ACTION (0xffff)
#define FOUR_BYTE_WRITE_ACTION (0xffffffff)
#define EIGHT_BYTE_WRITE_ACTION (0xffffffffffffffff)

//---- add <key, freq> tuple to the dead map ----//
static inline void AddToDeadTable(uint64 key, uint value){
    DeadspyThreadData* tData = (DeadspyThreadData*)drmgr_get_tls_field(dr_get_current_drcontext(), DS_GLOBAL_STATE.DeadSpyTlsKey);
    deadWrites[key] += value;
    tData->bytesDead += value;
}

//---- loop body to update context, report redundancy ----//
template<int start, int end, int incr>
struct UnrolledLoop{
    //loop to update the context
    static __attribute__((always_inline)) void BodyUpdateCxt(ContextHandle_t * prevIP, const ContextHandle_t handle){
        prevIP[start] = handle;
        UnrolledLoop<start+incr,end,incr>::BodyUpdateCxt(prevIP,handle);
    }
    static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, uint8_t * prevType, const ContextHandle_t handle){
        if(prevType[start] == ONE_BYTE_WRITE_ACTION) AddToDeadTable(MAKE_CONTEXT_PAIR(prevIP[start],handle), 1);
        else prevType[start] = ONE_BYTE_WRITE_ACTION;
        prevIP[start] = handle;
        UnrolledLoop<start+incr, end, incr>::BodySamePage(prevIP, prevType, handle);
    }
    static __attribute__((always_inline)) void BodyStraddlePage(uint64 addr, const ContextHandle_t handle){
        tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = * (shadowMem.GetOrCreateShadowBaseAddress((uint64_t)addr+start));
        uint8_t* prevType = &(get<0>(t)[PAGE_OFFSET(((uint64_t)addr+start))]);
        ContextHandle_t * prevIP = &(get<1>(t)[PAGE_OFFSET(((uint64_t)addr+start))]);
   
        if(prevType[0] == ONE_BYTE_WRITE_ACTION) AddToDeadTable(MAKE_CONTEXT_PAIR(prevIP[0],handle), 1);
        else prevType[0] = ONE_BYTE_WRITE_ACTION;
        prevIP[0] = handle;
        UnrolledLoop<start+incr, end, incr>::BodyStraddlePage(addr, handle); 
    }
};
template<int end,  int incr>
struct UnrolledLoop<end , end , incr>{
    static __attribute__((always_inline)) void BodyUpdateCxt(ContextHandle_t * prevIP, const ContextHandle_t handle){}
    static __attribute__((always_inline)) void BodySamePage(ContextHandle_t * __restrict__ prevIP, uint8_t* prevType, const ContextHandle_t handle){}
    static __attribute__((always_inline)) void BodyStraddlePage(uint64_t addr, const ContextHandle_t handle){}
};

//---- loop body to check whether type or context is consistent ----//
template<int start, int end, int incr>
struct UnrolledConjunction{
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ prevIP){
        return (prevIP[0] == prevIP[start]) && UnrolledConjunction<start+incr, end, incr>:: BodyContextCheck(prevIP);
    }
};
template<int end,  int incr>
struct UnrolledConjunction<end , end , incr>{
    static __attribute__((always_inline)) bool BodyContextCheck(ContextHandle_t * __restrict__ prevIP){
        return true;
    }
};

//---- deadSpy analysis update read, write seperatly ----//
template<class T, uint AccessLen>
struct DeadSpyAnalysis{
    //on memory read, update access type, no need to update context
    static void OnMemRead(void* addr){

        tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = *(shadowMem.GetOrCreateShadowBaseAddress((uint64)addr));
        uint8_t* prevIP = &(get<0>(t)[PAGE_OFFSET(((uint64)addr))]);
        if(*((T*)prevIP) != READ_ACTION)
            *((T*)prevIP) = READ_ACTION;
    }
    static void OnMemWrite(void* addr, uint slot){
        DeadspyThreadData* tData = (DeadspyThreadData*)drmgr_get_tls_field(dr_get_current_drcontext(), DS_GLOBAL_STATE.DeadSpyTlsKey);
        tData->bytesWrite += AccessLen;
        const bool isAccessWithinPageBoundary = IS_ACCESS_WITHIN_PAGE_BOUNDARY( (uint64_t)addr, AccessLen);
        ContextHandle_t curCxt = GetContextHandle(dr_get_current_drcontext(), slot);
        if(isAccessWithinPageBoundary){
            tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = *(shadowMem.GetOrCreateShadowBaseAddress((uint64)addr));
            uint8_t* prevTypeIP = &(get<0>(t)[PAGE_OFFSET(((uint64)addr))]);
            ContextHandle_t * prevCxtIP = &(get<1>(t)[PAGE_OFFSET(((uint64)addr))]);
            T tmp = *(T*)prevTypeIP;

            if(UnrolledConjunction<0,AccessLen,1>::BodyContextCheck(prevCxtIP)){
                switch(AccessLen){
                    case 1: if(tmp == ONE_BYTE_WRITE_ACTION) AddToDeadTable(MAKE_CONTEXT_PAIR(prevCxtIP[0], curCxt), AccessLen); *(T*)prevTypeIP = (T)ONE_BYTE_WRITE_ACTION; break;
                    case 2: if(tmp == TWO_BYTE_WRITE_ACTION) AddToDeadTable(MAKE_CONTEXT_PAIR(prevCxtIP[0], curCxt), AccessLen); *(T*)prevTypeIP = (T)TWO_BYTE_WRITE_ACTION; break;
                    case 4: if(tmp == FOUR_BYTE_WRITE_ACTION) AddToDeadTable(MAKE_CONTEXT_PAIR(prevCxtIP[0], curCxt), AccessLen); *(T*)prevTypeIP = (T)FOUR_BYTE_WRITE_ACTION; break;
                    case 8: if(tmp == EIGHT_BYTE_WRITE_ACTION) AddToDeadTable(MAKE_CONTEXT_PAIR(prevCxtIP[0], curCxt), AccessLen); *(T*)prevTypeIP = (T)EIGHT_BYTE_WRITE_ACTION; break;
                }
                UnrolledLoop<0,AccessLen,1>::BodyUpdateCxt(prevCxtIP,curCxt);
            }else{
                UnrolledLoop<0,AccessLen,1>::BodySamePage(prevCxtIP,prevTypeIP,curCxt); 
            }
        }else{
            UnrolledLoop<0,AccessLen,1>::BodyStraddlePage((uint64)addr,curCxt);
        }
    }
};
static void OnLargeMemRead(void* addr, uint accessLen){
    tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = *(shadowMem.GetOrCreateShadowBaseAddress((uint64)addr));
    uint8_t* prevIP = &(get<0>(t)[PAGE_OFFSET(((uint64)addr))]);
    memset(prevIP, READ_ACTION, accessLen);
}
static void OnLargeMemWrite(void* addr, uint accessLen, uint slot){
    DeadspyThreadData* tData = (DeadspyThreadData*)drmgr_get_tls_field(dr_get_current_drcontext(), DS_GLOBAL_STATE.DeadSpyTlsKey);
    tData->bytesWrite += accessLen;
    ContextHandle_t curCxt = GetContextHandle(dr_get_current_drcontext(), slot);

    for(uint i=0; i<accessLen; ++i){
        tuple<uint8_t[SHADOW_PAGE_SIZE], ContextHandle_t[SHADOW_PAGE_SIZE]> &t = *(shadowMem.GetOrCreateShadowBaseAddress((uint64)addr+i));
        uint8_t* prevIP = &(get<0>(t)[PAGE_OFFSET(((uint64)addr+i))]);
        ContextHandle_t* prevCxt = &(get<1>(t)[PAGE_OFFSET(((uint64)addr+i))]);
        if(prevIP[0] == ONE_BYTE_WRITE_ACTION) AddToDeadTable(MAKE_CONTEXT_PAIR(prevCxt[0], curCxt), 1);
        else prevIP[0] = ONE_BYTE_WRITE_ACTION;
        prevCxt[0] = curCxt;
    }
}
#define HANDLE_WRITE_CASE(T,ACCESS_LEN) dr_insert_clean_call(drcontext, ilist, ins, (void *)DeadSpyAnalysis<T,(ACCESS_LEN)>::OnMemWrite, false, 2, opnd_create_reg(regAddr), OPND_CREATE_INT32(slot));
#define HANDLE_READ_CASE(T,ACCESS_LEN) dr_insert_clean_call(drcontext, ilist, ins, (void *)DeadSpyAnalysis<T,(ACCESS_LEN)>::OnMemRead, false, 1, opnd_create_reg(regAddr));
//fix this for ARM
#define HANDLE_LARGE_WRITE() dr_insert_clean_call(drcontext, ilist, ins, (void *)OnLargeMemWrite, false, 3, opnd_create_reg(regAddr), OPND_CREATE_INT32(size), OPND_CREATE_INT32(slot));
#define HANDLE_LARGE_READ() dr_insert_clean_call(drcontext, ilist, ins, (void *)OnLargeMemRead, false, 2, opnd_create_reg(regAddr), OPND_CREATE_INT32(size));

static void InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t* ins, opnd_t ref, bool write, uint slot) {
    //two scratch registers
    reg_id_t regPtr, regAddr;
    if(drreg_reserve_register(drcontext, ilist, ins, NULL, &regPtr) != DRREG_SUCCESS || drreg_reserve_register(drcontext, ilist, ins, NULL, &regAddr) != DRREG_SUCCESS) {
        DR_ASSERT(false);
        return;
    }
    //get memory read/write address, store in regAddr
    bool ok;
    ok = drutil_insert_get_mem_addr(drcontext,ilist,ins,ref,regAddr,regPtr);
    DR_ASSERT(ok);
    //get memory read/write size
    uint size = drutil_opnd_mem_size_in_bytes(ref, ins);

    if(write){
        switch(size){
            case 1: HANDLE_WRITE_CASE(uint8_t,1);break;
            case 2: HANDLE_WRITE_CASE(uint16_t,2);break;
            case 4: HANDLE_WRITE_CASE(uint32_t,4);break;
            case 8: HANDLE_WRITE_CASE(uint64_t,8);break;
            default: HANDLE_LARGE_WRITE();
        } 
    }else{ 
        switch(size){
            case 1: HANDLE_READ_CASE(uint8_t,1);break;
            case 2: HANDLE_READ_CASE(uint16_t,2);break;
            case 4: HANDLE_READ_CASE(uint32_t,4);break;
            case 8: HANDLE_READ_CASE(uint64_t,8);break;
            default: HANDLE_LARGE_READ();
        }
    }
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, ins, regAddr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, ins, regPtr) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

void InstrumentInsCallback(void *drcontext, instrlist_t *ilist, instr_t* ins, void * v, uint slot) {
    /*** deadSpy ***/
    //check memory reads
    for(int i = 0; i < instr_num_srcs(ins); ++i){
        if(opnd_is_memory_reference(instr_get_src(ins,i)))
            InstrumentMem(drcontext,ilist,ins,instr_get_src(ins,i), false, slot);
    }
    //check memory writes
    for(int i = 0; i < instr_num_dsts(ins); i++){
        if(opnd_is_memory_reference(instr_get_dst(ins,i)))
            InstrumentMem(drcontext,ilist,ins,instr_get_dst(ins,i), true, slot);
    }
    /*** end deadSpy ***/
}




void ClientInit(int argc,const char* argv[]) {
    char name[CCTLIB_N_MAX_FILE_PATH] = "client.out.";
    char* envPath = getenv("DR_CCTLIB_CLIENT_OUTPUT_FILE");
    
    if(envPath) {
        // assumes max of CCTLIB_N_MAX_FILE_PATH
        strcpy(name, envPath);
    }

    gethostname(name + strlen(name), CCTLIB_N_MAX_FILE_PATH - strlen(name));
    pid_t pid = getpid();
    sprintf(name + strlen(name), "%d", pid);
    cerr << "\n Creating log file at:" << name << "\n";
    gTraceFile = dr_open_file(name, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");

    for(int i = 0 ; i < argc; i++) {
        dr_fprintf(gTraceFile, "%s ", argv[i]);
    }

    dr_fprintf(gTraceFile, "\n");
}

void DrThreadStart(){
    
}

void DrThreadEnd(){

}

void DrDeadspyFini() {
    //++++ deadSpy data ++++//
    dr_fprintf(gTraceFile, "\nTotalBytesWrite = %" PRIu64, totBytesWrite);
    dr_fprintf(gTraceFile, "\nTotalBytesDead = %" PRIu64, totBytesDead);
    //++++ ++++//
    /***  deadSpy  ***/
    if(drreg_exit() != DRREG_SUCCESS) DR_ASSERT(false);
    /***  deadSpy  ***/
    dr_close_file(DS_GLOBAL_STATE.logFile);
}

void DrDeadspyInit(){
    /*** deadSpy ***/
    drreg_options_t ops = {sizeof(ops), 3, false};
    if(drreg_init(&ops) != DRREG_SUCCESS) DR_ASSERT(false);
    /*** end deadSpy ***/

    // Obtain  a key for TLS storage.
    DS_GLOBAL_STATE.DeadSpyTlsKey = drmgr_register_tls_field();
    DR_ASSERT(DS_GLOBAL_STATE.DeadSpyTlsKey != -1);

    DS_GLOBAL_STATE.lock = dr_mutex_create();
}


#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_deadspy'", "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    CCTLibCallbackFuncStruct* drCallbackFuncs = new CCTLibCallbackFuncStruct();
    drCallbackFuncs->initFunc = DrDeadspyInit;
    drCallbackFuncs->finiFunc = DrDeadspyFini;
    drCallbackFuncs->threadStartFunc = DrThreadStart;
    drCallbackFuncs->threadEndFunc = DrThreadEnd;
    drcctlib_init(INTERESTING_INS_MEMORY_ACCESS, gTraceFile, InstrumentInsCallback, 0, drCallbackFuncs);
}

#ifdef __cplusplus
}
#endif
