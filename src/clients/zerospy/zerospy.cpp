#include <unordered_map>
#include <vector>
#include <string>
#include <sys/stat.h>
#include <assert.h>
#include <algorithm>

// #define ZEROSPY_DEBUG
#define _WERROR

#ifdef TIMING
#include <time.h>
#include <math.h>
uint64_t get_miliseconds() {
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return spec.tv_sec*1000 + round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
}
#endif

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drcctlib.h"
#include "utils.h"

#define ENABLE_SAMPLING 1
#ifdef ENABLE_SAMPLING
// different frequency configurations:
//      Rate:   1/10, 1/100, 1/1000, 5/10, 5/100, 5/1000
//      Window: 1e6, 1e7, 1e8, 1e9, 1e10 
// Enumuration of RATEs
#define RATE_NUM 6
#define RATE_0 (0.5)
#define RATE_1 (0.1)
#define RATE_2 (0.05)
#define RATE_3 (0.01)
#define RATE_4 (0.005)
#define RATE_5 (0.001)
// RATE -> WINDOW_ENABLE mapping
#define RATE_0_WIN(WINDOW) ((int64_t)(RATE_0*WINDOW))
#define RATE_1_WIN(WINDOW) ((int64_t)(RATE_1*WINDOW))
#define RATE_2_WIN(WINDOW) ((int64_t)(RATE_2*WINDOW))
#define RATE_3_WIN(WINDOW) ((int64_t)(RATE_3*WINDOW))
#define RATE_4_WIN(WINDOW) ((int64_t)(RATE_4*WINDOW))
#define RATE_5_WIN(WINDOW) ((int64_t)(RATE_5*WINDOW))
// Enumuration of WINDOWs
#define WINDOW_NUM 5
#define WINDOW_0 (1000000)
#define WINDOW_1 (10000000)
#define WINDOW_2 (100000000)
#define WINDOW_3 (1000000000)
#define WINDOW_4 (10000000000)
#endif

// Client Options
#include "droption.h"
static droption_t<bool> op_enable_sampling
(DROPTION_SCOPE_CLIENT, "enable_sampling", 0, 0, 64, "Enable Bursty Sampling",
 "Enable bursty sampling for lower overhead with less profiling accuracy.");

static droption_t<bool> op_no_flush
(DROPTION_SCOPE_CLIENT, "no_flush", 0, 0, 64, "Disable code flushing of Bursty Sampling",
 "Disable code flushing of Bursty Sampling.");

static droption_t<bool> op_help
(DROPTION_SCOPE_CLIENT, "help", 0, 0, 64, "Show this help",
 "Show this help.");

static droption_t<int> op_rate
(DROPTION_SCOPE_CLIENT, "rate", 3, 0, RATE_NUM, "Sampling rate configuration of bursty sampling",
 "Sampling rate configuration of bursty sampling. Only available when sampling is enabled."
 "Only the following configurations are valid:\n"
 "\t0: 0.5\n"
 "\t1: 0.1\n"
 "\t2: 0.05\n"
 "\t3: 0.01\n"
 "\t4: 0.005\n"
 "\t5: 0.001\n");

const float conf2rate[RATE_NUM] = {
    RATE_0,
    RATE_1,
    RATE_2,
    RATE_3,
    RATE_4,
    RATE_5
};

static droption_t<int> op_window
(DROPTION_SCOPE_CLIENT, "window", 2, 0, WINDOW_NUM, "Window size configuration of sampling",
 "Window size of sampling. Only available when sampling is enabled."
 "Only the following configurations are valid:\n"
 "\t0: 1000000\n"
 "\t1: 10000000\n"
 "\t2: 100000000\n"
 "\t3: 1000000000\n"
 "\t4: 10000000000\n");

const uint64_t conf2window[WINDOW_NUM] = {
    WINDOW_0,
    WINDOW_1,
    WINDOW_2,
    WINDOW_3,
    WINDOW_4
};

using namespace std;

#define ZEROSPY_PRINTF(format, args...) \
    DRCCTLIB_PRINTF_TEMPLATE("zerospy", format, ##args)
#define ZEROSPY_EXIT_PROCESS(format, args...)                                           \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("zerospy", format, \
                                          ##args)
#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#endif

// We only interest in memory loads
bool
zerospy_filter_read_mem_access_instr(instr_t *instr)
{
    return instr_reads_memory(instr);
}

#define ZEROSPY_FILTER_READ_MEM_ACCESS_INSTR zerospy_filter_read_mem_access_instr

static string g_folder_name;
static int tls_idx;

struct INTRedLogs{
    uint64_t tot;
    uint64_t red;
    uint64_t fred; // full redundancy
    uint64_t redByteMap;
};

struct FPRedLogs{
    uint64_t fred; // full redundancy
    uint64_t ftot;
    uint64_t redByteMap;
    uint8_t AccessLen;
    uint8_t size;
};

#define MINSERT instrlist_meta_preinsert
#define DECODE_DEAD(data) static_cast<uint8_t>(((data)  & 0xffffffffffffffff) >> 32 )
#define DECODE_KILL(data) (static_cast<context_handle_t>( (data)  & 0x00000000ffffffff))
#define MAKE_CONTEXT_PAIR(a, b) (((uint64_t)(a) << 32) | ((uint64_t)(b)))
#define delta 0.01
#define MAX_REDUNDANT_CONTEXTS_TO_LOG (1000)
// maximum cct depth to print
#define MAX_DEPTH 10

// 1M
#define MAX_CLONE_INS 1048576
typedef struct _per_thread_t {
    unordered_map<uint64_t, INTRedLogs> *INTRedMap;
    unordered_map<uint64_t, FPRedLogs > *FPRedMap;
    file_t output_file;
#ifdef ENABLE_SAMPLING
    long long numIns;
    bool sampleFlag;
#endif
    vector<instr_t*> *instr_clones;
} per_thread_t;

file_t gFile;
static void *gLock;
#ifndef _WERROR
file_t fwarn;
bool warned=false;
#endif
#ifdef ZEROSPY_DEBUG
file_t gDebug;
#endif

// global metrics
uint64_t grandTotBytesLoad = 0;
uint64_t grandTotBytesRedLoad = 0;
uint64_t grandTotBytesApproxRedLoad = 0;

/*******************************************************************************************/
static inline void AddToRedTable(uint64_t key,  uint16_t value, uint64_t byteMap, uint16_t total, per_thread_t *pt) __attribute__((always_inline,flatten));
static inline void AddToRedTable(uint64_t key,  uint16_t value, uint64_t byteMap, uint16_t total, per_thread_t *pt) {
    unordered_map<uint64_t, INTRedLogs>::iterator it = pt->INTRedMap->find(key);
    if ( it  == pt->INTRedMap->end()) {
        INTRedLogs log;
        log.red = value;
        log.tot = total;
        log.fred= (value==total);
        log.redByteMap = byteMap;
        (*pt->INTRedMap)[key] = log;
    } else {
        it->second.red += value;
        it->second.tot += total;
        it->second.fred+= (value==total);
        it->second.redByteMap &= byteMap;
    }
}

static inline void AddToApproximateRedTable(uint64_t key, uint64_t byteMap, uint16_t total, uint16_t zeros, uint16_t nums, uint8_t size, per_thread_t *pt) __attribute__((always_inline,flatten));
static inline void AddToApproximateRedTable(uint64_t key, uint64_t byteMap, uint16_t total, uint16_t zeros, uint16_t nums, uint8_t size, per_thread_t *pt) {
    unordered_map<uint64_t, FPRedLogs>::iterator it = pt->FPRedMap->find(key);
    if ( it  == pt->FPRedMap->end()) {
        FPRedLogs log;
        log.fred= zeros;
        log.ftot= nums;
        log.redByteMap = byteMap;
        log.AccessLen = total;
        log.size = size;
        (*pt->FPRedMap)[key] = log;
    } else {
        it->second.fred+= zeros;
        it->second.ftot+= nums;
        it->second.redByteMap &= byteMap;
    }
}
/*******************************************************************************************/
// single floating point zero byte counter
// 32-bit float: |sign|exp|mantissa| = | 1 | 8 | 23 |
// the redmap of single floating point takes up 5 bits (1 bit sign, 1 bit exp, 3 bit mantissa)
#define SP_MAP_SIZE 5
inline __attribute__((always_inline)) uint64_t count_zero_bytemap_fp(void * addr) {
    register uint32_t xx = *((uint32_t*)addr);
    // reduce by bits until byte level
    // | 0 | x0x0 x0x0 | 0x0 x0x0 x0x0 x0x0 x0x0 x0x0 |
    xx = xx | ((xx>>1)&0xffbfffff);
    // | x | 00xx 00xx | 0xx 00xx 00xx 00xx 00xx 00xx |
    xx = xx | ((xx>>2)&0xffdfffff);
    // | x | 0000 xxxx | 000 xxxx 0000 xxxx 0000 xxxx |
    xx = xx | ((xx>>4)&0xfff7ffff);
    // now xx is byte level reduced, check if it is zero and mask the unused bits
    xx = (~xx) & 0x80810101;
    // narrowing
    xx = xx | (xx>>7) | (xx>>14) | (xx>>20) | (xx>>27);
    xx = xx & 0x1f;
    return xx;
}
inline __attribute__((always_inline)) bool hasRedundancy_fp(void * addr) {
    register uint32_t xx = *((uint32_t*)addr);
    return (xx & 0x007f0000)==0;
}
/*******************************************************************************************/
// double floating point zero byte counter
// 64-bit float: |sign|exp|mantissa| = | 1 | 11 | 52 |
// the redmap of single floating point takes up 10 bits (1 bit sign, 2 bit exp, 7 bit mantissa)
#define DP_MAP_SIZE 10
inline __attribute__((always_inline)) uint64_t count_zero_bytemap_dp(void * addr) {
    register uint64_t xx = (static_cast<uint64_t*>(addr))[0];
    // reduce by bits until byte level
    // | 0 | 0x0 x0x0 x0x0 | x0x0 x0x0_x0x0 x0x0_x0x0 x0x0_x0x0 x0x0_x0x0 x0x0_x0x0 x0x0_x0x0 |
    xx = xx | ((xx>>1)&(~0x4008000000000000LL));
    // | x | 0xx 00xx 00xx | 00xx 00xx_00xx 00xx_00xx 00xx_00xx 00xx_00xx 00xx_00xx 00xx_00xx |
    xx = xx | ((xx>>2)&(~0x200c000000000000LL));
    // | x | xxx 0000 xxxx | xxxx 0000_xxxx 0000_xxxx 0000_xxxx 0000_xxxx 0000_xxxx 0000_xxxx |
    xx = xx | ((xx>>4)&(~0x100f000000000000LL));
    // now xx is byte level reduced, check if it is zero and mask the unused bits
    xx = (~xx) & 0x9011010101010101LL;
    // narrowing
    register uint64_t m = xx & 0x1010101010101LL;
    m = m | (m>>7);
    m = m | (m>>14);
    m = m | (m>>28);
    m = m & 0x7f;
    xx = xx | (xx>>9) | (xx>>7);
    xx = (xx >> 45) & 0x380;
    xx = m | xx;
    return xx;
}
inline __attribute__((always_inline)) bool hasRedundancy_dp(void * addr) {
    register uint64_t xx = *((uint64_t*)addr);
    return (xx & 0x000f000000000000LL)==0;
}
/***************************************************************************************/
/*********************** floating point full redundancy functions **********************/
/***************************************************************************************/

#if __BYTE_ORDER == __BIG_ENDIAN
typedef union {
  float f;
  struct {
    uint32_t : 1;
    uint32_t value : 31;
  } vars;
} float_cast;

typedef union {
  double f;
  struct {
    uint64_t : 1;
    uint64_t value : 63;
  } vars;
} double_cast;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
typedef union {
  float f;
  struct {
    uint32_t value : 31;
    uint32_t : 1;
  } vars;
} float_cast;

typedef union {
  double f;
  struct {
    uint64_t value : 63;
    uint64_t : 1;
  } vars;
} double_cast;
#else
    #error Known Byte Order
#endif

template<int start, int end, int incr>
struct UnrolledConjunctionApprox{
    // if the mantisa is 0, the value of the double/float var must be 0
    static __attribute__((always_inline)) uint64_t BodyZeros(uint8_t* addr){
        if(incr==4)
            return ((*(reinterpret_cast<float_cast*>(&addr[start]))).vars.value==0) + (UnrolledConjunctionApprox<start+incr,end,incr>::BodyZeros(addr));
        else if(incr==8)
            return ((*(reinterpret_cast<double_cast*>(&addr[start]))).vars.value==0) + (UnrolledConjunctionApprox<start+incr,end,incr>::BodyZeros(addr));
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyRedMap(uint8_t* addr){
        if(incr==4)
            return count_zero_bytemap_fp((void*)(addr+start)) | (UnrolledConjunctionApprox<start+incr,end,incr>::BodyRedMap(addr)<<SP_MAP_SIZE);
        else if(incr==8)
            return count_zero_bytemap_dp((void*)(addr+start)) | (UnrolledConjunctionApprox<start+incr,end,incr>::BodyRedMap(addr)<<DP_MAP_SIZE);
        else
            assert(0 && "Not Supportted floating size! now only support for FP32 or FP64.");
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyHasRedundancy(uint8_t* addr){
        if(incr==4)
            return hasRedundancy_fp((void*)(addr+start)) || (UnrolledConjunctionApprox<start+incr,end,incr>::BodyHasRedundancy(addr));
        else if(incr==8)
            return hasRedundancy_dp((void*)(addr+start)) || (UnrolledConjunctionApprox<start+incr,end,incr>::BodyHasRedundancy(addr));
        else
            assert(0 && "Not Supportted floating size! now only support for FP32 or FP64.");
        return 0;
    }
};

template<int end,  int incr>
struct UnrolledConjunctionApprox<end , end , incr>{
    static __attribute__((always_inline)) uint64_t BodyZeros(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyRedMap(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyHasRedundancy(uint8_t* addr){
        return 0;
    }
};

/****************************************************************************************/
inline __attribute__((always_inline)) uint64_t count_zero_bytemap_int8(uint8_t * addr) {
    register uint8_t xx = *((uint8_t*)addr);
    // reduce by bits until byte level
    xx = xx | (xx>>1) | (xx>>2) | (xx>>3) | (xx>>4) | (xx>>5) | (xx>>6) | (xx>>7);
    // now xx is byte level reduced, check if it is zero and mask the unused bits
    xx = (~xx) & 0x1;
    return xx;
}
inline __attribute__((always_inline)) uint64_t count_zero_bytemap_int16(uint8_t * addr) {
    register uint16_t xx = *((uint16_t*)addr);
    // reduce by bits until byte level
    xx = xx | (xx>>1) | (xx>>2) | (xx>>3) | (xx>>4) | (xx>>5) | (xx>>6) | (xx>>7);
    // now xx is byte level reduced, check if it is zero and mask the unused bits
    xx = (~xx) & 0x101;
    // narrowing
    xx = xx | (xx>>7);
    xx = xx & 0x3;
    return xx;
}
inline __attribute__((always_inline)) uint64_t count_zero_bytemap_int32(uint8_t * addr) {
    register uint32_t xx = *((uint32_t*)addr);
    // reduce by bits until byte level
    xx = xx | (xx>>1) | (xx>>2) | (xx>>3) | (xx>>4) | (xx>>5) | (xx>>6) | (xx>>7);
    // now xx is byte level reduced, check if it is zero and mask the unused bits
    xx = (~xx) & 0x1010101;
    // narrowing
    xx = xx | (xx>>7);
    xx = xx | (xx>>14);
    xx = xx & 0xf;
    return xx;
}
inline __attribute__((always_inline)) uint64_t count_zero_bytemap_int64(uint8_t * addr) {
    register uint64_t xx = *((uint64_t*)addr);
    // reduce by bits until byte level
    xx = xx | (xx>>1) | (xx>>2) | (xx>>3) | (xx>>4) | (xx>>5) | (xx>>6) | (xx>>7);
    // now xx is byte level reduced, check if it is zero and mask the unused bits
    xx = (~xx) & 0x101010101010101LL;
    // narrowing
    xx = xx | (xx>>7);
    xx = xx | (xx>>14);
    xx = xx | (xx>>28);
    xx = xx & 0xff;
    return xx;
}

static const unsigned char BitCountTable4[] __attribute__ ((aligned(64))) = {
    0, 0, 1, 2
};

static const unsigned char BitCountTable8[] __attribute__ ((aligned(64))) = {
    0, 0, 0, 0, 1, 1, 2, 3
};

static const unsigned char BitCountTable16[] __attribute__ ((aligned(64))) = {
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 4
};

static const unsigned char BitCountTable256[] __attribute__ ((aligned(64))) = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 
    4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8
};

// accessLen & eleSize are size in bits
template<uint32_t AccessLen, uint32_t EleSize>
struct RedMapString {
    static __attribute__((always_inline)) string getIntRedMapString(uint64_t redmap) {
        // static_assert(AccessLen % EleSize == 0);
        string buff = 
            RedMapString<AccessLen-EleSize, EleSize>::getIntRedMapString(redmap>>(AccessLen-EleSize)) + 
            " , " + RedMapString<EleSize, EleSize>::getIntRedMapString(redmap);
        return buff;
    }
};

template<uint32_t AccessLen>
struct RedMapString <AccessLen, AccessLen> {
    static __attribute__((always_inline)) string getIntRedMapString(uint64_t redmap) {
        string buff = "";
        buff += ((redmap>>(AccessLen-1))&0x1) ? "00 " : "XX ";
        buff += RedMapString<AccessLen-1, AccessLen-1>::getIntRedMapString(redmap>>1);
        return buff;
    }
};

template<>
struct RedMapString <1, 1> {
    static __attribute__((always_inline)) string getIntRedMapString(uint64_t redmap) {
        return string((redmap&0x1) ? "00" : "XX");
    }
};

template<uint32_t n_exp, uint32_t n_man>
inline __attribute__((always_inline)) string __getFpRedMapString(uint64_t redmap) {
    string buff = "";
    const uint32_t signPos = n_exp + n_man;
    buff += RedMapString<1,1>::getIntRedMapString(redmap>>signPos) + " | ";
    buff += RedMapString<n_exp,n_exp>::getIntRedMapString(redmap>>n_man) + " | ";
    buff += RedMapString<n_man,n_man>::getIntRedMapString(redmap);
    return buff;
}

template<uint32_t n_exp, uint32_t n_man>
string getFpRedMapString(uint64_t redmap, uint64_t accessLen) {
    string buff = "";
    uint64_t newAccessLen = accessLen - (n_exp + n_man + 1);
    if(newAccessLen==0) {
        return __getFpRedMapString<n_exp,n_man>(redmap);
    } else {
        return getFpRedMapString<n_exp,n_man>(redmap>>newAccessLen, newAccessLen) + " , " + __getFpRedMapString<n_exp,n_man>(redmap);
    }
    return buff;
}

#define getFpRedMapString_SP(redmap, num) getFpRedMapString<1,3>(redmap, num*5)
#define getFpRedMapString_DP(redmap, num) getFpRedMapString<2,7>(redmap, num*10)

template<int start, int end, int incr>
struct UnrolledConjunction{
    // if the mantisa is 0, the value of the double/float var must be 0
    static __attribute__((always_inline)) uint64_t BodyRedNum(uint64_t rmap){
        // static_assert(start < end);
        if(incr==1)
            return ((start==0) ? (rmap&0x1) : ((rmap>>start)&0x1)) + (UnrolledConjunction<start+incr,end,incr>::BodyRedNum(rmap));
        else if(incr==2)
            return ((start==0) ? BitCountTable8[rmap&0x3] : BitCountTable8[(rmap>>start)&0x3]) + (UnrolledConjunction<start+incr,end,incr>::BodyRedNum(rmap));
        else if(incr==4)
            return ((start==0) ? BitCountTable16[rmap&0xf] : BitCountTable16[(rmap>>start)&0xf]) + (UnrolledConjunction<start+incr,end,incr>::BodyRedNum(rmap));
        else if(incr==8)
            return ((start==0) ? BitCountTable256[rmap&0xff] : BitCountTable256[(rmap>>start)&0xff]) + (UnrolledConjunction<start+incr,end,incr>::BodyRedNum(rmap));
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyRedMap(uint8_t* addr){
        // static_assert(start < end);
        if(incr==1)
            return count_zero_bytemap_int8(addr+start) | (UnrolledConjunction<start+incr,end,incr>::BodyRedMap(addr)<<1);
        else if(incr==2)
            return count_zero_bytemap_int16(addr+start) | (UnrolledConjunction<start+incr,end,incr>::BodyRedMap(addr)<<2);
        else if(incr==4)
            return count_zero_bytemap_int32(addr+start) | (UnrolledConjunction<start+incr,end,incr>::BodyRedMap(addr)<<4);
        else if(incr==8)
            return count_zero_bytemap_int64(addr+start) | (UnrolledConjunction<start+incr,end,incr>::BodyRedMap(addr)<<8);
        else
            assert(0 && "Not Supportted integer size! now only support for INT8, INT16, INT32 or INT64.");
        return 0;
    }
    static __attribute__((always_inline)) bool BodyHasRedundancy(uint8_t* addr){
        if(incr==1)
            return (addr[start]==0) || (UnrolledConjunction<start+incr,end,incr>::BodyHasRedundancy(addr));
        else if(incr==2)
            return (((*((uint16_t*)(&addr[start])))&0xff00)==0) || (UnrolledConjunction<start+incr,end,incr>::BodyRedMap(addr));
        else if(incr==4)
            return (((*((uint32_t*)(&addr[start])))&0xff000000)==0) || (UnrolledConjunction<start+incr,end,incr>::BodyRedMap(addr));
        else if(incr==8)
            return (((*((uint64_t*)(&addr[start])))&0xff00000000000000LL)==0) || (UnrolledConjunction<start+incr,end,incr>::BodyRedMap(addr));
        else
            assert(0 && "Not Supportted integer size! now only support for INT8, INT16, INT32 or INT64.");
        return 0;
    }
};

template<int end,  int incr>
struct UnrolledConjunction<end , end , incr>{
    static __attribute__((always_inline)) uint64_t BodyRedNum(uint64_t rmap){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyRedMap(uint8_t* addr){
        return 0;
    }
    static __attribute__((always_inline)) uint64_t BodyHasRedundancy(uint8_t* addr){
        return 0;
    }
};
/*******************************************************************************************/

#ifdef ENABLE_SAMPLING
template<int64_t WINDOW_ENABLE, int64_t WINDOW_DISABLE, bool sampleFlag>
struct BBSample {
    static void update_per_bb(uint instruction_count, app_pc src)
    {
        void *drcontext = dr_get_current_drcontext();
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        pt->numIns += instruction_count;
        if(pt->sampleFlag) {
            if(pt->numIns > WINDOW_ENABLE) {
                pt->sampleFlag = false;
            }
        } else {
            if(pt->numIns > WINDOW_DISABLE) {
                pt->sampleFlag = true;
                pt->numIns = 0;
            }
        }
        // If the sample flag is changed, flush the region and re-instrument
        if(pt->sampleFlag != sampleFlag) {
            dr_mcontext_t mcontext;
            mcontext.size = sizeof(mcontext);
            mcontext.flags = DR_MC_ALL;
            dr_flush_region(src, 1);
            dr_get_mcontext(drcontext, &mcontext);
            mcontext.pc = src;
            dr_redirect_execution(&mcontext);
        }
    }
};

void (*BBSampleTable[RATE_NUM][WINDOW_NUM][2])(uint, app_pc) = {
    {   {BBSample<RATE_0_WIN(WINDOW_0), WINDOW_0, false>::update_per_bb, BBSample<RATE_0_WIN(WINDOW_0), WINDOW_0, true>::update_per_bb},
        {BBSample<RATE_0_WIN(WINDOW_1), WINDOW_1, false>::update_per_bb, BBSample<RATE_0_WIN(WINDOW_1), WINDOW_1, true>::update_per_bb},
        {BBSample<RATE_0_WIN(WINDOW_2), WINDOW_2, false>::update_per_bb, BBSample<RATE_0_WIN(WINDOW_2), WINDOW_2, true>::update_per_bb},
        {BBSample<RATE_0_WIN(WINDOW_3), WINDOW_3, false>::update_per_bb, BBSample<RATE_0_WIN(WINDOW_3), WINDOW_3, true>::update_per_bb},
        {BBSample<RATE_0_WIN(WINDOW_4), WINDOW_4, false>::update_per_bb, BBSample<RATE_0_WIN(WINDOW_4), WINDOW_4, true>::update_per_bb},
    },
    {   {BBSample<RATE_1_WIN(WINDOW_0), WINDOW_0, false>::update_per_bb, BBSample<RATE_1_WIN(WINDOW_0), WINDOW_0, true>::update_per_bb},
        {BBSample<RATE_1_WIN(WINDOW_1), WINDOW_1, false>::update_per_bb, BBSample<RATE_1_WIN(WINDOW_1), WINDOW_1, true>::update_per_bb},
        {BBSample<RATE_1_WIN(WINDOW_2), WINDOW_2, false>::update_per_bb, BBSample<RATE_1_WIN(WINDOW_2), WINDOW_2, true>::update_per_bb},
        {BBSample<RATE_1_WIN(WINDOW_3), WINDOW_3, false>::update_per_bb, BBSample<RATE_1_WIN(WINDOW_3), WINDOW_3, true>::update_per_bb},
        {BBSample<RATE_1_WIN(WINDOW_4), WINDOW_4, false>::update_per_bb, BBSample<RATE_1_WIN(WINDOW_4), WINDOW_4, true>::update_per_bb},
    },
    {   {BBSample<RATE_2_WIN(WINDOW_0), WINDOW_0, false>::update_per_bb, BBSample<RATE_2_WIN(WINDOW_0), WINDOW_0, true>::update_per_bb},
        {BBSample<RATE_2_WIN(WINDOW_1), WINDOW_1, false>::update_per_bb, BBSample<RATE_2_WIN(WINDOW_1), WINDOW_1, true>::update_per_bb},
        {BBSample<RATE_2_WIN(WINDOW_2), WINDOW_2, false>::update_per_bb, BBSample<RATE_2_WIN(WINDOW_2), WINDOW_2, true>::update_per_bb},
        {BBSample<RATE_2_WIN(WINDOW_3), WINDOW_3, false>::update_per_bb, BBSample<RATE_2_WIN(WINDOW_3), WINDOW_3, true>::update_per_bb},
        {BBSample<RATE_2_WIN(WINDOW_4), WINDOW_4, false>::update_per_bb, BBSample<RATE_2_WIN(WINDOW_4), WINDOW_4, true>::update_per_bb},
    },
    {   {BBSample<RATE_3_WIN(WINDOW_0), WINDOW_0, false>::update_per_bb, BBSample<RATE_3_WIN(WINDOW_0), WINDOW_0, true>::update_per_bb},
        {BBSample<RATE_3_WIN(WINDOW_1), WINDOW_1, false>::update_per_bb, BBSample<RATE_3_WIN(WINDOW_1), WINDOW_1, true>::update_per_bb},
        {BBSample<RATE_3_WIN(WINDOW_2), WINDOW_2, false>::update_per_bb, BBSample<RATE_3_WIN(WINDOW_2), WINDOW_2, true>::update_per_bb},
        {BBSample<RATE_3_WIN(WINDOW_3), WINDOW_3, false>::update_per_bb, BBSample<RATE_3_WIN(WINDOW_3), WINDOW_3, true>::update_per_bb},
        {BBSample<RATE_3_WIN(WINDOW_4), WINDOW_4, false>::update_per_bb, BBSample<RATE_3_WIN(WINDOW_4), WINDOW_4, true>::update_per_bb},
    },
    {   {BBSample<RATE_4_WIN(WINDOW_0), WINDOW_0, false>::update_per_bb, BBSample<RATE_4_WIN(WINDOW_0), WINDOW_0, true>::update_per_bb},
        {BBSample<RATE_4_WIN(WINDOW_1), WINDOW_1, false>::update_per_bb, BBSample<RATE_4_WIN(WINDOW_1), WINDOW_1, true>::update_per_bb},
        {BBSample<RATE_4_WIN(WINDOW_2), WINDOW_2, false>::update_per_bb, BBSample<RATE_4_WIN(WINDOW_2), WINDOW_2, true>::update_per_bb},
        {BBSample<RATE_4_WIN(WINDOW_3), WINDOW_3, false>::update_per_bb, BBSample<RATE_4_WIN(WINDOW_3), WINDOW_3, true>::update_per_bb},
        {BBSample<RATE_4_WIN(WINDOW_4), WINDOW_4, false>::update_per_bb, BBSample<RATE_4_WIN(WINDOW_4), WINDOW_4, true>::update_per_bb},
    },
    {   {BBSample<RATE_5_WIN(WINDOW_0), WINDOW_0, false>::update_per_bb, BBSample<RATE_5_WIN(WINDOW_0), WINDOW_0, true>::update_per_bb},
        {BBSample<RATE_5_WIN(WINDOW_1), WINDOW_1, false>::update_per_bb, BBSample<RATE_5_WIN(WINDOW_1), WINDOW_1, true>::update_per_bb},
        {BBSample<RATE_5_WIN(WINDOW_2), WINDOW_2, false>::update_per_bb, BBSample<RATE_5_WIN(WINDOW_2), WINDOW_2, true>::update_per_bb},
        {BBSample<RATE_5_WIN(WINDOW_3), WINDOW_3, false>::update_per_bb, BBSample<RATE_5_WIN(WINDOW_3), WINDOW_3, true>::update_per_bb},
        {BBSample<RATE_5_WIN(WINDOW_4), WINDOW_4, false>::update_per_bb, BBSample<RATE_5_WIN(WINDOW_4), WINDOW_4, true>::update_per_bb},
    },
};
void (*BBSample_target[2])(uint, app_pc);

template<int64_t WINDOW_ENABLE, int64_t WINDOW_DISABLE>
struct BBSampleNoFlush {
    static void update_per_bb(uint instruction_count)
    {
        void *drcontext = dr_get_current_drcontext();
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        pt->numIns += instruction_count;
        if(pt->sampleFlag) {
            if(pt->numIns > WINDOW_ENABLE) {
                pt->sampleFlag = false;
            }
        } else {
            if(pt->numIns > WINDOW_DISABLE) {
                pt->sampleFlag = true;
                pt->numIns = 0;
            }
        }
    }
};

void (*BBSampleNoFlushTable[RATE_NUM][WINDOW_NUM])(uint) {
    {   BBSampleNoFlush<RATE_0_WIN(WINDOW_0), WINDOW_0>::update_per_bb,
        BBSampleNoFlush<RATE_0_WIN(WINDOW_1), WINDOW_1>::update_per_bb,
        BBSampleNoFlush<RATE_0_WIN(WINDOW_2), WINDOW_2>::update_per_bb,
        BBSampleNoFlush<RATE_0_WIN(WINDOW_3), WINDOW_3>::update_per_bb,
        BBSampleNoFlush<RATE_0_WIN(WINDOW_4), WINDOW_4>::update_per_bb,
    },
    {   BBSampleNoFlush<RATE_1_WIN(WINDOW_0), WINDOW_0>::update_per_bb,
        BBSampleNoFlush<RATE_1_WIN(WINDOW_1), WINDOW_1>::update_per_bb,
        BBSampleNoFlush<RATE_1_WIN(WINDOW_2), WINDOW_2>::update_per_bb,
        BBSampleNoFlush<RATE_1_WIN(WINDOW_3), WINDOW_3>::update_per_bb,
        BBSampleNoFlush<RATE_1_WIN(WINDOW_4), WINDOW_4>::update_per_bb,
    },
    {   BBSampleNoFlush<RATE_2_WIN(WINDOW_0), WINDOW_0>::update_per_bb,
        BBSampleNoFlush<RATE_2_WIN(WINDOW_1), WINDOW_1>::update_per_bb,
        BBSampleNoFlush<RATE_2_WIN(WINDOW_2), WINDOW_2>::update_per_bb,
        BBSampleNoFlush<RATE_2_WIN(WINDOW_3), WINDOW_3>::update_per_bb,
        BBSampleNoFlush<RATE_2_WIN(WINDOW_4), WINDOW_4>::update_per_bb,
    },
    {   BBSampleNoFlush<RATE_3_WIN(WINDOW_0), WINDOW_0>::update_per_bb,
        BBSampleNoFlush<RATE_3_WIN(WINDOW_1), WINDOW_1>::update_per_bb,
        BBSampleNoFlush<RATE_3_WIN(WINDOW_2), WINDOW_2>::update_per_bb,
        BBSampleNoFlush<RATE_3_WIN(WINDOW_3), WINDOW_3>::update_per_bb,
        BBSampleNoFlush<RATE_3_WIN(WINDOW_4), WINDOW_4>::update_per_bb,
    },
    {   BBSampleNoFlush<RATE_4_WIN(WINDOW_0), WINDOW_0>::update_per_bb,
        BBSampleNoFlush<RATE_4_WIN(WINDOW_1), WINDOW_1>::update_per_bb,
        BBSampleNoFlush<RATE_4_WIN(WINDOW_2), WINDOW_2>::update_per_bb,
        BBSampleNoFlush<RATE_4_WIN(WINDOW_3), WINDOW_3>::update_per_bb,
        BBSampleNoFlush<RATE_4_WIN(WINDOW_4), WINDOW_4>::update_per_bb,
    },
    {   BBSampleNoFlush<RATE_5_WIN(WINDOW_0), WINDOW_0>::update_per_bb,
        BBSampleNoFlush<RATE_5_WIN(WINDOW_1), WINDOW_1>::update_per_bb,
        BBSampleNoFlush<RATE_5_WIN(WINDOW_2), WINDOW_2>::update_per_bb,
        BBSampleNoFlush<RATE_5_WIN(WINDOW_3), WINDOW_3>::update_per_bb,
        BBSampleNoFlush<RATE_5_WIN(WINDOW_4), WINDOW_4>::update_per_bb,
    },
};
void (*BBSampleNoFlush_target)(uint);

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating, OUT void **user_data)
{
    uint num_instructions = 0;
    instr_t *instr;
    /* count the number of instructions in this block */
    for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr)) {
        num_instructions++;
    }
    /* insert clean call */
    if(op_no_flush.get_value()) {
        dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void *) BBSampleNoFlush_target, false, 1, 
                            OPND_CREATE_INT32(num_instructions));
    } else {
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        if(pt->sampleFlag) {
            dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void *) BBSample_target[1], false, 2, 
                            OPND_CREATE_INT32(num_instructions), 
                            OPND_CREATE_INTPTR(instr_get_app_pc(instrlist_first(bb))));
        } else {
            dr_insert_clean_call(drcontext, bb, instrlist_first(bb), (void *) BBSample_target[0], false, 2, 
                            OPND_CREATE_INT32(num_instructions), 
                            OPND_CREATE_INTPTR(instr_get_app_pc(instrlist_first(bb))));
        }
    }
    return DR_EMIT_DEFAULT;
}
#endif

template<class T, uint32_t AccessLen, uint32_t ElemLen, bool isApprox, bool enable_sampling>
struct ZeroSpyAnalysis{
#ifdef ZEROSPY_DEBUG
    static __attribute__((always_inline)) void CheckNByteValueAfterRead(int32_t slot, void* addr, instr_t* instr)
#else
    static __attribute__((always_inline)) void CheckNByteValueAfterRead(int32_t slot, void* addr)
#endif
    {
        void *drcontext = dr_get_current_drcontext();
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
#ifdef ENABLE_SAMPLING
        if(enable_sampling) {
            if(!pt->sampleFlag) {
                return ;
            }
        }
#endif
        context_handle_t curCtxtHandle = drcctlib_get_context_handle(drcontext, slot);
        uint8_t* bytes = static_cast<uint8_t*>(addr);
        if(isApprox) {
            bool hasRedundancy = UnrolledConjunctionApprox<0,AccessLen,sizeof(T)>::BodyHasRedundancy(bytes);
            if(hasRedundancy) {
                uint64_t map = UnrolledConjunctionApprox<0,AccessLen,sizeof(T)>::BodyRedMap(bytes);
                uint32_t zeros = UnrolledConjunctionApprox<0,AccessLen,sizeof(T)>::BodyZeros(bytes);        
                AddToApproximateRedTable((uint64_t)curCtxtHandle, map, AccessLen, zeros, AccessLen/sizeof(T), sizeof(T), pt);
            } else {
                AddToApproximateRedTable((uint64_t)curCtxtHandle, 0, AccessLen, 0, AccessLen/sizeof(T), sizeof(T), pt);
            }
        } else {
            bool hasRedundancy = UnrolledConjunction<0,AccessLen,sizeof(T)>::BodyHasRedundancy(bytes);
            if(hasRedundancy) {
                uint64_t redbyteMap = UnrolledConjunction<0,AccessLen,sizeof(T)>::BodyRedMap(bytes);
                uint32_t redbyteNum = UnrolledConjunction<0,AccessLen,sizeof(T)>::BodyRedNum(redbyteMap);
                AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(AccessLen, curCtxtHandle), redbyteNum, redbyteMap, AccessLen, pt);
            } else {
                AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(AccessLen, curCtxtHandle), 0, 0, AccessLen, pt);
            }
        }
    }
#ifdef X86
    static __attribute__((always_inline)) void CheckNByteValueAfterVGather(int32_t slot, instr_t* instr)
    {
        void *drcontext = dr_get_current_drcontext();
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
#ifdef ENABLE_SAMPLING
        if(enable_sampling) {
            if(!pt->sampleFlag) {
                return ;
            }
        }
#endif
        dr_mcontext_t mcontext;
        mcontext.size = sizeof(mcontext);
        mcontext.flags= DR_MC_ALL;
        DR_ASSERT(dr_get_mcontext(drcontext, &mcontext));
        context_handle_t curCtxtHandle = drcctlib_get_context_handle(drcontext, slot);
#ifdef DEBUG_VGATHER
        printf("\n^^ CheckNByteValueAfterVGather: ");
        disassemble(drcontext, instr_get_app_pc(instr), 1/*sdtout file desc*/);
        printf("\n");
#endif
        if(isApprox) {
            uint32_t zeros=0;
            uint64_t map=0;
            app_pc addr;
            bool is_write;
            uint32_t pos;
            for( int index=0; instr_compute_address_ex_pos(instr, &mcontext, index, &addr, &is_write, &pos); ++index ) {
                DR_ASSERT(!is_write);
                uint8_t* bytes = reinterpret_cast<uint8_t*>(addr);
                bool hasRedundancy = (bytes[sizeof(T)-1]==0);
                if(hasRedundancy) {
                    if(sizeof(T)==4) { map = map | (UnrolledConjunctionApprox<0,sizeof(T),sizeof(T)>::BodyRedMap(bytes) << (SP_MAP_SIZE * pos) ); }
                    else if(sizeof(T)==8) { map = map |  (UnrolledConjunctionApprox<0,sizeof(T),sizeof(T)>::BodyRedMap(bytes) << (DP_MAP_SIZE * pos) ); }
                    zeros = zeros + UnrolledConjunctionApprox<0,sizeof(T),sizeof(T)>::BodyZeros(bytes);
                }
            }
            AddToApproximateRedTable((uint64_t)curCtxtHandle, map, AccessLen, zeros, AccessLen/sizeof(T), sizeof(T), pt);
        } else {
            assert(0 && "VGather should be a floating point operation!");
        }
    }
#endif
};

template<bool enable_sampling>
static inline void CheckAfterLargeRead(int32_t slot, void* addr, uint32_t accessLen)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
#ifdef ENABLE_SAMPLING
    if(enable_sampling) {
        if(!pt->sampleFlag) {
            return ;
        }
    }
#endif
    context_handle_t curCtxtHandle = drcctlib_get_context_handle(drcontext, slot);
    uint8_t* bytes = static_cast<uint8_t*>(addr);
    // quick check whether the most significant byte of the read memory is redundant zero or not
    bool hasRedundancy = (bytes[accessLen-1]==0);
    if(hasRedundancy) {
        // calculate redmap by binary reduction with bitwise operation
        register uint64_t redbyteMap = 0;
        int restLen = accessLen;
        int index = 0;
        while(restLen>=8) {
            redbyteMap = (redbyteMap<<8) | count_zero_bytemap_int64(bytes+index);
            restLen -= 8;
            index += 8;
        }
        while(restLen>=4) {
            redbyteMap = (redbyteMap<<4) | count_zero_bytemap_int32(bytes+index);
            restLen -= 4;
            index += 4;
        }
        while(restLen>=2) {
            redbyteMap = (redbyteMap<<2) | count_zero_bytemap_int16(bytes+index);
            restLen -= 2;
            index += 2;
        }
        while(restLen>=1) {
            redbyteMap = (redbyteMap<<1) | count_zero_bytemap_int8(bytes+index);
            restLen -= 1;
            index += 1;
        }
        // now redmap is calculated, count for redundancy
        bool counting = true;
        register uint64_t redbytesNum = 0;
        restLen = accessLen;
        while(counting && restLen>=8) {
            restLen -= 8;
            register uint8_t t = BitCountTable256[(redbyteMap>>restLen)&0xff];
            redbytesNum += t;
            if(t!=8) {
                counting = false;
                break;
            }
        }
        while(counting && restLen>=4) {
            restLen -= 4;
            register uint8_t t = BitCountTable16[(redbyteMap>>restLen)&0xf];
            redbytesNum += t;
            if(t!=4) {
                counting = false;
                break;
            }
        }
        while(counting && restLen>=2) {
            restLen -= 2;
            register uint8_t t = BitCountTable4[(redbyteMap>>restLen)&0x3];
            redbytesNum += t;
            if(t!=8) {
                counting = false;
                break;
            }
        }
        // dont check here as this loop must execute only once
        while(counting && restLen>=1) {
            restLen -= 1;
            register uint8_t t = (redbyteMap>>restLen)&0x1;
            redbytesNum += t;
        }
        // report in RedTable
        AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(accessLen, curCtxtHandle), redbytesNum, redbyteMap, accessLen, pt);
    }
    else {
        AddToRedTable((uint64_t)MAKE_CONTEXT_PAIR(accessLen, curCtxtHandle), 0, 0, accessLen, pt);
    }
}
#ifdef ENABLE_SAMPLING
/* Check if sampling is enabled */
#ifdef ZEROSPY_DEBUG
#define HANDLE_CASE(T, ACCESS_LEN, ELEMENT_LEN, IS_APPROX) \
do { \
if(op_no_flush.get_value()) \
{ dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX), true/*sample*/>::CheckNByteValueAfterRead, false, 3, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg), OPND_CREATE_INTPTR(ins_clone)); } else \
{ dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX), false/* not */>::CheckNByteValueAfterRead, false, 3, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg), OPND_CREATE_INTPTR(ins_clone)); } } while(0)
#else
#define HANDLE_CASE(T, ACCESS_LEN, ELEMENT_LEN, IS_APPROX) \
do { \
if(op_no_flush.get_value()) \
{ dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX), true/*sample*/>::CheckNByteValueAfterRead, false, 2, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg)); } else \
{ dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX), false/* not */>::CheckNByteValueAfterRead, false, 2, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg)); } } while(0)

#endif

#define HANDLE_LARGE() \
do { \
if(op_no_flush.get_value()) \
{ dr_insert_clean_call(drcontext, bb, ins, (void *)CheckAfterLargeRead<true/*sample*/>, false, 3, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg), OPND_CREATE_CCT_INT(refSize)); } else \
{ dr_insert_clean_call(drcontext, bb, ins, (void *)CheckAfterLargeRead<false/* not */>, false, 3, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg), OPND_CREATE_CCT_INT(refSize)); } } while(0)

#ifdef X86
#define HANDLE_VGATHER(T, ACCESS_LEN, ELEMENT_LEN, IS_APPROX, ins) \
do { \
if(op_no_flush.get_value()) \
{ dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX), true/*sample*/>::CheckNByteValueAfterVGather, false, 2, OPND_CREATE_CCT_INT(slot), OPND_CREATE_INTPTR(ins_clone)); } else\
{ dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX), false/* not */>::CheckNByteValueAfterVGather, false, 2, OPND_CREATE_CCT_INT(slot), OPND_CREATE_INTPTR(ins_clone)); } } while (0)
#endif

#else
/* NO SAMPLING */
#ifdef ZEROSPY_DEBUG
#define HANDLE_CASE(T, ACCESS_LEN, ELEMENT_LEN, IS_APPROX) \
dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, false, 3, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg),  OPND_CREATE_INTPTR(instr_get_app_pc(ins)))
#else
#define HANDLE_CASE(T, ACCESS_LEN, ELEMENT_LEN, IS_APPROX) \
dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX)>::CheckNByteValueAfterRead, false, 2, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg))
#endif

#define HANDLE_LARGE() \
dr_insert_clean_call(drcontext, bb, ins, (void *)CheckAfterLargeRead, false, 3, OPND_CREATE_CCT_INT(slot), opnd_create_reg(addr_reg), OPND_CREATE_CCT_INT(refSize))

#ifdef X86
#define HANDLE_VGATHER(T, ACCESS_LEN, ELEMENT_LEN, IS_APPROX, ins) \
dr_insert_clean_call(drcontext, bb, ins, (void *)ZeroSpyAnalysis<T, (ACCESS_LEN), (ELEMENT_LEN), (IS_APPROX)>::CheckNByteValueAfterVGather, false, 2, OPND_CREATE_CCT_INT(slot), OPND_CREATE_INTPTR(ins_clone))
#endif
#endif /*ENABLE_SAMPLING*/

#include <signal.h>

struct ZerospyInstrument{
    static __attribute__((always_inline)) void InstrumentReadValueBeforeAndAfterLoading(void *drcontext, instrlist_t *bb, instr_t *ins, opnd_t opnd, reg_id_t addr_reg, int32_t slot)
    {
        uint32_t refSize = opnd_size_in_bytes(opnd_get_size(opnd));
        if (refSize==0) {
            // Something strange happened, so ignore it
            return ;
        }
#ifdef ZEROSPY_DEBUG
        per_thread_t *pt2 = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        instr_t* ins_clone = instr_clone(drcontext, ins);
        pt2->instr_clones->push_back(ins_clone);
            dr_mutex_lock(gLock);
            dr_fprintf(gDebug, "^^ INFO: Disassembled Instruction ^^^\n");
            dr_fprintf(gDebug, "ins=%p, ins_clone=%p\n", ins, ins_clone);
            disassemble(drcontext, instr_get_app_pc(ins), gDebug);
            disassemble(drcontext, instr_get_app_pc(ins_clone), gDebug);
            dr_fprintf(gDebug, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
            dr_mutex_unlock(gLock);
#endif
#ifdef ARM_CCTLIB
        // Currently, we cannot identify the difference between floating point operand 
        // and inter operand from instruction type (both is LD), so just ignore the fp
        if (false)
#else
        if (instr_is_floating(ins))
#endif
        {
            uint32_t operSize = FloatOperandSizeTable(ins, opnd);
            if(operSize>0) {
                switch(refSize) {
                    case 1:
                    case 2:
#ifdef _WERROR
                        dr_fprintf(STDOUT, "\nERROR: refSize for floating point instruction is too small: %u!\n", refSize);
                        dr_fprintf(STDOUT, "^^ Disassembled Instruction ^^^\n");
                        disassemble(drcontext, instr_get_app_pc(ins), STDOUT);
                        dr_fprintf(STDOUT, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                        fflush(stdout);
                        assert(0 && "memory read floating data with unexptected small size");
#else
                        dr_mutex_lock(gLock);
                        dr_fprintf(fwarn, "\nERROR: refSize for floating point instruction is too small: %u!\n", refSize);
                        dr_fprintf(fwarn, "^^ Disassembled Instruction ^^^\n");
                        disassemble(drcontext, instr_get_app_pc(ins), fwarn);
                        dr_fprintf(fwarn, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                        warned = true;
                        dr_mutex_unlock(gLock);
                        /* Do nothing, just report warning */
                        break;
#endif
                    case 4: HANDLE_CASE(float, 4, 4, true); break;
                    case 8: HANDLE_CASE(double, 8, 8, true); break;
                    case 10: HANDLE_CASE(uint8_t, 10, 1, true); break;
                    case 16: {
                        switch (operSize) {
                            case 4: HANDLE_CASE(float, 16, 4, true); break;
                            case 8: HANDLE_CASE(double, 16, 8, true); break;
                            default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                        }
                    }break;
                    case 32: {
                        switch (operSize) {
                            case 4: HANDLE_CASE(float, 32, 4, true); break;
                            case 8: HANDLE_CASE(double, 32, 8, true); break;
                            default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                        }
                    }break;
                    default: 
#ifdef _WERROR
                        dr_fprintf(STDOUT, "\nERROR: refSize for floating point instruction is too large: %u!\n", refSize);
                        dr_fprintf(STDOUT, "^^ Disassembled Instruction ^^^\n");
                        disassemble(drcontext, instr_get_app_pc(ins), STDOUT);
                        dr_fprintf(STDOUT, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                        fflush(stdout);
                        assert(0 && "unexpected large memory read\n"); break;
#else
                        dr_mutex_lock(gLock);
                        dr_fprintf(fwarn, "\nERROR: refSize for floating point instruction is too large: %d!\n", refSize);
                        dr_fprintf(fwarn, "^^ Disassembled Instruction ^^^\n");
                        disassemble(drcontext, instr_get_app_pc(ins), fwarn);
                        dr_fprintf(fwarn, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                        warned = true;
                        dr_mutex_unlock(gLock);
                        /* Do nothing, just report warning */
                        break;
#endif
                }
            }
        } else {
            switch(refSize) {
#ifdef SKIP_SMALLCASE
                // do nothing when access is small
                case 1: break;
                case 2: break;
#else
                case 1: HANDLE_CASE(uint8_t, 1, 1, false); break;
                case 2: HANDLE_CASE(uint16_t, 2, 2, false); break;
#endif
                case 4: HANDLE_CASE(uint32_t, 4, 4, false); break;
                case 8: HANDLE_CASE(uint64_t, 8, 8, false); break;
                    
                default: {
                    HANDLE_LARGE();
                }
            }
        }
    }
#ifdef X86
    static __attribute__((always_inline)) void InstrumentReadValueBeforeVGather(void *drcontext, instrlist_t *bb, instr_t *ins, int32_t slot){
        opnd_t opnd = instr_get_src(ins, 0);
        uint32_t operSize = FloatOperandSizeTable(ins, opnd); // VGather's second operand is the memory operand
        uint32_t refSize = opnd_size_in_bytes(opnd_get_size(instr_get_dst(ins, 0)));
        per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
        instr_t* ins_clone = instr_clone(drcontext, ins);
        pt->instr_clones->push_back(ins_clone);
        switch(refSize) {
            case 1:
            case 2: 
            case 4: 
            case 8: 
            case 10: 
#ifdef _WERROR
                    dr_fprintf(STDOUT, "\nERROR: refSize for floating point instruction is too small: %u!\n", refSize);
                    dr_fprintf(STDOUT, "^^ Disassembled Instruction ^^^\n");
                    disassemble(drcontext, instr_get_app_pc(ins), STDOUT);
                    dr_fprintf(STDOUT, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                    fflush(stdout);
                    assert(0 && "memory read floating data with unexptected small size");
#else
                    dr_mutex_lock(gLock);
                    dr_fprintf(fwarn, "\nERROR: refSize for floating point instruction is too small: %u!\n", refSize);
                    dr_fprintf(fwarn, "^^ Disassembled Instruction ^^^\n");
                    disassemble(drcontext, instr_get_app_pc(ins), fwarn);
                    dr_fprintf(fwarn, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                    warned = true;
                    dr_mutex_unlock(gLock);
                    /* Do nothing, just report warning */
                    break;
#endif
            case 16: {
                switch (operSize) {
                    case 4: HANDLE_VGATHER(float, 16, 4, true, ins); break;
                    case 8: HANDLE_VGATHER(double, 16, 8, true, ins); break;
                    default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                }
            }break;
            case 32: {
                switch (operSize) {
                    case 4: HANDLE_VGATHER(float, 32, 4, true, ins); break;
                    case 8: HANDLE_VGATHER(double, 32, 8, true, ins); break;
                    default: assert(0 && "handle large mem read with unexpected operand size\n"); break;
                }
            }break;
            default: 
#ifdef _WERROR
                    dr_fprintf(STDOUT, "\nERROR: refSize for floating point instruction is too large: %u!\n", refSize);
                    dr_fprintf(STDOUT, "^^ Disassembled Instruction ^^^\n");
                    disassemble(drcontext, instr_get_app_pc(ins), STDOUT);
                    dr_fprintf(STDOUT, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                    fflush(stdout);
                    assert(0 && "unexpected large memory read\n"); break;
#else
                    dr_mutex_lock(gLock);
                    dr_fprintf(fwarn, "\nERROR: refSize for floating point instruction is too large: %u!\n", refSize);
                    dr_fprintf(fwarn, "^^ Disassembled Instruction ^^^\n");
                    disassemble(drcontext, instr_get_app_pc(ins), fwarn);
                    dr_fprintf(fwarn, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
                    warned = true;
                    dr_mutex_unlock(gLock);
                    /* Do nothing, just report warning */
                    break;
#endif
        }
    }
#endif
};

static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref, int32_t slot)
{
    /* We need two scratch registers */
    reg_id_t reg1, reg2;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg1) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg2) != DRREG_SUCCESS) {
        ZEROSPY_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg1/*addr*/,
                                    reg2/*scratch*/)) {
#ifdef _WERROR
        dr_fprintf(STDERR, "\nERROR: drutil_insert_get_mem_addr failed!\n");
        dr_fprintf(STDERR, "^^ Disassembled Instruction ^^^\n");
        disassemble(drcontext, instr_get_app_pc(where), STDERR);
        dr_fprintf(STDERR, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
        ZEROSPY_EXIT_PROCESS("InstrumentMem drutil_insert_get_mem_addr failed!");
#else
        dr_mutex_lock(gLock);
        dr_fprintf(fwarn, "\nERROR: drutil_insert_get_mem_addr failed!\n");
        dr_fprintf(fwarn, "^^ Disassembled Instruction ^^^\n");
        disassemble(drcontext, instr_get_app_pc(where), fwarn);
        dr_fprintf(fwarn, "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
        warned = true;
        dr_mutex_unlock(gLock);
#endif
    } else {
        ZerospyInstrument::InstrumentReadValueBeforeAndAfterLoading(drcontext, ilist, where, ref, reg1, slot);
    }
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg1) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg2) != DRREG_SUCCESS) {
        ZEROSPY_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}

void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    // early return when code flush is enabled and not sampled
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if( op_enable_sampling.get_value() && 
       !op_no_flush.get_value() && 
       !pt->sampleFlag) {
           return;
    }
    // extract data from drcctprof's given message
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    // check if this instruction is actually our interest
    if(!instr_reads_memory(instr)) return;
    // If this instr is prefetch, the memory address is not guaranteed to be valid, and it may be also ignored by hardware
    // Besides, prefetch instructions are not the actual memory access instructions, so we also ignore them
    if(instr_is_prefetch(instr)) return;

    // store cct in tls filed
    // InstrumentIns(drcontext, bb, instr, slot);
#ifdef X86
    // gather may result in failure, need special care
    if(instr_is_gather(instr)) {
        // We use instr_compute_address_ex_pos to handle gather (with VSIB addressing)
#ifdef DEBUG
        printf("INFO: HANDLE vgather\n");
#endif
        ZerospyInstrument::InstrumentReadValueBeforeVGather(drcontext, bb, instr, slot);
        return ;
    }
#endif

    // Currently, we mark x87 control instructions handling FPU states are ignorable (not insterested)
    if(instr_is_ignorable(instr)) {
        return ;
    }
    
    int num_srcs = instr_num_srcs(instr);
    for(int i=0; i<num_srcs; ++i) {
        opnd_t opnd = instr_get_src(instr, i);
        if(opnd_is_memory_reference(opnd)) {
            InstrumentMem(drcontext, bb, instr, opnd, slot);
        }
    }
}

static void
ThreadOutputFileInit(per_thread_t *pt)
{
    int32_t id = drcctlib_get_thread_id();
    char name[MAXIMUM_PATH+1];
    name[MAXIMUM_PATH] = '\0';
    snprintf(name, MAXIMUM_PATH, "%s/thread-%d.topn.log", g_folder_name.c_str(), id);
    pt->output_file = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(pt->output_file != INVALID_FILE);
    if (op_enable_sampling.get_value()) {
        dr_fprintf(pt->output_file, "[ZEROSPY INFO] Sampling Enabled\n");
    }
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        ZEROSPY_EXIT_PROCESS("pt == NULL");
    }
    pt->INTRedMap = new unordered_map<uint64_t, INTRedLogs>();
    pt->FPRedMap = new unordered_map<uint64_t, FPRedLogs>();
    pt->instr_clones = new vector<instr_t*>();
    pt->INTRedMap->rehash(10000000);
    pt->FPRedMap->rehash(10000000);
#ifdef ENABLE_SAMPLING
    pt->numIns = 0;
    pt->sampleFlag = true;
#endif
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);
    ThreadOutputFileInit(pt);
}

/*******************************************************************/
/* Output functions */
struct RedundacyData {
    context_handle_t cntxt;
    uint64_t frequency;
    uint64_t all0freq;
    uint64_t ltot;
    uint64_t byteMap;
    uint8_t accessLen;
};

struct ApproxRedundacyData {
    context_handle_t cntxt;
    uint64_t all0freq;
    uint64_t ftot;
    uint64_t byteMap;
    uint8_t accessLen;
    uint8_t size;
};

static inline bool RedundacyCompare(const struct RedundacyData &first, const struct RedundacyData &second) {
    return first.frequency > second.frequency ? true : false;
}
static inline bool ApproxRedundacyCompare(const struct ApproxRedundacyData &first, const struct ApproxRedundacyData &second) {
    return first.all0freq > second.all0freq ? true : false;
}
//#define SKIP_SMALLACCESS
#ifdef SKIP_SMALLACCESS
#define LOGGING_THRESHOLD 100
#endif

#include <omp.h>

static uint64_t PrintRedundancyPairs(per_thread_t *pt, uint64_t threadBytesLoad, int threadId) {
    vector<RedundacyData> tmpList;
    vector<RedundacyData>::iterator tmpIt;

    file_t gTraceFile = pt->output_file;
    
    uint64_t grandTotalRedundantBytes = 0;
    tmpList.reserve(pt->INTRedMap->size());
    dr_fprintf(STDOUT, "Dumping INTEGER Redundancy Info... Total num : %lu\n",(uint64_t)pt->INTRedMap->size());
    fflush(stdout);
    dr_fprintf(gTraceFile, "\n--------------- Dumping INTEGER Redundancy Info ----------------\n");
    dr_fprintf(gTraceFile, "\n*************** Dump Data from Thread %d ****************\n", threadId);
    uint64_t count = 0; uint64_t rep = -1;
    for (unordered_map<uint64_t, INTRedLogs>::iterator it = pt->INTRedMap->begin(); it != pt->INTRedMap->end(); ++it) {
        ++count;
        if(100 * count / pt->INTRedMap->size()!=rep) {
            rep = 100 * count / pt->INTRedMap->size();
            dr_fprintf(STDOUT, "\r%lu%%  Finish",rep);
            fflush(stdout);
        }
        RedundacyData tmp = { DECODE_KILL((*it).first), (*it).second.red,(*it).second.fred,(*it).second.tot,(*it).second.redByteMap,DECODE_DEAD((*it).first)};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += tmp.frequency;
    }
    dr_fprintf(STDOUT, "\r100%%  Finish\n");
    fflush(stdout);
    
    __sync_fetch_and_add(&grandTotBytesRedLoad,grandTotalRedundantBytes);
    printf("Extracted Raw data, now sorting...\n");
    fflush(stdout);
    
    dr_fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / threadBytesLoad);
    dr_fprintf(gTraceFile, "\n INFO : Total redundant bytes = %f %% (%lu / %lu) \n", grandTotalRedundantBytes * 100.0 / threadBytesLoad, grandTotalRedundantBytes, threadBytesLoad);
    
    sort(tmpList.begin(), tmpList.end(), RedundacyCompare);
    printf("Sorted, Now generating reports...\n");
    fflush(stdout);
    int cntxtNum = 0;
    for (vector<RedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            dr_fprintf(gTraceFile, "\n\n======= (%f) %% of total Redundant, with local redundant %f %% (%lu Bytes / %lu Bytes) ======\n", 
                (*listIt).frequency * 100.0 / grandTotalRedundantBytes,
                (*listIt).frequency * 100.0 / (*listIt).ltot,
                (*listIt).frequency,(*listIt).ltot);
            dr_fprintf(gTraceFile, "\n\n======= with All Zero Redundant %f %% (%ld / %ld) ======\n", 
                (*listIt).all0freq * (*listIt).accessLen * 100.0 / (*listIt).ltot,
                (*listIt).all0freq,(*listIt).ltot/(*listIt).accessLen);
            dr_fprintf(gTraceFile, "\n======= Redundant byte map : [0] ");
            for(uint32_t i=0;i<(*listIt).accessLen;++i) {
                if((*listIt).byteMap & (1<<i)) {
                    dr_fprintf(gTraceFile, "00 ");
                }
                else {
                    dr_fprintf(gTraceFile, "XX ");
                }
            }
            dr_fprintf(gTraceFile, " [AccessLen=%d] =======\n", (*listIt).accessLen);
            dr_fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            drcctlib_print_backtrace(gTraceFile, (*listIt).cntxt, true, true, MAX_DEPTH);
        }
        else {
            break;
        }
        cntxtNum++;
    }
    dr_fprintf(gTraceFile, "\n------------ Dumping INTEGER Redundancy Info Finish -------------\n");
    printf("INTEGER Report dumped\n");
    fflush(stdout);
    return grandTotalRedundantBytes;
}

static uint64_t PrintApproximationRedundancyPairs(per_thread_t *pt, uint64_t threadBytesLoad, int threadId) {
    vector<ApproxRedundacyData> tmpList;
    vector<ApproxRedundacyData>::iterator tmpIt;
    tmpList.reserve(pt->FPRedMap->size());
    
    file_t gTraceFile = pt->output_file;

    uint64_t grandTotalRedundantBytes = 0;
    dr_fprintf(gTraceFile, "\n--------------- Dumping Approximation Redundancy Info ----------------\n");
    dr_fprintf(gTraceFile, "\n*************** Dump Data(delta=%.2f%%) from Thread %d ****************\n", delta*100,threadId);

    printf("Dumping INTEGER Redundancy Info... Total num : %lu\n", (uint64_t)pt->FPRedMap->size());
    uint64_t count = 0; uint64_t rep = -1;
    for (unordered_map<uint64_t, FPRedLogs>::iterator it = pt->FPRedMap->begin(); it != pt->FPRedMap->end(); ++it) {
        ++count;
        if(100 * count / pt->INTRedMap->size()!=rep) {
            rep = 100 * count / pt->INTRedMap->size();
            printf("\r%lu%%  Finish",rep);
            fflush(stdout);
        }
        ApproxRedundacyData tmp = { static_cast<context_handle_t>((*it).first), (*it).second.fred,(*it).second.ftot, (*it).second.redByteMap,(*it).second.AccessLen, (*it).second.size};
        tmpList.push_back(tmp);
        grandTotalRedundantBytes += (*it).second.fred * (*it).second.AccessLen;
    }
    printf("\r100%%  Finish\n");
    fflush(stdout);
    
    __sync_fetch_and_add(&grandTotBytesApproxRedLoad,grandTotalRedundantBytes);
    
    dr_fprintf(gTraceFile, "\n Total redundant bytes = %f %%\n", grandTotalRedundantBytes * 100.0 / threadBytesLoad);
    dr_fprintf(gTraceFile, "\n INFO : Total redundant bytes = %f %% (%lu / %lu) \n", grandTotalRedundantBytes * 100.0 / threadBytesLoad, grandTotalRedundantBytes, threadBytesLoad);
    
#ifdef ENABLE_FILTER_BEFORE_SORT
#define FILTER_THESHOLD 1000
    dr_fprintf(gTraceFile, "\n Filter out small redundancies according to the predefined threshold: %.2lf %%\n", 100.0/(double)FILTER_THESHOLD);
    // pt->FPRedMap->clear();
    vector<ApproxRedundacyData> tmpList2;
    tmpList2 = move(tmpList);
    tmpList.clear(); // make sure it is empty
    tmpList.reserve(tmpList2.size());
    for(tmpIt = tmpList2.begin();tmpIt != tmpList2.end(); ++tmpIt) {
        if(tmpIt->all0freq * FILTER_THESHOLD > tmpIt->ftot) {
            tmpList.push_back(*tmpIt);
        }
    }
    dr_fprintf(gTraceFile, " Remained Redundancies: %ld (%.2lf %%)\n", tmpList.size(), (double)tmpList.size()/(double)tmpList2.size());
    tmpList2.clear();
#undef FILTER_THRESHOLD
#endif

    sort(tmpList.begin(), tmpList.end(), ApproxRedundacyCompare);
    int cntxtNum = 0;
    for (vector<ApproxRedundacyData>::iterator listIt = tmpList.begin(); listIt != tmpList.end(); ++listIt) {
        if (cntxtNum < MAX_REDUNDANT_CONTEXTS_TO_LOG) {
            dr_fprintf(gTraceFile, "\n======= (%f) %% of total Redundant, with local redundant %f %% (%ld Zeros / %ld Reads) ======\n",
                (*listIt).all0freq * 100.0 / grandTotalRedundantBytes,
                (*listIt).all0freq * 100.0 / (*listIt).ftot,
                (*listIt).all0freq,(*listIt).ftot); 
            dr_fprintf(gTraceFile, "\n======= Redundant byte map : [mantiss | exponent | sign] ========\n");
            if((*listIt).size==4) {
                dr_fprintf(gTraceFile, "%s", getFpRedMapString_SP((*listIt).byteMap, (*listIt).accessLen/4).c_str());
            } else {
                dr_fprintf(gTraceFile, "%s", getFpRedMapString_DP((*listIt).byteMap, (*listIt).accessLen/8).c_str());
            }
            dr_fprintf(gTraceFile, "\n===== [AccessLen=%d, typesize=%d] =======\n", (*listIt).accessLen, (*listIt).size);
            dr_fprintf(gTraceFile, "\n---------------------Redundant load with---------------------------\n");
            drcctlib_print_backtrace(gTraceFile, (*listIt).cntxt, true, true, MAX_DEPTH);
        }
        else {
            break;
        }
        cntxtNum++;
    }
    dr_fprintf(gTraceFile, "\n------------ Dumping Approximation Redundancy Info Finish -------------\n");
    printf("Floating Point Report dumped\n");
    fflush(stdout);
    return grandTotalRedundantBytes;
}
/*******************************************************************/
static uint64_t getThreadByteLoad(per_thread_t *pt) {
    register uint64_t x = 0;
    for (unordered_map<uint64_t, INTRedLogs>::iterator it = pt->INTRedMap->begin(); it != pt->INTRedMap->end(); ++it) {
        x += (*it).second.tot;
    }
    for (unordered_map<uint64_t, FPRedLogs>::iterator it = pt->FPRedMap->begin(); it != pt->FPRedMap->end(); ++it) {
        x += (*it).second.ftot * (*it).second.AccessLen;
    }
    return x;
}
/*******************************************************************/
static void
ClientThreadEnd(void *drcontext)
{
#ifdef TIMING
    uint64_t time = get_miliseconds();
#endif
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    if (pt->INTRedMap->empty() && pt->FPRedMap->empty()) return;
    uint64_t threadByteLoad = getThreadByteLoad(pt);
    __sync_fetch_and_add(&grandTotBytesLoad,threadByteLoad);
    int threadId = drcctlib_get_thread_id();
    uint64_t threadRedByteLoadINT = PrintRedundancyPairs(pt, threadByteLoad, threadId);
    uint64_t threadRedByteLoadFP = PrintApproximationRedundancyPairs(pt, threadByteLoad, threadId);
#ifdef TIMING
    time = get_miliseconds() - time;
    printf("Thread %d: Time %lu ms for generating outputs\n", threadId, time);
#endif

    dr_mutex_lock(gLock);
    dr_fprintf(gFile, "\n#THREAD %d Redundant Read:", threadId);
    dr_fprintf(gFile, "\nTotalBytesLoad: %lu ",threadByteLoad);
    dr_fprintf(gFile, "\nRedundantBytesLoad: %lu %.2f",threadRedByteLoadINT, threadRedByteLoadINT * 100.0/threadByteLoad);
    dr_fprintf(gFile, "\nApproxRedundantBytesLoad: %lu %.2f\n",threadRedByteLoadFP, threadRedByteLoadFP * 100.0/threadByteLoad);
    dr_mutex_unlock(gLock);

    dr_close_file(pt->output_file);
    delete pt->INTRedMap;
    delete pt->FPRedMap;
    for(size_t i=0;i<pt->instr_clones->size();++i) {
        instr_destroy(drcontext, (*pt->instr_clones)[i]);
    }
    delete pt->instr_clones;
#ifdef DEBUG_REUSE
    dr_close_file(pt->log_file);
#endif
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    /* Parse options */
    std::string parse_err;
    int last_index;
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, &parse_err, &last_index)) {
        dr_fprintf(STDERR, "Usage error: %s", parse_err.c_str());
        dr_abort();
    }
    /* Creating result directories */
    pid_t pid = getpid();
    char buff[MAXIMUM_PATH];
#ifdef ARM_CCTLIB
    std::string name("arm-");
#else
    std::string name("x86-");
#endif
    gethostname(buff, MAXIMUM_PATH);
    name += std::string(buff);
    snprintf(buff, MAXIMUM_PATH, "-%d-zerospy", pid);
    name += std::string(buff);
    g_folder_name = name;
    mkdir(g_folder_name.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    dr_fprintf(STDOUT, "[ZEROSPY INFO] Profiling result directory: %s\n", g_folder_name.c_str());

    name += "/zerospy.log";
    gFile = dr_open_file(name.c_str(), DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gFile != INVALID_FILE);
    if (op_enable_sampling.get_value()) {
        dr_fprintf(STDOUT, "[ZEROSPY INFO] Sampling Enabled\n");
        dr_fprintf(gFile, "[ZEROSPY INFO] Sampling Enabled\n");
        if(op_no_flush.get_value()) {
            dr_fprintf(STDOUT, "[ZEROSPY INFO] Code flush is disabled.\n");
            dr_fprintf(gFile,  "[ZEROSPY INFO] Code flush is disabled.\n");
        }
        dr_fprintf(STDOUT, "[ZEROSPU INFO] Sampling Rate: %.3f, Window Size: %ld\n", conf2rate[op_rate.get_value()], conf2window[op_window.get_value()]);
        dr_fprintf(gFile,  "[ZEROSPU INFO] Sampling Rate: %.3f, Window Size: %ld\n", conf2rate[op_rate.get_value()], conf2window[op_window.get_value()]);
        BBSample_target[0] = BBSampleTable[op_rate.get_value()][op_window.get_value()][0];
        BBSample_target[1] = BBSampleTable[op_rate.get_value()][op_window.get_value()][1];
        BBSampleNoFlush_target = BBSampleNoFlushTable[op_rate.get_value()][op_window.get_value()];
    }
    if (op_help.get_value()) {
        dr_fprintf(STDOUT, "%s\n", droption_parser_t::usage_long(DROPTION_SCOPE_CLIENT).c_str());
        exit(1);
    }
#ifndef _WERROR
    std::string warn_fn(name);
    warn_fn += ".warn";
    fwarn = dr_open_file(warn_fn.c_str(), DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(fwarn != INVALID_FILE);
#endif
#ifdef ZEROSPY_DEBUG
    std::string debug_fn(name);
    debug_fn += ".debug";
    gDebug = dr_open_file(debug_fn.c_str(), DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gDebug != INVALID_FILE);
#endif
}

static void
ClientExit(void)
{
    dr_fprintf(gFile, "\n#Redundant Read:");
    dr_fprintf(gFile, "\nTotalBytesLoad: %lu \n",grandTotBytesLoad);
    dr_fprintf(gFile, "\nRedundantBytesLoad: %lu %.2f\n",grandTotBytesRedLoad, grandTotBytesRedLoad * 100.0/grandTotBytesLoad);
    dr_fprintf(gFile, "\nApproxRedundantBytesLoad: %lu %.2f\n",grandTotBytesApproxRedLoad, grandTotBytesApproxRedLoad * 100.0/grandTotBytesLoad);
#ifndef _WERROR
    if(warned) {
        dr_fprintf(gFile, "####################################\n");
        dr_fprintf(gFile, "WARNING: some unexpected instructions are ignored. Please check zerospy.log.warn for detail.\n");
        dr_fprintf(gFile, "####################################\n");
    }
#endif
    dr_close_file(gFile);
    dr_mutex_destroy(gLock);
    drcctlib_exit();
    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
#ifdef ENABLE_SAMPLING
        // must unregister event after client exit, or it will cause unexpected errors during execution
        ( op_enable_sampling.get_value() && !drmgr_unregister_bb_instrumentation_event(event_basic_block) ) ||
#endif
        !drmgr_unregister_tls_field(tls_idx)) {
        printf("ERROR: zerospy failed to unregister in ClientExit");
        fflush(stdout);
        exit(-1);
    }
    drutil_exit();
    drreg_exit();
    drmgr_exit();
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'zerospy'",
                       "http://dynamorio.org/issues");
    ClientInit(argc, argv);

    if (!drmgr_init()) {
        ZEROSPY_EXIT_PROCESS("ERROR: zerospy unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        ZEROSPY_EXIT_PROCESS("ERROR: zerospy unable to initialize drreg");
    }
    if (!drutil_init()) {
        ZEROSPY_EXIT_PROCESS("ERROR: zerospy unable to initialize drutil");
    }
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri),
                                         "zerospy-thread-init", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri),
                                         "zerispy-thread-exit", NULL, NULL,
                                         DRCCTLIB_THREAD_EVENT_PRI + 1 };
    if (
#ifdef ENABLE_SAMPLING
        // bb instrumentation event must be performed in analysis passes (as we don't change the application codes)
        ( op_enable_sampling.get_value() && !drmgr_register_bb_instrumentation_event(event_basic_block, NULL, NULL) ) ||
#endif
        !drmgr_register_thread_init_event_ex(ClientThreadStart, &thread_init_pri) ||
        !drmgr_register_thread_exit_event_ex(ClientThreadEnd, &thread_exit_pri) ) {
        ZEROSPY_EXIT_PROCESS("ERROR: zerospy unable to register events");
    }

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        ZEROSPY_EXIT_PROCESS("ERROR: zerospy drmgr_register_tls_field fail");
    }

    gLock = dr_mutex_create();

    drcctlib_init(ZEROSPY_FILTER_READ_MEM_ACCESS_INSTR, INVALID_FILE, InstrumentInsCallback, false/*do data centric*/);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif