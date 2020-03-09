// -*-Mode: C++;-*- // technically C99

// * BeginRiceCopyright *****************************************************
//
// $HeadURL: https://outreach.scidac.gov/svn/hpctoolkit/trunk/src/tool/hpcrun/sample-sources/papi.c $
// $Id: papi.c 4027 2012-11-28 20:03:03Z krentel $
//
// --------------------------------------------------------------------------
// Part of HPCToolkit (hpctoolkit.org)
//
// Information about sources of support for research and development of
// HPCToolkit is at 'hpctoolkit.org' and in 'README.Acknowledgments'.
// --------------------------------------------------------------------------
//
// Copyright ((c)) 2002-2014, Rice University
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of Rice University (RICE) nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// This software is provided by RICE and contributors "as is" and any
// express or implied warranties, including, but not limited to, the
// implied warranties of merchantability and fitness for a particular
// purpose are disclaimed. In no event shall RICE or contributors be
// liable for any direct, indirect, incidental, special, exemplary, or
// consequential damages (including, but not limited to, procurement of
// substitute goods or services; loss of use, data, or profits; or
// business interruption) however caused and on any theory of liability,
// whether in contract, strict liability, or tort (including negligence
// or otherwise) arising in any way out of the use of this software, even
// if advised of the possibility of such damage.
//
// ******************************************************* EndRiceCopyright *

//
// PAPI-C (Component PAPI) sample source simple oo interface
//


/******************************************************************************
 * system includes
 *****************************************************************************/
#include <alloca.h>
#include <assert.h>
#include <ctype.h>
#include <papi.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ucontext.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>
#include <linux/perf_event.h>
/******************************************************************************
 * libmonitor
 *****************************************************************************/
#include <monitor.h>

/******************************************************************************
 * local includes
 *****************************************************************************/

#include "simple_oo.h"
#include "sample_source_obj.h"
#include "common.h"
#include "papi-c-extended-info.h"

#include <hpcrun/hpcrun_options.h>
#include <hpcrun/hpcrun_stats.h>
#include <hpcrun/metrics.h>
#include <hpcrun/safe-sampling.h>
#include <hpcrun/sample_sources_registered.h>
#include <hpcrun/sample_event.h>
#include <hpcrun/thread_data.h>
#include <hpcrun/threadmgr.h>

#include <sample-sources/blame-shift/blame-shift.h>
#include <utilities/tokenize.h>
#include <messages/messages.h>
#include <lush/lush-backtrace.h>
#include <lib/prof-lean/hpcrun-fmt.h>

// necessary for breakpoints
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>
#include <xmmintrin.h>
#include <immintrin.h>

#include "datacentric.h"
#include <hpcrun/unwind/x86-family/x86-move.h>
#include <utilities/arch/context-pc.h>
#include "watchpoint_support.h"


#define DEADSPY_CLIENT
//#define REDSPY_CLIENT

int red_metric_id = -1;
int redApprox_metric_id = -1;
int load_metric_id = -1;
int dead_metric_id = -1;
int measured_metric_id = -1;
int latency_metric_id = -1;
int temporal_metric_id = -1;
int spatial_metric_id = -1;
int ww_metric_id = -1;
int rw_metric_id = -1;
int wr_metric_id = -1;
int last_pebs_metric_id = -1;


static dso_info_t * hpcrunLM;
static dso_info_t * libmonitorLM;


typedef struct WPStats{
    long numImpreciseSamples __attribute__((aligned(CACHE_LINE_SZ)));
    long numWatchpointsSet;
    char dummy[CACHE_LINE_SZ];
}WPStats_t;


__thread WPStats_t wpStats;

/******************************************************************************
 * macros
 *****************************************************************************/

#define OVERFLOW_MODE 0
#define WEIGHT_METRIC 0
#define DEFAULT_THRESHOLD  2000000L
#define APPROX_RATE (0.01)
#define WP_DEADSPY_EVENT_NAME "WP_DEADSPY"
#define WP_REDSPY_EVENT_NAME "WP_REDSPY"
#define WP_LOADSPY_EVENT_NAME "WP_LOADSPY"
#define WP_TEMPORAL_REUSE_EVENT_NAME "WP_TEMPORAL_REUSE"
#define WP_SPATIAL_REUSE_EVENT_NAME "WP_SPATIAL_REUSE"
#define WP_FALSE_SHARING_EVENT_NAME "WP_FALSE_SHARING"


typedef enum WP_CLIENT_ID{WP_DEADSPY, WP_REDSPY, WP_LOADSPY, WP_TEMPORAL_REUSE, WP_SPATIAL_REUSE, WP_FALSE_SHARING, WP_MAX_CLIENTS }WP_CLIENT_ID;

typedef struct WpClientConfig{
    WP_CLIENT_ID id;
    char * name;
    WatchPointUpCall_t wpCallback;
    ClientConfigOverrideCall_t configOverrideCallback;
}WpClientConfig_t;

typedef struct SharedData{
    volatile uint64_t counter __attribute__((aligned(CACHE_LINE_SZ)));
    uint64_t time __attribute__((aligned(CACHE_LINE_SZ)));
    int tid;
    WatchPointType wpType;
    AccessType accessType;
    void *address;
    cct_node_t * node;
    char dummy[CACHE_LINE_SZ];
} SharedData_t;

SharedData_t gSharedData = {.counter = 0, .time=0, .wpType = -1, .accessType = UNKNOWN, .tid = -1, .address = 0};
__thread int64_t lastTime = 0;
__thread uint64_t writtenBytes = 0;
__thread uint64_t loadedBytes = 0;
__thread uint64_t usedBytes = 0;
__thread uint64_t deadBytes = 0;
__thread uint64_t oldBytes = 0;
__thread uint64_t oldAppxBytes = 0;
__thread uint64_t newBytes = 0;
__thread uint64_t accessedIns = 0;
__thread uint64_t wwIns = 0;
__thread uint64_t wrIns = 0;
__thread uint64_t rwIns = 0;


/******************************************************************************
 * sample source registration
 *****************************************************************************/

// Support for derived events (proxy sampling).
static int derived[MAX_EVENTS];
static int some_overflow;


/******************************************************************************
 * method functions
 *****************************************************************************/

static WPUpCallTRetType DeadStoreWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt);
static WPUpCallTRetType RedStoreWPCallback(WatchPointInfo_t *wpi, int startOffseti, int safeAccessLen, WatchPointTrigger_t * wt);
static WPUpCallTRetType TemporalReuseWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt);
static WPUpCallTRetType SpatialReuseWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt);
static WPUpCallTRetType LoadLoadWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt);
static WPUpCallTRetType FalseSharingWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt);


static WpClientConfig_t wpClientConfig[] = {
    /**** DeadSpy ***/
    {
        .id = WP_DEADSPY,
        .name = WP_DEADSPY_EVENT_NAME,
        .wpCallback = DeadStoreWPCallback,
        .configOverrideCallback = NULL
    },
    /**** RedSpy ***/
    {
        .id = WP_REDSPY,
        .name = WP_REDSPY_EVENT_NAME,
        .wpCallback = RedStoreWPCallback,
        .configOverrideCallback = NULL
    },
    /**** LoadSpy ***/
    {
        .id = WP_LOADSPY,
        .name = WP_LOADSPY_EVENT_NAME,
        .wpCallback = RedStoreWPCallback /*LoadLoadWPCallback LOADSPY uses the same callback as REDSPY*/,
        .configOverrideCallback = NULL
    },
    /**** Temporal Reuse ***/
    {
        .id = WP_TEMPORAL_REUSE,
        .name = WP_TEMPORAL_REUSE_EVENT_NAME,
        .wpCallback = TemporalReuseWPCallback,
        .configOverrideCallback = TemporalReuseWPConfigOverride
    },
    /**** Spatial Reuse ***/
    {
        .id = WP_SPATIAL_REUSE,
        .name = WP_SPATIAL_REUSE_EVENT_NAME,
        .wpCallback = SpatialReuseWPCallback,
        .configOverrideCallback = SpatialReuseWPConfigOverride
    },
    /**** False Sharing ***/
    {
        .id = WP_FALSE_SHARING,
        .name = WP_FALSE_SHARING_EVENT_NAME,
        .wpCallback = FalseSharingWPCallback,
        .configOverrideCallback = FalseSharingWPConfigOverride
    }
};


static WpClientConfig_t * theWPConfig = NULL;

bool WatchpointClientActive(){
    return theWPConfig != NULL;
}

#define MAX_BLACK_LIST_ADDRESS (1024)

typedef struct BlackListAddressRange{
    void * startAddr;
    void * endAddr;
}BlackListAddressRange_t;
static BlackListAddressRange_t blackListAddresses [MAX_BLACK_LIST_ADDRESS];
static uint16_t numBlackListAddresses = 0;

static const char * blackListedModules[] = {"libmonitor.so", "libhpcrun.so", "libpfm.so", "libpapi.so", "anon_inode:[perf_event]"};
static const int  numblackListedModules = 5;
static spinlock_t blackListLock = SPINLOCK_UNLOCKED;



static void PopulateBlackListAddresses() {
    spinlock_lock(&blackListLock);
    if(numBlackListAddresses == 0) {
        FILE* loadmap = fopen("/proc/self/maps", "r");
        if (! loadmap) {
            EMSG("Could not open /proc/self/maps");
            return;
        }
        char linebuf[1024 + 1];
        char tmpname[PATH_MAX];
        char* addr = NULL;
        for(;;) {
            char* l = fgets(linebuf, sizeof(linebuf), loadmap);
            if (feof(loadmap)) break;
            char* save = NULL;
            const char delim[] = " \n";
            addr = strtok_r(l, delim, &save);
            char* perms = strtok_r(NULL, delim, &save);
            // skip 3 tokens
            for (int i=0; i < 3; i++) { (void) strtok_r(NULL, delim, &save);}
            char* name = strtok_r(NULL, delim, &save);
            realpath(name, tmpname);
            for(int i = 0; i < numblackListedModules; i++) {
                if (strstr(tmpname, blackListedModules[i])){
                    char* save = NULL;
                    const char dash[] = "-";
                    char* start_str = strtok_r(addr, dash, &save);
                    char* end_str   = strtok_r(NULL, dash, &save);
                    void *start = (void*) (uintptr_t) strtol(start_str, NULL, 16);
                    void *end   = (void*) (uintptr_t) strtol(end_str, NULL, 16);
                    blackListAddresses[numBlackListAddresses].startAddr = start;
                    blackListAddresses[numBlackListAddresses].endAddr = end;
                    numBlackListAddresses++;
                }
            }
        }
        fclose(loadmap);
        extern void * __tls_get_addr (void *);
        blackListAddresses[numBlackListAddresses].startAddr = ((void *)__tls_get_addr) - 1000 ;
        blackListAddresses[numBlackListAddresses].endAddr = ((void *)__tls_get_addr) + 1000;
        numBlackListAddresses++;
    }
    spinlock_unlock(&blackListLock);
}


static void
METHOD_FN(init)
{
    self->state = INIT;
}

static void
METHOD_FN(thread_init)
{
    TMSG(PAPI, "thread init");
    TMSG(PAPI, "thread init OK");
}

static void
METHOD_FN(thread_init_action)
{
    TMSG(PAPI, "register thread");
    wpStats.numImpreciseSamples = 0;
    wpStats.numWatchpointsSet = 0;
    WatchpointThreadInit(theWPConfig->wpCallback);
    TMSG(PAPI, "register thread ok");
}

static void
METHOD_FN(start)
{
    thread_data_t* td = hpcrun_get_thread_data();
    source_state_t my_state = TD_GET(ss_state)[self->sel_idx];
    
    if (my_state == START) {
        TMSG(PAPI,"*NOTE* PAPI start called when already in state START");
        return;
    }
    td->ss_state[self->sel_idx] = START;
}

static void ClientTermination(){
    // Cleanup the watchpoint data
    hpcrun_stats_num_samples_imprecise_inc(wpStats.numImpreciseSamples);
    hpcrun_stats_num_watchpoints_set_inc(wpStats.numWatchpointsSet);
    WatchpointThreadTerminate();
    
    switch (theWPConfig->id) {
        case WP_DEADSPY:
            hpcrun_stats_num_writtenBytes_inc(writtenBytes);
            hpcrun_stats_num_usedBytes_inc(usedBytes);
            hpcrun_stats_num_deadBytes_inc(deadBytes);
            
            break;
        case WP_REDSPY:
            hpcrun_stats_num_writtenBytes_inc(writtenBytes);
            hpcrun_stats_num_newBytes_inc(newBytes);
            hpcrun_stats_num_oldBytes_inc(oldBytes);
            hpcrun_stats_num_oldAppxBytes_inc(oldAppxBytes);

            
            break;
        case WP_LOADSPY:
            hpcrun_stats_num_loadedBytes_inc(loadedBytes);
            hpcrun_stats_num_newBytes_inc(newBytes);
            hpcrun_stats_num_oldBytes_inc(oldBytes);
            hpcrun_stats_num_oldAppxBytes_inc(oldAppxBytes);

            
            break;
        case WP_TEMPORAL_REUSE:
            break;
        case WP_SPATIAL_REUSE:
            break;
        case WP_FALSE_SHARING:
            hpcrun_stats_num_accessedIns_inc(accessedIns);
            hpcrun_stats_num_wwIns_inc(wwIns);
            hpcrun_stats_num_rwIns_inc(rwIns);
            hpcrun_stats_num_wrIns_inc(wrIns);
            break;
        default:
            break;
    }
    
    
    
    
}

static void
METHOD_FN(thread_fini_action)
{
    ClientTermination();
    TMSG(PAPI, "unregister thread");
}

static void
METHOD_FN(stop)
{
    int cidx;
    
    TMSG(PAPI, "stop");
    thread_data_t *td = hpcrun_get_thread_data();
    int nevents = self->evl.nevents;
    source_state_t my_state = TD_GET(ss_state)[self->sel_idx];
    
    if (my_state == STOP) {
        TMSG(PAPI,"*NOTE* PAPI stop called when already in state STOP");
        return;
    }
    
    if (my_state != START) {
        TMSG(PAPI,"*WARNING* PAPI stop called when not in state START");
        return;
    }
    TD_GET(ss_state)[self->sel_idx] = STOP;
}

static void
METHOD_FN(shutdown)
{
    TMSG(PAPI, "shutdown");
    
    METHOD_CALL(self, stop); // make sure stop has been called
    
    ClientTermination();
    self->state = UNINIT;
}

// Return true if PAPI recognizes the name, whether supported or not.
// We'll handle unsupported events later.
static bool
METHOD_FN(supports_event, const char *ev_str)
{
    for(int i = 0; i < WP_MAX_CLIENTS; i++) {
        if (hpcrun_ev_is(ev_str, wpClientConfig[i].name))
            return true;
    }
    return false;
}

static void
METHOD_FN(process_event_list, int lush_metrics)
{
    char* evlist = METHOD_CALL(self, get_event_str);
    char* event = start_tok(evlist);
    
    // only one supported
    for(int i = 0; i < WP_MAX_CLIENTS; i++) {
        if (hpcrun_ev_is(event, wpClientConfig[i].name)) {
            theWPConfig  = &wpClientConfig[i];
            break;
        }
    }
    
    wpStats.numImpreciseSamples = 0;
    wpStats.numWatchpointsSet = 0;
    WatchpointThreadInit(theWPConfig->wpCallback);
    
    if(theWPConfig->configOverrideCallback){
        theWPConfig->configOverrideCallback(0);
    }
    
    PopulateBlackListAddresses();
    
    switch (theWPConfig->id) {
        case WP_DEADSPY:
            measured_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(measured_metric_id, "BYTES_USED", MetricFlags_ValFmt_Int, 1, metric_property_none);
            dead_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(dead_metric_id, "BYTES_DEAD", MetricFlags_ValFmt_Int, 1, metric_property_none);
            last_pebs_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(last_pebs_metric_id, "IGNORE_ME", MetricFlags_ValFmt_Int, 1, metric_property_none);
            break;
            
        case WP_REDSPY:
        case WP_LOADSPY:
            assert(0);
            measured_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(measured_metric_id, "BYTES_NEW", MetricFlags_ValFmt_Int, 1, metric_property_none);
            red_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(red_metric_id, "BYTES_RED", MetricFlags_ValFmt_Int, 1, metric_property_none);
            redApprox_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(redApprox_metric_id, "BYTES_RED_APPROX", MetricFlags_ValFmt_Int, 1, metric_property_none);
            last_pebs_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(last_pebs_metric_id, "IGNORE_ME", MetricFlags_ValFmt_Int, 1, metric_property_none);
            break;

        case WP_TEMPORAL_REUSE:
            temporal_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(temporal_metric_id, "TEMPORAL", MetricFlags_ValFmt_Int, 1, metric_property_none);
            last_pebs_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(last_pebs_metric_id, "IGNORE_ME", MetricFlags_ValFmt_Int, 1, metric_property_none);
            break;
            
        case WP_SPATIAL_REUSE:
            spatial_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(spatial_metric_id, "SPATIAL", MetricFlags_ValFmt_Int, 1, metric_property_none);
            last_pebs_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(last_pebs_metric_id, "IGNORE_ME", MetricFlags_ValFmt_Int, 1, metric_property_none);
            break;
            
        case WP_FALSE_SHARING:
            measured_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(measured_metric_id, "MONITORED", MetricFlags_ValFmt_Int, 1, metric_property_none);
            
            ww_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(ww_metric_id, "WW_CONFLICT", MetricFlags_ValFmt_Int, 1, metric_property_none);
            
            rw_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(rw_metric_id, "RW_CONFLICT", MetricFlags_ValFmt_Int, 1, metric_property_none);
            
            wr_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(wr_metric_id, "WR_CONFLICT", MetricFlags_ValFmt_Int, 1, metric_property_none);

            last_pebs_metric_id = hpcrun_new_metric();
            hpcrun_set_metric_info_and_period(last_pebs_metric_id, "IGNORE_ME", MetricFlags_ValFmt_Int, 1, metric_property_none);
            
            break;
            
        default:
            break;
    }
    
    
    
    
    



}

static void
METHOD_FN(gen_event_set, int lush_metrics)
{
}

static void
METHOD_FN(display_events)
{
    printf("===========================================================================\n");
    printf("Watchpoint events\n");
    printf("---------------------------------------------------------------------------\n");
    printf("%s\n", WP_DEADSPY_EVENT_NAME);
    printf("---------------------------------------------------------------------------\n");
    printf("%s\n", WP_REDSPY_EVENT_NAME);
    printf("---------------------------------------------------------------------------\n");
    printf("%s\n", WP_LOADSPY_EVENT_NAME);
    printf("---------------------------------------------------------------------------\n");
    printf("%s\n", WP_TEMPORAL_REUSE_EVENT_NAME);
    printf("---------------------------------------------------------------------------\n");
    printf("%s\n", WP_SPATIAL_REUSE_EVENT_NAME);
    printf("---------------------------------------------------------------------------\n");
    printf("%s\n", WP_FALSE_SHARING_EVENT_NAME);
    printf("===========================================================================\n");
    printf("\n");
}


/***************************************************************************
 * object
 ***************************************************************************/

#define ss_name witch
#define ss_cls SS_HARDWARE

#include "ss_obj.h"

// **************************************************************************
// * public operations
// **************************************************************************

/******************************************************************************
 * private operations
 *****************************************************************************/

static void KILLED_BY(void) {}
static void USED_BY(void) {}
static void NEW_VAL_BY(void) {}


static void TEPORALLY_REUSED_BY(void) {}

static void SPATIALLY_REUSED_BY(void) {}

static void WW_PING_PONG(void) {}
static void WR_PING_PONG(void) {}
static void RW_PING_PONG(void) {}


static inline uint64_t GetWeightedMetricDiffAndReset(cct_node_t * ctxtNode, int pebsMetricId, int catchUpMetricId){
    assert(ctxtNode);
    metric_set_t* set = hpcrun_get_metric_set(ctxtNode);
    cct_metric_data_t diffWithPeriod;
    cct_metric_data_t diff;
    hpcrun_get_weighted_metric_diff(pebsMetricId, catchUpMetricId, set, &diff, &diffWithPeriod);
    // catch up metric: up catchUpMetricId to macth pebsMetricId
    cct_metric_data_increment(catchUpMetricId, ctxtNode, diff);
    return diffWithPeriod.i;
}

static void UpdateFoundMetrics(cct_node_t * ctxtNode, cct_node_t * oldNode, void * joinNode, int foundMetric, int foundMetricInc){
    // insert a special node
    cct_node_t *node = hpcrun_insert_special_node(oldNode, joinNode);
    // concatenate call paths
    node = hpcrun_cct_insert_path_return_leaf(ctxtNode, node);
    // update the foundMetric
    cct_metric_data_increment(foundMetric, node, (cct_metric_data_t){.i = foundMetricInc});
}


static cct_node_t * UpdateMetrics(void *ctxt, cct_node_t * oldNode, void * joinNode, int checkedMetric, int foundMetric, int checkedMetricInc, int foundMetricInc){
    // unwind call stack once
    sample_val_t v = hpcrun_sample_callpath(ctxt, checkedMetric, checkedMetricInc, 0/*skipInner*/, 1/*isSync*/);
    if(foundMetricInc) {
        UpdateFoundMetrics(v.sample_node, oldNode, joinNode, foundMetric, foundMetricInc);
    }
    return v.sample_node;
}

static inline UpdateConcatenatedPathPair(void *ctxt, cct_node_t * oldNode, void * joinNode, int metricId, int metricInc){
    // unwind call stack once
    sample_val_t v = hpcrun_sample_callpath(ctxt, metricId, 0, 0/*skipInner*/, 1/*isSync*/);
    // insert a special node
    cct_node_t *node = hpcrun_insert_special_node(oldNode, joinNode);
    // concatenate call paths
    node = hpcrun_cct_insert_path_return_leaf(v.sample_node, node);
    // update the foundMetric
    cct_metric_data_increment(metricId, node, (cct_metric_data_t){.i = metricInc});
}

static WPUpCallTRetType DeadStoreWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt){
    if(!wt->pc) {
        // if the ip is 0, let's drop the WP
        return DISABLE;
    }
    
    // This is a approximation.
    // If we took N samples at wpi->sample.node since the last time a WP triggered here,
    // If this a dead write, we'll update the dead_writes metric at the call path <wpi->sample.node:KILLED_BY:curctxt>
    // Otherwise (not dead), we'll update the used_writes metric at the call path <wpi->sample.node:USED_BY:curctxt>
    // In either case, the increment will be (N * overlapBytes)
    // Bump up last_pebs_metric_id to match sampledMetricId
    uint64_t numDiffSamples = GetWeightedMetricDiffAndReset(wpi->sample.node, wpi->sample.sampledMetricId, last_pebs_metric_id);
    int overlapBytes = GET_OVERLAP_BYTES(wpi->sample.va, wpi->sample.wpLength, wt->va, wt->accessLength);
    if(!overlapBytes){
        fprintf(stderr, "\n wpi->sample.va=%p, wpi->sample.wpLength = %d,  wt->va = %p, wt->accessLength=%d\n", wpi->sample.va, wpi->sample.wpLength, wt->va, wt->accessLength);
        monitor_real_abort();
    }
    
    // Now increment dead_metric_id by numDiffSamples * wpi->sample.accessLength
    // I could have done numDiffSamples * overlapBytes, but it will cause misattribution when access sizes are not same at dead and kill sites.
    // Basically, we are assuming that whatever happened in the observed watchpoints is applicable to the entire access length
    uint64_t inc = numDiffSamples * wpi->sample.accessLength;

    // if the access is a LOAD we are done! not a dead write :)
    if(wt->accessType == LOAD) {
        // update the measured (i.e. not dead)
        usedBytes += inc;
        UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)USED_BY+1) /* joinNode*/, measured_metric_id /* checkedMetric */, inc);
    } else {
        deadBytes += inc;
        UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)KILLED_BY+1) /* joinNode*/, dead_metric_id /* checkedMetric */, inc);
    }
    return DISABLE;
}

static WPUpCallTRetType RedStoreWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt){
    void *pip = wt->pc;
    if(!pip) {
        // if the ip is 0, let's retain the WP
        return RETAIN;
    }
    //
    bool isFloatOperation = is_float_operation(wt->pc);
    bool redBytes = 0;
    int offset = 0;
    
    if(isFloatOperation){

        int operandSize = get_len_float_operand(wt->pc,1); //////shasha todo
        // Addresses must be same
            if(wt->va == wpi->sample.va) {
                // check floating point instructions
                switch (wt->accessLength) {
                    case 4 /* float */:
                    {
                        // The two floats must be aligned to the 4-byte boundary
                        if(IS_4_BYTE_ALIGNED(wt->va)) {
                            float old = *((float*)(wpi->value));
                            float new = *((float*)(wt->va));
                            if(old != new){
                                float rate = (old-new)/old;/////shasha:in case old may be 0
                                if(rate > APPROX_RATE || rate < -APPROX_RATE)
                                    redBytes = 0;
                                else
                                    redBytes = sizeof(float);
                            } else {
                                redBytes = sizeof(float);
                            }
                        }
                        break;
                    }
                    case 8 /* double */:
                    {
                        if(IS_8_BYTE_ALIGNED(wt->va)) {
                            double old = *((double*)(wpi->value));
                            double new = *((double*)(wt->va));
                            if(old != new){
                                double rate = (old-new)/old;/////shasha:in case old may be 0
                                if(rate > APPROX_RATE || rate < -APPROX_RATE)
                                    redBytes = 0;
                                else
                                    redBytes = sizeof(double);
                            } else {
                                redBytes = sizeof(double);
                            }
                        }
                        break;
                    }
                    case 10 /* X87 registers  */:
                    {
                        uint8_t newValue[10];
                        memcpy(newValue, wt->va,wt->accessLength);
                
                        uint64_t * upperOld = (uint64_t*)&(wpi->value[2]);
                        uint64_t * upperNew = (uint64_t*)&(newValue[2]);
                
                        uint16_t * lowOld = (uint16_t*)&(wpi->value[0]);
                        uint16_t * lowNew = (uint16_t*)&(newValue[0]);
                
                        if((*lowOld & 0xfff0) == (*lowNew & 0xfff0) && *upperNew == *upperOld){
                           redBytes = 10;
                        }else{redBytes = 0;}
                    }
                    case 16 /* XMM */:
                    {
                        if(operandSize == 4){
                            __m128 oldValue = _mm_loadu_ps( (float*)(wpi->value));
                            __m128 newValue = _mm_loadu_ps( (float*) (wt->va));
                    
                            __m128 result = _mm_sub_ps(newValue,oldValue);
                    
                            result = _mm_div_ps(result,oldValue);
                            float rates[4] __attribute__((aligned(16)));
                            _mm_store_ps(rates,result);
                    
                            for(int i = 0; i < 4; ++i){
                               if(rates[i] < -APPROX_RATE || rates[i] > APPROX_RATE) {
                                  redBytes = 0; break;
                               }
                            }
                            redBytes = sizeof(float) * 4; break;
                        }else if(operandSize == 8){
                            __m128d oldValue = _mm_loadu_pd( (double*) (wpi->value));
                            __m128d newValue = _mm_loadu_pd( (double*) (wt->va));
                    
                            __m128d result = _mm_sub_pd(newValue,oldValue);
                    
                            result = _mm_div_pd(result,oldValue);
                    
                            double rate[2];
                            _mm_storel_pd(&rate[0],result);
                            _mm_storeh_pd(&rate[1],result);
                    
                            if(rate[0] < -APPROX_RATE || rate[0] > APPROX_RATE){redBytes = 0; break;}
                            if(rate[1] < -APPROX_RATE || rate[1] > APPROX_RATE){redBytes = 0; break;}
                             
                            redBytes = sizeof(double)*2; break;
                        }else {redBytes = 0; break;}
                    }
#if 0 
                    case 32 /* YMM */:
                    {
                        if(operandSize == 4){
                            __m256 oldValue = _mm256_loadu_ps( (float*) (wpi->value));
                            __m256 newValue = _mm256_loadu_ps( (float*) (wt->va));
                    
                            __m256 result = _mm256_sub_ps(newValue,oldValue);
                    
                            result = _mm256_div_ps(result,oldValue);
                            float rates[8] __attribute__((aligned(32)));
                            _mm256_store_ps(rates,result);
                    
                            for(int i = 0; i < 8; ++i){
                               if(rates[i] < -APPROX_RATE || rates[i] > APPROX_RATE) {
                                  redBytes = 0; break;
                               }
                            }
                            redBytes = sizeof(float) * 8; break;
                        }else if(operandSize == 8){
                            __m256d oldValue = _mm256_loadu_pd( (const double*) (wpi->value));
                            __m256d newValue = _mm256_loadu_pd( (const double*) (wt->va));
                    
                            __m256d result = _mm256_sub_pd(newValue,oldValue);
                    
                            result = _mm256_div_pd(result,oldValue);
                            double rates[4] __attribute__((aligned(32)));
                            _mm256_store_pd(rates,result);
                    
                            for(int i = 0; i < 4; ++i){
                               if(rates[i] < -APPROX_RATE || rates[i] > APPROX_RATE) {
                                  redBytes = 0; break;
                               }
                            }
                            
                            redBytes = sizeof(double) * 4; break;
                        }else {redBytes = 0; break;}
                    }
#endif
                    default:
                        redBytes = 0;
                        break;
                }
            }
            uint64_t numDiffSamples = GetWeightedMetricDiffAndReset(wpi->sample.node, wpi->sample.sampledMetricId, last_pebs_metric_id);
            // Now increment metric by numDiffSamples * redBytes
            uint64_t inc = numDiffSamples * redBytes;
        
            if(numDiffSamples != 0) {
                // Now increment metric by numDiffSamples * redBytes
                uint64_t inc = numDiffSamples * redBytes;
                oldAppxBytes += inc;
                UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)KILLED_BY+1) /* joinNode*/, redApprox_metric_id /* checkedMetric */, inc);
            } else {
                uint64_t inc = numDiffSamples * wt->accessLength;
                newBytes += inc;
                UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)NEW_VAL_BY+1) /* joinNode*/, measured_metric_id /* checkedMetric */, inc);
            }
        }else{
            // check integer instructions
            int overlapLen = GET_OVERLAP_BYTES(wt->va, safeAccessLen, wpi->sample.va, wpi->sample.wpLength);
            int firstOffest = FIRST_OVERLAPPED_BYTE_OFFSET_IN_FIRST(wt->va, safeAccessLen, wpi->sample.va, wpi->sample.wpLength);
            int secondOffest = FIRST_OVERLAPPED_BYTE_OFFSET_IN_FIRST(wt->va, safeAccessLen, wpi->sample.va, wpi->sample.wpLength);
            
            for(int i = firstOffest, k = secondOffest ; i < firstOffest + overlapLen; i++, k++){
                if(((uint8_t*)(wt->va))[i] == wpi->value[k]) {
                    redBytes ++;
                } else{
                    redBytes = 0;
                    break;
                }
            }
            uint64_t numDiffSamples = GetWeightedMetricDiffAndReset(wpi->sample.node, wpi->sample.sampledMetricId, last_pebs_metric_id);

            if(numDiffSamples != 0) {
                // Now increment metric by numDiffSamples * redBytes
                uint64_t inc = numDiffSamples * redBytes;
                oldBytes += inc;
                UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)KILLED_BY+1) /* joinNode*/, red_metric_id /* checkedMetric */, inc);
            } else {
                uint64_t inc = numDiffSamples * overlapLen;
                newBytes += inc;
                UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)NEW_VAL_BY+1) /* joinNode*/, measured_metric_id /* checkedMetric */, inc);
            }
        }
        return DISABLE;
    }
    
    static WPUpCallTRetType TemporalReuseWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt){
        if(!wt->pc) {
            // if the ip is 0, let's retain the WP
            return RETAIN;
        }
        // Report a reuse
        thread_data_t *td = hpcrun_get_thread_data();
        uint64_t numDiffSamples = GetWeightedMetricDiffAndReset(wpi->sample.node, wpi->sample.sampledMetricId, last_pebs_metric_id);
        // Now increment temporal_metric_id by numDiffSamples * overlapBytes
        uint64_t inc = numDiffSamples;
        UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)TEPORALLY_REUSED_BY+1) /* joinNode*/, temporal_metric_id /* checkedMetric */, inc);
        return DISABLE;
    }
    
    static WPUpCallTRetType SpatialReuseWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt){
        void *pip = wt->pc;
        if(!wt->pc) {
            // if the ip is 0, let's retain the WP
            return RETAIN;
        }
        // Report a reuse
        thread_data_t *td = hpcrun_get_thread_data();
        uint64_t numDiffSamples = GetWeightedMetricDiffAndReset(wpi->sample.node, wpi->sample.sampledMetricId, last_pebs_metric_id);
        // Now increment dead_metric_id by numDiffSamples * overlapBytes
        uint64_t inc = numDiffSamples;
        
        UpdateConcatenatedPathPair(wt->ctxt, wpi->sample.node /* oldNode*/, (void *)((uint64_t)SPATIALLY_REUSED_BY+1) /* joinNode*/, spatial_metric_id /* checkedMetric */, inc);
        return DISABLE;
    }
    
    static WPUpCallTRetType LoadLoadWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt){
        return DISABLE;
    }
    static WPUpCallTRetType FalseSharingWPCallback(WatchPointInfo_t *wpi, int startOffset, int safeAccessLen, WatchPointTrigger_t * wt){
        int metricId = -1;
        void* joinNode;
        
        if(wpi->sample.accessType == LOAD){
            wrIns ++;
            metricId = wr_metric_id;
            joinNode = (void *)((uint64_t)WR_PING_PONG +1);
        } else {
            if(wt->accessType == LOAD) {
                rwIns ++;
                metricId = rw_metric_id;
                joinNode = (void *)((uint64_t)RW_PING_PONG +1);
            } else{
                wwIns ++;
                metricId =  ww_metric_id;
                joinNode = (void *)((uint64_t)WW_PING_PONG +1);
            }
        }
        
        sample_val_t v = hpcrun_sample_callpath(wt->ctxt, measured_metric_id, 1, 0/*skipInner*/, 1/*isSync*/);
        // insert a special node
        cct_node_t *node = hpcrun_insert_special_node(v.sample_node, joinNode);
        node = hpcrun_cct_insert_path_return_leaf(wpi->sample.node, node);
        // update the metricId
        cct_metric_data_increment(metricId, node, (cct_metric_data_t){.i = 1});
        
        
        return DISABLE_ALL_WP;
    }
    
    static inline bool IsLibMonitorAddress(void * addr) {
        // race is ok,
        if(!libmonitorLM){
            libmonitorLM = hpcrun_loadmap_findByName(hpcrun_loadmap_findLoadName("libmonitor.so"))->dso_info;
        }
        
        if (addr >= libmonitorLM->start_addr && addr < libmonitorLM->end_addr){
            return true;
        }
        return false;
    }
        
    static inline bool IsHPCRunAddress(void * addr) {
        if(!hpcrunLM){
            hpcrunLM = hpcrun_loadmap_findByName(hpcrun_loadmap_findLoadName("libhpcrun.so"))->dso_info;
        }

        if (addr >= hpcrunLM->start_addr && addr < hpcrunLM->end_addr){
            return true;
        }
        return false;
    }


    static inline bool isTdataAddress(void *addr) {
      void *tdata = &inside_hpcrun;
      if ((addr > tdata-100) && (addr < tdata+100)) return true;
      return false;
    }

    static inline bool IsBlackListedWatchpointAddress(void *addr){
        for(int i = 0; i < numBlackListAddresses; i++){
            if (addr >= blackListAddresses[i].startAddr && addr < blackListAddresses[i].endAddr){
                return true;
            }
        }
        return false;
    }

    // Avoids Kernel address and zeros
    static inline bool IsValidAddress(void * addr, void * pc){
        thread_data_t * td =  hpcrun_get_thread_data();
        if(((td-1) <= addr) && (addr < td+2)) // td data
            return false;
        if(IsAltStackAddress(addr))
            return false;
        
        if(IsBlackListedWatchpointAddress(addr) || IsBlackListedWatchpointAddress(pc)){
            return false;
        }
        
        if (isTdataAddress(addr))
            return false;

        if((addr && !(((unsigned long)addr) & 0xF0000000000000)) &&
           (pc && !(((unsigned long)pc) & 0xF0000000000000)))
            return true;
        return false;
    }
    
    
    void ReadSharedDataTransactionally(SharedData_t *localSharedData){
        // Laport's STM
        do{
            int64_t startCounter = gSharedData.counter;
            if(startCounter & 1)
                continue; // Some writer is updating
            
            __sync_synchronize();
            *localSharedData = gSharedData;
            __sync_synchronize();
            int64_t endCounter = gSharedData.counter;
            if(startCounter == endCounter)
                break;
        }while(1);
    }
    
    bool OnSample(void * data_addr, void * pc, cct_node_t *node, int accessLen, AccessType accessType, int sampledMetricId, bool disAssemble) {
        // do not monitor kernel address
        if (!IsValidAddress(data_addr, pc)) {
            goto ErrExit; // incorrect access type
        }
        
        if(disAssemble){
            if(false == get_mem_access_length_and_type(pc, &accessLen, &accessType)){
                //EMSG("Sampled a non load store at = %p\n", pc);
                goto ErrExit; // incorrect access type
            }
            if(accessType == UNKNOWN || accessLen == 0){
                //EMSG("Sampled sd.accessType = %d, accessLen=%d at pc = %p\n", accessType, accessLen, pc);
                goto ErrExit; // incorrect access type
            }
        }
        
        switch (theWPConfig->id) {
            case WP_DEADSPY:{
                if(accessType == LOAD){
                    //EMSG("Sampled accessType = %d\n", accessType);
                    goto ErrExit; // incorrect access type
                }
                
                long  metricThreshold = hpcrun_id2metric(sampledMetricId)->period;
                writtenBytes += accessLen * metricThreshold;
                SampleData_t sd= {.va = data_addr, .node = node, .type=WP_RW, .wpLength = accessLen, .accessLength= accessLen, .accessType=accessType, .sampledMetricId=sampledMetricId};
                if(accessLen != 1 && accessLen != 2 && accessLen != 4 && accessLen != 8)
                    sd.wpLength = 1; // force 1 length
                else
                    sd.wpLength = accessLen;
                SubscribeWatchpoint(&sd, OVERWRITE, false /* capture value */);
            }
                break;
                
            case WP_REDSPY:{
                long  metricThreshold = hpcrun_id2metric(sampledMetricId)->period;
                writtenBytes += accessLen * metricThreshold;
                SampleData_t sd= {.va = data_addr, .node = node, .type=WP_WRITE, .wpLength = accessLen, .accessLength= accessLen,.accessType=accessType, .sampledMetricId=sampledMetricId};
                // Must have a store address
                if(accessType == STORE || sd.accessType == LOAD_AND_STORE){
                    if(accessLen != 1 && accessLen != 2 && accessLen != 4 && accessLen != 8)
                        sd.wpLength = 1; // force 1 length
                    else
                        sd.wpLength = accessLen;
                    
                    SubscribeWatchpoint(&sd, OVERWRITE, true /* capture value */);
                } else {
                    //EMSG("Sampled accessType = %d\n", accessType);
                    goto ErrExit; // incorrect access type
                }
            }
                break;
            case WP_LOADSPY:{
                long  metricThreshold = hpcrun_id2metric(sampledMetricId)->period;
                loadedBytes += accessLen * metricThreshold;
                SampleData_t sd= {.va = data_addr, .node = node, .type=WP_READ, .wpLength = accessLen, .accessLength= accessLen,.accessType=accessType, .sampledMetricId=sampledMetricId};
                // Must have a store address
                if(accessType == LOAD || sd.accessType == LOAD_AND_STORE){
                    if(accessLen != 1 && accessLen != 2 && accessLen != 4 && accessLen != 8)
                        sd.wpLength = 1; // force 1 length
                    else
                        sd.wpLength = accessLen;
                    
                    SubscribeWatchpoint(&sd, OVERWRITE, true /* capture value */);
                } else {
                    //EMSG("Sampled accessType = %d\n", accessType);
                    goto ErrExit; // incorrect access type
                }
            }
                break;
            case WP_SPATIAL_REUSE:{
                SampleData_t sd= {.node = node, .type=WP_RW, .accessType=accessType, .wpLength = accessLen, .accessLength= accessLen, .sampledMetricId=sampledMetricId};
                if(accessLen != 1 && accessLen != 2 && accessLen != 4 && accessLen != 8)
                    sd.wpLength = 1; // force 1 length
                else
                    sd.wpLength = accessLen;
                // randomly protect another word in the same cache line
                uint64_t aligned_pc = ALIGN_TO_CACHE_LINE((uint64_t)data_addr);
                int offset = ((uint64_t)data_addr - aligned_pc) / accessLen;
                int bound = CACHE_LINE_SZ / accessLen;
                int r = rdtsc() % bound;
                if (r == offset) r = (r+1) % bound;
                sd.va = aligned_pc + (r * accessLen);
                SubscribeWatchpoint(&sd, OVERWRITE, false /* capture value */);
            }
                break;
            case WP_TEMPORAL_REUSE:{
                SampleData_t sd= {.va = data_addr, .node = node, .type=WP_RW, .accessType=accessType, .wpLength = accessLen, .accessLength= accessLen,.sampledMetricId=sampledMetricId};
                if(accessLen != 1 && accessLen != 2 && accessLen != 4 && accessLen != 8)
                    sd.wpLength = 1; // force 1 length
                else
                    sd.wpLength = accessLen;
                SubscribeWatchpoint(&sd, OVERWRITE, false /* capture value */);
            }
                break;
            case WP_FALSE_SHARING:{
                
                // Is the published address old enough (stayed for > 1 sample time span)
                int64_t curTime = rdtsc();
                SharedData_t localSharedData;
                int me = TD_GET(core_profile_trace_data.id);
                ReadSharedDataTransactionally(&localSharedData);
                if( (curTime-localSharedData.time) > 2 * (curTime-lastTime)) {
                    // Attempt to replace WP with my new address
                    uint64_t theCounter = localSharedData.counter;
                    localSharedData.time = rdtsc();
                    localSharedData.tid = me;
                    localSharedData.wpType = accessType == LOAD ? WP_WRITE : WP_RW;
                    localSharedData.accessType = accessType;
                    localSharedData.address = data_addr;
                    localSharedData.counter ++; // makes the counter odd
                    localSharedData.node = node;
                    
                    if(__sync_bool_compare_and_swap(&gSharedData.counter, theCounter, theCounter+1)){
                        gSharedData = localSharedData;
                        __sync_synchronize();
                        gSharedData.counter++; // makes the counter even
                    } else {
                        // Failed to update ==> someone else succeeded ==> Fetch that address and set a WP for that
                        ReadSharedDataTransactionally(&localSharedData);
                        goto SET_FS_WP;
                    }
                } else if ((localSharedData.tid != me)  && (localSharedData.tid != -1)/* dont set WP for my own accessed locations */){
                    // If the data is "new" set the WP
                    void * cacheLineBaseAddress;
                SET_FS_WP:
                    ;
                    long  metricThreshold = hpcrun_id2metric(sampledMetricId)->period;
                    accessedIns += metricThreshold;
                    cacheLineBaseAddress = ALIGN_TO_CACHE_LINE((size_t)localSharedData.address);
                    // Find 4 slots in the cacheline
                    int shuffleNums[CACHE_LINE_SZ/MAX_WP_LENGTH] = {0, 1, 2, 3, 4, 5, 6, 7}; // hard coded
                    for(int i = 0; i < CACHE_LINE_SZ/MAX_WP_LENGTH/2; i ++) {
                        int idx = rdtsc() & (CACHE_LINE_SZ/MAX_WP_LENGTH -1);
                        int tmpVal = shuffleNums[idx];
                        shuffleNums[idx] = shuffleNums[i];
                        shuffleNums[i] = tmpVal;
                    }
                    for(int i = 0; i < wpConfig.maxWP; i ++) {
                        SampleData_t sd= {.va = cacheLineBaseAddress + (shuffleNums[i] << 3), .node = localSharedData.node, .accessType=localSharedData.accessType, .type=localSharedData.wpType, .wpLength = MAX_WP_LENGTH, .accessLength= accessLen, .sampledMetricId=sampledMetricId};
                        SubscribeWatchpoint(&sd, OVERWRITE, false /* capture value */);
                    }
                }else{
                    /* dont set WP for my own accessed locations */
                }
                lastTime = curTime;
            }
                break;
            default:
                break;
        }
        wpStats.numWatchpointsSet ++;
        return true;
        
    ErrExit:
        wpStats.numImpreciseSamples ++;
        return false;
        
    }
    
