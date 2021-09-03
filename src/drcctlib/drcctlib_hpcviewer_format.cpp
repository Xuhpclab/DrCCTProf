/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <cinttypes>
#include <string>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dr_api.h"
#include "drmgr.h"
#include "hashtable.h"
#include "drcctlib_priv_share.h"
#include "drcctlib_hpcviewer_format.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("hpcviewer", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("hpcviewer", _FORMAT, ##_ARGS)

/* ==================================hpcviewer support===================================*/

// necessary macros
#define HASH_PRIME 2001001003
#define HASH_GEN 4001
#define SPINLOCK_UNLOCKED_VALUE (0L)
#define SPINLOCK_LOCKED_VALUE (1L)
#define OSUtil_hostid_NULL (-1)
#define INITIALIZE_SPINLOCK(x) \
    {                          \
        .thelock = (x)         \
    }
#define SPINLOCK_UNLOCKED INITIALIZE_SPINLOCK(SPINLOCK_UNLOCKED_VALUE)
#define SPINLOCK_LOCKED INITIALIZE_SPINLOCK(SPINLOCK_LOCKED_VALUE)

#define HPCRUN_FMT_NV_prog "program-name"
#define HPCRUN_FMT_NV_progPath "program-path"
#define HPCRUN_FMT_NV_envPath "env-path"
#define HPCRUN_FMT_NV_jobId "job-id"
#define HPCRUN_FMT_NV_mpiRank "mpi-id"
#define HPCRUN_FMT_NV_tid "thread-id"
#define HPCRUN_FMT_NV_hostid "host-id"
#define HPCRUN_FMT_NV_pid "process-id"
#define HPCRUN_SAMPLE_PROB "HPCRUN_PROCESS_FRACTION"
#define HPCRUN_FMT_NV_traceMinTime "trace-min-time"
#define HPCRUN_FMT_NV_traceMaxTime "trace-max-time"

#define FILENAME_TEMPLATE "%s/%s-%06u-%03d-%08lx-%u-%d.%s"
#define TEMPORARY "%s/%s-"
#define RANK 0

#define FILES_RANDOM_GEN 4
#define FILES_MAX_GEN 11
#define FILES_EARLY 0x1
#define FILES_LATE 0x2
#define DEFAULT_PROB 0.1

// *** atomic-op-asm.h && atomic-op-gcc.h ***
#if defined(LL_BODY) && defined(SC_BODY)

#    define read_modify_write(type, addr, expn, result)                                \
        {                                                                              \
            type __new;                                                                \
            do {                                                                       \
                result = (type)load_linked((unsigned long *)addr);                     \
                __new = expn;                                                          \
            } while (!store_conditional((unsigned long *)addr, (unsigned long)__new)); \
        }
#else

#    define read_modify_write(type, addr, expn, result)                \
        {                                                              \
            type __new;                                                \
            do {                                                       \
                result = *addr;                                        \
                __new = expn;                                          \
            } while (compare_and_swap(addr, result, __new) != result); \
        }
#endif

#define compare_and_swap(addr, oldval, newval) \
    __sync_val_compare_and_swap(addr, oldval, newval)

// ***********************

#define MAX_METRICS (10)
#define MAX_LEN (128)

typedef struct _offline_module_data_t {
    int id;
    bool app;
    char path[MAXIMUM_FILEPATH];
    app_pc start;
    app_pc end;
} offline_module_data_t;
#define OFFLINE_MODULE_DATA_TABLE_HASH_BITS 6
static hashtable_t global_module_data_table;
static void *module_data_lock;

// create a new node type to substitute cct_ip_node_t and cct_bb_node_t
struct hpcviewer_format_ip_node_t {
    int32_t parentID;
    hpcviewer_format_ip_node_t *parentIPNode;

    int32_t ID;
    app_pc IPAddress;
    uint64_t *metricVal;

    vector<hpcviewer_format_ip_node_t *> childIPNodes;
};

typedef struct _per_thread_t {
    int id;
    hpcviewer_format_ip_node_t *tlsHPCRunCCTRoot;
    uint64_t nodeCount;
} per_thread_t;

typedef struct _hpc_format_config_t {
    bool metric_cct;
    int metric_num;
    char metric_name_arry[MAX_METRICS][MAX_LEN];
    hpcviewer_format_ip_node_t *gHPCRunCCTRoot;
    uint64_t nodeCount;
    std::string dirName;
    std::string filename;
} hpc_format_config_t;
static hpc_format_config_t global_hpc_fmt_config;

static int tls_idx;

typedef enum {
    MetricFlags_Ty_NULL = 0,
    MetricFlags_Ty_Raw,
    MetricFlags_Ty_Final,
    MetricFlags_Ty_Derived
} MetricFlags_Ty_t;

typedef enum {
    MetricFlags_ValTy_NULL = 0,
    MetricFlags_ValTy_Incl,
    MetricFlags_ValTy_Excl
} MetricFlags_ValTy_t;

typedef enum {
    MetricFlags_ValFmt_NULL = 0,
    MetricFlags_ValFmt_Int,
    MetricFlags_ValFmt_Real,
} MetricFlags_ValFmt_t;

typedef struct epoch_flags_bitfield {
    bool isLogicalUnwind : 1;
    uint64_t unused : 63;
} epoch_flags_bitfield;

typedef union epoch_flags_t {
    epoch_flags_bitfield fields;
    uint64_t bits; // for reading/writing
} epoch_flags_t;

typedef struct metric_desc_properties_t {
    unsigned time : 1;
    unsigned cycles : 1;
} metric_desc_properties_t;

typedef struct hpcrun_metricFlags_fields {
    MetricFlags_Ty_t ty : 8;
    MetricFlags_ValTy_t valTy : 8;
    MetricFlags_ValFmt_t valFmt : 8;
    uint8_t unused0;
    uint16_t partner;
    uint8_t /*bool*/ show;
    uint8_t /*bool*/ showPercent;
    uint64_t unused1;
} hpcrun_metricFlags_fields;

typedef union hpcrun_metricFlags_t {
    hpcrun_metricFlags_fields fields;
    uint8_t bits[2 * 8];  // for reading/writing
    uint64_t bits_big[2]; // for easy initialization
} hpcrun_metricFlags_t;

typedef struct metric_desc_t {
    char *name;
    char *description;
    hpcrun_metricFlags_t flags;
    uint64_t period;
    metric_desc_properties_t properties;
    char *formula;
    char *format;
    bool is_frequency_metric;
} metric_desc_t;

typedef struct spinlock_t {
    volatile long thelock;
} spinlock_t;

struct fileid {
    int done;
    long host;
    int gen;
};

extern const metric_desc_t metricDesc_NULL;

const metric_desc_t metricDesc_NULL = {
    NULL, // name
    NULL, // description
    MetricFlags_Ty_NULL,
    MetricFlags_ValTy_NULL,
    MetricFlags_ValFmt_NULL,
    0,              // fields.unused0
    0,              // fields.partner
    (uint8_t) true, // fields.show
    (uint8_t) true, // fields.showPercent
    0,              // unused 1
    0,              // period
    0,              // properties.time
    0,              // properties.cycles
    NULL,
    NULL,
};

extern const hpcrun_metricFlags_t hpcrun_metricFlags_NULL;

const hpcrun_metricFlags_t hpcrun_metricFlags_NULL = {
    MetricFlags_Ty_NULL,
    MetricFlags_ValTy_NULL,
    MetricFlags_ValFmt_NULL,
    0,              // fields.unused0
    0,              // fields.partner
    (uint8_t) true, // fields.show
    (uint8_t) true, // fields.showPercent
    0,              // unused 1
};

static epoch_flags_t epoch_flags = { .bits = 0x0000000000000000 };

static const uint64_t default_measurement_granularity = 1;
static const uint32_t default_ra_to_callsite_distance = 1;

// ***************** file ************************
static spinlock_t files_lock = SPINLOCK_UNLOCKED;
static pid_t mypid = 0;
static struct fileid earlyid;
static struct fileid lateid;
static int log_done = 0;
static int log_rename_done = 0;
static int log_rename_ret = 0;
// ***********************************************
/*   for HPCViewer output format     */

static int32_t global_fmt_ip_node_start = 0;

// *************************************** format ****************************************
static const char HPCRUN_FMT_Magic[] = "HPCRUN-profile____";
static const int HPCRUN_FMT_MagicLen = (sizeof(HPCRUN_FMT_Magic) - 1);
static const char HPCRUN_FMT_Endian[] = "b";
static const int HPCRUN_FMT_EndianLen = (sizeof(HPCRUN_FMT_Endian) - 1);
static const char HPCRUN_ProfileFnmSfx[] = "hpcrun";
static const char HPCRUN_FMT_Version[] = "02.00";
static const char HPCRUN_FMT_VersionLen = (sizeof(HPCRUN_FMT_Version) - 1);
static const char HPCRUN_FMT_EpochTag[] = "EPOCH___";
static const int HPCRUN_FMT_EpochTagLen = (sizeof(HPCRUN_FMT_EpochTag) - 1);
const uint bufSZ = 32; // sufficient to hold a 64-bit integer in base 10
int
hpcfmt_str_fwrite(const char *str, FILE *outfs);
int
hpcrun_fmt_hdrwrite(FILE *fs);
int
hpcrun_fmt_hdr_fwrite(FILE *fs, const char *arg1, const char *arg2);
int
hpcrun_open_profile_file(int thread, const char *fileName);
static int
hpcrun_open_file(int thread, const char *suffix, int flags, const char *fileName);
int
hpcrun_fmt_loadmap_fwrite(FILE *fs);
int
hpcrun_fmt_epochHdr_fwrite(FILE *fs, epoch_flags_t flags, uint64_t measurementGranularity,
                           uint32_t raToCallsiteOfst);
static void
hpcrun_files_init();
uint
OSUtil_pid();
const char *
OSUtil_jobid();
long
OSUtil_hostid();
void
hpcrun_set_metric_info_w_fn(int metric_id, const char *name, MetricFlags_ValFmt_t valFmt,
                            size_t period, FILE *fs);
size_t
hpcio_ben_fwrite(uint64_t val, int n, FILE *fs);
size_t
hpcio_beX_fwrite(uint8_t val, size_t size, FILE *fs);

// ******************************************************************************************

// ****************Merge splay trees **************************************************
void
tranverseIPs(hpcviewer_format_ip_node_t *curIPNode, splay_node_t *splay_node,
             uint64_t *nodeCount);
hpcviewer_format_ip_node_t *
constructIPNodeFromIP(hpcviewer_format_ip_node_t *parentIP, app_pc address,
                      uint64_t *nodeCount);
hpcviewer_format_ip_node_t *
findSameIP(vector<hpcviewer_format_ip_node_t *> *nodes, cct_ip_node_t *node);
hpcviewer_format_ip_node_t *
findSameIPbyIP(vector<hpcviewer_format_ip_node_t *> nodes, app_pc address);
void
mergeIP(hpcviewer_format_ip_node_t *prev, cct_ip_node_t *cur, uint64_t *nodeCount);
int32_t
get_fmt_ip_node_new_id();
// ************************************************************************************

// ****************Print merged splay tree*********************************************
void
IPNode_fwrite(hpcviewer_format_ip_node_t *node, FILE *fs);
void
tranverseNewCCT(vector<hpcviewer_format_ip_node_t *> *nodes, FILE *fs);
// ************************************************************************************

static int unsigned long
fetch_and_store(volatile long *addr, long newval)
{
    long result;
    read_modify_write(long, addr, newval, result);
    return result;
}

static inline void
spinlock_unlock(spinlock_t *l)
{
    l->thelock = SPINLOCK_UNLOCKED_VALUE;
}

static inline void
spinlock_lock(spinlock_t *l)
{
    /* test-and-test-and-set lock*/
    for (;;) {
        while (l->thelock != SPINLOCK_UNLOCKED_VALUE)
            ;

        if (fetch_and_store(&l->thelock, SPINLOCK_LOCKED_VALUE) ==
            SPINLOCK_UNLOCKED_VALUE) {
            break;
        }
    }
}

uint
OSUtil_pid()
{
    pid_t pid = getpid();
    return (uint)pid;
}

const char *
OSUtil_jobid()
{
    char *jid = NULL;

    // Cobalt
    jid = getenv("COBALT_JOB_ID");
    if (jid)
        return jid;

    // PBS
    jid = getenv("PBS_JOB_ID");
    if (jid)
        return jid;

    // SLURM
    jid = getenv("SLURM_JOB_ID");
    if (jid)
        return jid;

    // Sun Grid Engine
    jid = getenv("JOB_ID");
    if (jid)
        return jid;

    return jid;
}

long
OSUtil_hostid()
{
    // static long hostid = OSUtil_hostid_NULL;
    // if (hostid == OSUtil_hostid_NULL) {
    // //     DRCCTLIB_PRINTF("if (hostid == OSUtil_hostid_NULL) {");
    // //     // gethostid returns a 32-bit id. treat it as unsigned to prevent useless
    // sign
    // //     // extension
    //     hostid = (uint32_t)gethostid();
    // //     DRCCTLIB_PRINTF("hostid = (uint32_t)gethostid();");
    // }
    // SYS_osf_gethostid();

    return 0xbad;
}

size_t
hpcio_ben_fwrite(uint64_t val, int n, FILE *fs)
{
    size_t num_write = 0;
    for (int shift = 8 * (n - 1); shift >= 0; shift -= 8) {
        int c = fputc(((val >> shift) & 0xff), fs);
        if (c == EOF) {
            break;
        }
        num_write++;
    }
    return num_write;
}

size_t
hpcio_beX_fwrite(uint8_t *val, size_t size, FILE *fs)
{
    size_t num_write = 0;
    for (uint i = 0; i < size; ++i) {
        int c = fputc(val[i], fs);
        if (c == EOF)
            break;
        num_write++;
    }
    return num_write;
}

int
hpcio_fclose(FILE *fs)
{
    if (fs && fclose(fs) == EOF) {
        return 1;
    }
    return 0;
}

static inline int
hpcfmt_int2_fwrite(uint16_t val, FILE *outfs)
{
    if (sizeof(uint16_t) != hpcio_ben_fwrite(val, 2, outfs)) {
        return 0;
    }
    return 1;
}

static inline int
hpcfmt_int4_fwrite(uint32_t val, FILE *outfs)
{
    if (sizeof(uint32_t) != hpcio_ben_fwrite(val, 4, outfs)) {
        return 0;
    }
    return 1;
}

static inline int
hpcfmt_int8_fwrite(uint64_t val, FILE *outfs)
{
    if (sizeof(uint64_t) != hpcio_ben_fwrite(val, 8, outfs)) {
        return 0;
    }
    return 1;
}

static inline int
hpcfmt_intX_fwrite(uint8_t *val, size_t size, FILE *outfs)
{
    if (size != hpcio_beX_fwrite(val, size, outfs)) {
        return 0;
    }
    return 1;
}

int
hpcfmt_str_fwrite(const char *str, FILE *outfs)
{
    unsigned int i;
    uint32_t len = (str) ? strlen(str) : 0;
    hpcfmt_int4_fwrite(len, outfs);

    for (i = 0; i < len; i++) {
        int c = fputc(str[i], outfs);

        if (c == EOF)
            return 0;
    }

    return 1;
}

static void
hpcrun_files_init(void)
{
    pid_t cur_pid = getpid();
    if (mypid != cur_pid) {
        mypid = cur_pid;
        earlyid.done = 0;
        earlyid.host = OSUtil_hostid();
        earlyid.gen = 0;
        lateid = earlyid;
        log_done = 0;
        log_rename_done = 0;
        log_rename_ret = 0;
    }
}

// Replace "id" with the next unique id if possible. Normally, (hostid, pid, gen)
// works after one or two iteration. To be extra robust (eg, hostid is not unique),
// at some point, give up and pick a random hostid.
// Returns: 0 on success, else -1 on failure.
static int
hpcrun_files_next_id(struct fileid *id)
{
    struct timeval tv;
    int fd;

    if (id->done || id->gen >= FILES_MAX_GEN) {
        // failure, out of options
        return -1;
    }

    id->gen++;
    if (id->gen >= FILES_RANDOM_GEN) {
        // give up and use a random host id
        fd = open("/dev/urandom", O_RDONLY);
        dr_printf("Inside hpcrun_files_next_id fd = %d\n", fd);
        if (fd >= 0) {
            ssize_t read_size = read(fd, &id->host, sizeof(id->host));
            if (read_size == -1) {
                dr_printf("hpcrun_files_next_id read_size == -1\n");
            }
            close(fd);
        }
        gettimeofday(&tv, NULL);
        id->host += (tv.tv_sec << 20) + tv.tv_usec;
        id->host &= 0x00ffffffff;
    }
    return 0;
}

static int
hpcrun_open_file(int thread, const char *suffix, int flags, const char *fileName)
{
    char name[MAXIMUM_FILEPATH];
    struct fileid *id;
    int fd, ret;

    id = (flags & FILES_EARLY) ? &earlyid : &lateid;
    for (;;) {
        errno = 0;
        ret = snprintf(name, MAXIMUM_FILEPATH, FILENAME_TEMPLATE,
                       global_hpc_fmt_config.dirName.c_str(), fileName, RANK, thread,
                       id->host, mypid, id->gen, suffix);

        if (ret >= MAXIMUM_FILEPATH) {
            fd = -1;
            errno = ENAMETOOLONG;
            break;
        }

        fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0644);

        if (fd >= 0) {
            // sucess
            break;
        }

        if (errno != EEXIST || hpcrun_files_next_id(id) != 0) {
            // failure, out of options
            fd = -1;
            break;
        }
    }

    id->done = 1;

    if (flags & FILES_EARLY) {
        // late id starts where early id is chosen
        lateid = earlyid;
        lateid.done = 0;
    }

    if (fd < 0) {
        dr_printf("cctlib_hpcrun: unable to open %s file: '%s': %s", suffix, name,
                  strerror(errno));
    }

    return fd;
}

int
hpcrun_open_profile_file(int thread, const char *fileName)
{
    int ret;
    spinlock_lock(&files_lock);
    hpcrun_files_init();
    ret = hpcrun_open_file(thread, HPCRUN_ProfileFnmSfx, FILES_LATE, fileName);
    spinlock_unlock(&files_lock);
    return ret;
}

// Write out the format for metric table. Needs updates
void
hpcrun_set_metric_info_w_fn(int metric_id, const char *name, size_t period, FILE *fs)
{
    // Write out the number of metric table in the program
    metric_desc_t mdesc = metricDesc_NULL;
    mdesc.flags = hpcrun_metricFlags_NULL;

    for (int i = 0; i < 16; i++) {
        mdesc.flags.bits[i] = (uint8_t)0x00;
    }

    mdesc.name = (char *)name;
    mdesc.description = (char *)name; // TODO
    mdesc.period = period;
    mdesc.flags.fields.ty = MetricFlags_Ty_Raw;
    MetricFlags_ValFmt_t valFmt = (MetricFlags_ValFmt_t)1;
    mdesc.flags.fields.valFmt = valFmt;
    mdesc.flags.fields.show = true;
    mdesc.flags.fields.showPercent = true;
    mdesc.formula = NULL;
    mdesc.format = NULL;
    mdesc.is_frequency_metric = 0;

    hpcfmt_str_fwrite(mdesc.name, fs);
    hpcfmt_str_fwrite(mdesc.description, fs);
    hpcfmt_intX_fwrite(mdesc.flags.bits, sizeof(mdesc.flags),
                       fs); // Write metric flags bits for reading/writing
    hpcfmt_int8_fwrite(mdesc.period, fs);
    hpcfmt_str_fwrite(mdesc.formula, fs);
    hpcfmt_str_fwrite(mdesc.format, fs);
    hpcfmt_int2_fwrite(mdesc.is_frequency_metric, fs);

    // write auxaliary description to the table.
    // These values are only related to perf, not applicable to cctlib, so set all to 0
    hpcfmt_int2_fwrite(0, fs);
    hpcfmt_int8_fwrite(0, fs);
    hpcfmt_int8_fwrite(0, fs);
}

void
hpcrun_fmt_module_data_fwrite(void *payload, void *user_data)
{
    offline_module_data_t **print_vector = (offline_module_data_t **)user_data;
    offline_module_data_t *module_data = (offline_module_data_t *)payload;
    print_vector[module_data->id - 1] = module_data;
}

int
hpcrun_fmt_loadmap_fwrite(FILE *fs)
{
    // Write loadmap size
    hpcfmt_int4_fwrite((uint32_t)global_module_data_table.entries,
                       fs); // Write loadmap size
    offline_module_data_t **print_vector = (offline_module_data_t **)dr_global_alloc(
        global_module_data_table.entries * sizeof(offline_module_data_t *));
    hashtable_apply_to_all_payloads_user_data(
        &global_module_data_table, hpcrun_fmt_module_data_fwrite, (void *)print_vector);

    for (uint32_t i = 0; i < global_module_data_table.entries; i++) {
        hpcfmt_int2_fwrite(print_vector[i]->id, fs);  // Write loadmap id
        hpcfmt_str_fwrite(print_vector[i]->path, fs); // Write loadmap name
        hpcfmt_int8_fwrite((uint64_t)0, fs);
    }
    dr_global_free(print_vector,
                   global_module_data_table.entries * sizeof(offline_module_data_t *));
    return 0;
}

int
hpcrun_fmt_hdrwrite(FILE *fs)
{
    fwrite(HPCRUN_FMT_Magic, 1, HPCRUN_FMT_MagicLen, fs);
    fwrite(HPCRUN_FMT_Version, 1, HPCRUN_FMT_VersionLen, fs);
    fwrite(HPCRUN_FMT_Endian, 1, HPCRUN_FMT_EndianLen, fs);
    return 1;
}

int
hpcrun_fmt_epochHdr_fwrite(FILE *fs, epoch_flags_t flags, uint64_t measurementGranularity,
                           uint32_t raToCallsiteOfst)
{
    fwrite(HPCRUN_FMT_EpochTag, 1, HPCRUN_FMT_EpochTagLen, fs);
    hpcfmt_int8_fwrite(flags.bits, fs);
    hpcfmt_int8_fwrite(measurementGranularity, fs);
    hpcfmt_int4_fwrite(raToCallsiteOfst, fs);
    hpcfmt_int4_fwrite((uint32_t)1, fs);
    hpcrun_fmt_hdr_fwrite(fs, "TODO:epoch-name", "TODO:epoch-value");
    return 1;
}

int
hpcrun_fmt_hdr_fwrite(FILE *fs, const char *arg1, const char *arg2)
{
    hpcfmt_str_fwrite(arg1, fs);
    hpcfmt_str_fwrite(arg2, fs);
    return 1;
}

int32_t
get_fmt_ip_node_new_id()
{
    int32_t next_fmt_ip_node_id =
        dr_atomic_add32_return_sum(&global_fmt_ip_node_start, 2);
    return next_fmt_ip_node_id;
}

// Construct hpcviewer_format_ip_node_t
hpcviewer_format_ip_node_t *
constructIPNodeFromIP(hpcviewer_format_ip_node_t *parentIP, app_pc address,
                      uint64_t *nodeCount)
{
    hpcviewer_format_ip_node_t *curIP = new hpcviewer_format_ip_node_t();
    curIP->childIPNodes.clear();
    curIP->parentIPNode = parentIP;
    curIP->IPAddress = address;
    if (parentIP != NULL) {
        curIP->parentID = parentIP->ID;
    } else {
        curIP->parentID = 0;
    }
    curIP->ID = get_fmt_ip_node_new_id();
    if (global_hpc_fmt_config.metric_num > 0) {
        curIP->metricVal = new uint64_t[global_hpc_fmt_config.metric_num];
        for (int i = 0; i < global_hpc_fmt_config.metric_num; i++)
            curIP->metricVal[i] = 0;
    }
    if (parentIP != NULL) {
        parentIP->childIPNodes.push_back(curIP);
    }
    (*nodeCount)++;
    return curIP;
}

// Check to see whether another cct_ip_node_t has the same address under the same parent
hpcviewer_format_ip_node_t *
findSameIP(vector<hpcviewer_format_ip_node_t *> *nodes, cct_ip_node_t *node)
{
    app_pc address = drcctlib_priv_share_get_ip_from_ip_node(node);
    for (size_t i = 0; i < (*nodes).size(); i++) {
        if ((*nodes).at(i)->IPAddress == address)
            return (*nodes).at(i);
    }
    return NULL;
}

hpcviewer_format_ip_node_t *
findSameIPbyIP(vector<hpcviewer_format_ip_node_t *> nodes, app_pc address)
{
    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes.at(i)->IPAddress == address)
            return nodes.at(i);
    }
    return NULL;
}

// Merging the children of two nodes
void
mergeIP(hpcviewer_format_ip_node_t *prev, cct_ip_node_t *cur, uint64_t *nodeCount)
{
    if (drcctlib_priv_share_get_ip_node_callee_splay_tree_root(cur)) {
        tranverseIPs(prev, drcctlib_priv_share_get_ip_node_callee_splay_tree_root(cur), nodeCount);
    }
}

// Inorder tranversal of the previous splay tree and create the new tree
void
tranverseIPs(hpcviewer_format_ip_node_t *curIPNode, splay_node_t *splay_node,
             uint64_t *nodeCount)
{
    if (NULL == splay_node)
        return;

    cct_bb_node_t *bb_node = (cct_bb_node_t *)splay_node->payload;

    tranverseIPs(curIPNode, splay_node->left, nodeCount);

    for (slot_t i = 0; i < bb_node->max_slots; i++) {
        hpcviewer_format_ip_node_t *sameIP =
            findSameIP(&(curIPNode->childIPNodes),
                       drcctlib_priv_share_trans_ctxt_hndl_to_ip_node(bb_node->child_ctxt_start_idx + i));
        if (sameIP) {
            mergeIP(sameIP, drcctlib_priv_share_trans_ctxt_hndl_to_ip_node(bb_node->child_ctxt_start_idx + i),
                    nodeCount);
        } else {
            cct_ip_node_t *ip_node =
                drcctlib_priv_share_trans_ctxt_hndl_to_ip_node(bb_node->child_ctxt_start_idx + i);
            app_pc addr = drcctlib_priv_share_get_ip_from_ip_node(ip_node);
            hpcviewer_format_ip_node_t *new_fmt_node =
                constructIPNodeFromIP(curIPNode, addr, nodeCount);
            // curIPNode->childIPNodes.push_back(new_fmt_node);
            if (drcctlib_priv_share_get_ip_node_callee_splay_tree_root(ip_node)) {
                if (global_hpc_fmt_config.metric_cct) {
                    new_fmt_node->metricVal[0] = 0;
                }
                tranverseIPs(new_fmt_node, drcctlib_priv_share_get_ip_node_callee_splay_tree_root(ip_node),
                             nodeCount);
            } else {
                new_fmt_node->ID = -new_fmt_node->ID;
                if (global_hpc_fmt_config.metric_cct) {
                    new_fmt_node->metricVal[0] = 1;
                }
            }
        }
    }
    tranverseIPs(curIPNode, splay_node->right, nodeCount);
    return;
}

// Write out each IP's id, parent id, loadmodule id (1) and address
void
IPNode_fwrite(hpcviewer_format_ip_node_t *node, FILE *fs)
{
    if (node == NULL)
        return;
    hpcfmt_int4_fwrite(node->ID, fs);
    hpcfmt_int4_fwrite(node->parentID, fs);

    // adjust the IPaddress to point to return address of the callsite (internal nodes)
    // for hpcrun requirement

    if (node->IPAddress == 0) {
        hpcfmt_int2_fwrite(0, fs);
        hpcfmt_int8_fwrite((uint64_t)node->IPAddress, fs);
    } else {
        if (node->ID > 0)
            node->IPAddress++;
        module_data_t *info = dr_lookup_module(node->IPAddress);
        offline_module_data_t *off_module_data =
            (offline_module_data_t *)hashtable_lookup(&global_module_data_table,
                                                      (void *)info->start);
        hpcfmt_int2_fwrite(off_module_data->id, fs); // Set loadmodule id to 1
        // normalize the IP offset to the beginning of the load module and write out
        hpcfmt_int8_fwrite((uint64_t)(node->IPAddress - off_module_data->start), fs);
        dr_free_module_data(info);
    }

    // this uses .metric field in the hpcviewer_format_ip_node_t, which means we have per
    // cct_ip_node_t metric for this case, by default, we only have one metric
    for (int i = 0; i < global_hpc_fmt_config.metric_num; i++)
        hpcfmt_int8_fwrite(node->metricVal[i], fs);
    return;
}

// Tranverse and print the calling context tree (nodes first)
void
tranverseNewCCT(vector<hpcviewer_format_ip_node_t *> *nodes, FILE *fs)
{

    if ((*nodes).size() == 0)
        return;
    size_t i;

    for (i = 0; i < (*nodes).size(); i++) {
        IPNode_fwrite((*nodes).at(i), fs);
    }
    for (i = 0; i < (*nodes).size(); i++) {

        if ((*nodes).at(i)->childIPNodes.size() != 0) {
            tranverseNewCCT(&((*nodes).at(i)->childIPNodes), fs);
        }
    }
    return;
}

void
hpcrun_insert_path(hpcviewer_format_ip_node_t *root, HPCRunCCT_t *runNode,
                   uint64_t *nodeCount)
{
    if (runNode->ctxt_hndl_list.size() == 0) {
        return;
    }
    hpcviewer_format_ip_node_t *cur = root;
    for (uint32_t i = 0; i < runNode->ctxt_hndl_list.size(); i++) {
        context_handle_t cur_hndl = runNode->ctxt_hndl_list[i];
        if (cur_hndl == 0) {
            DRCCTLIB_PRINTF("USE ERROR: HPCRunCCT_t has invalid context_handle_t");
            break;
        }
        vector<app_pc> cur_pc_list;
        drcctlib_priv_share_get_full_calling_ip_vector(runNode->ctxt_hndl_list[i], cur_pc_list);
        for (int32_t i = cur_pc_list.size() - 1; i >= 0; i--) {
            hpcviewer_format_ip_node_t *tmp =
                findSameIPbyIP(cur->childIPNodes, cur_pc_list[i]);
            if (!tmp) {
                hpcviewer_format_ip_node_t *nIP =
                    constructIPNodeFromIP(cur, cur_pc_list[i], nodeCount);
                cur = nIP;
            } else {
                cur = tmp;
            }
        }
    }
    for (uint32_t i = 0; i < runNode->metric_list.size(); i++) {
        cur->metricVal[i] += runNode->metric_list[i];
    }
}

void
reset_leaf_node_id(hpcviewer_format_ip_node_t *root)
{
    if (root->childIPNodes.size() == 0) {
        root->ID = -root->ID;
    } else {
        for (uint32_t i = 0; i < root->childIPNodes.size(); i++) {
            reset_leaf_node_id(root->childIPNodes[i]);
        }
    }
}

// Initialize binary file and write hpcrun header
FILE *
lazy_open_data_file(int tID)
{
    const char *fileCharName = global_hpc_fmt_config.filename.c_str();
    int fd = hpcrun_open_profile_file(tID, fileCharName);
    FILE *fs = fdopen(fd, "w");

    if (fs == NULL)
        return NULL;
    const char *jobIdStr = OSUtil_jobid();

    if (!jobIdStr)
        jobIdStr = "";

    char mpiRankStr[bufSZ];
    mpiRankStr[0] = '0';
    snprintf(mpiRankStr, bufSZ, "%d", 0);
    char tidStr[bufSZ];
    snprintf(tidStr, bufSZ, "%d", tID);
    char hostidStr[bufSZ];
    snprintf(hostidStr, bufSZ, "%lx", OSUtil_hostid());
    char pidStr[bufSZ];
    snprintf(pidStr, bufSZ, "%u", OSUtil_pid());
    char traceMinTimeStr[bufSZ];
    snprintf(traceMinTimeStr, bufSZ, "%" PRIu64, (unsigned long int)0);
    char traceMaxTimeStr[bufSZ];
    snprintf(traceMaxTimeStr, bufSZ, "%" PRIu64, (unsigned long int)0);
    // ======  file hdr  =====
    hpcrun_fmt_hdrwrite(fs);
    static int global_arg_len = 9;
    hpcfmt_int4_fwrite(global_arg_len, fs);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_prog, fileCharName);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_progPath,
                          global_hpc_fmt_config.filename.c_str());
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_envPath, getenv("PATH"));
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_jobId, jobIdStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_tid, tidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_hostid, hostidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_pid, pidStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_traceMinTime, traceMinTimeStr);
    hpcrun_fmt_hdr_fwrite(fs, HPCRUN_FMT_NV_traceMaxTime, traceMaxTimeStr);
    hpcrun_fmt_epochHdr_fwrite(fs, epoch_flags, default_measurement_granularity,
                               default_ra_to_callsite_distance);
    // log the number of metrics
    hpcfmt_int4_fwrite((uint32_t)global_hpc_fmt_config.metric_num, fs);
    // log each metric
    for (int i = 0; i < global_hpc_fmt_config.metric_num; i++)
        hpcrun_set_metric_info_w_fn(i, global_hpc_fmt_config.metric_name_arry[i], 1, fs);
    hpcrun_fmt_loadmap_fwrite(fs);
    return fs;
}

#define ATOMC_ADD_MODULE_KEY(origin) dr_atomic_add32_return_sum(&origin, 1)
#define OFFLINE_MODULE_KEY_START 2
static inline int32_t
offline_module_get_next_key()
{
    static int32_t global_module_next_key = OFFLINE_MODULE_KEY_START;
    int32_t key = ATOMC_ADD_MODULE_KEY(global_module_next_key);
    return key - 1;
}

static inline offline_module_data_t *
offline_module_data_create(const module_data_t *info)
{
    offline_module_data_t *off_module_data =
        (offline_module_data_t *)dr_global_alloc(sizeof(offline_module_data_t));
    sprintf(off_module_data->path, "%s", info->full_path);
    off_module_data->start = info->start;
    off_module_data->end = info->end;
    if (strcmp(dr_module_preferred_name(info), global_hpc_fmt_config.filename.c_str()) ==
        0) {
#ifdef ARM_CCTLIB
        off_module_data->start = 0;
#endif
        off_module_data->app = true;
        off_module_data->id = 1;
    } else {
        off_module_data->app = false;
        off_module_data->id = offline_module_get_next_key();
    }
    return off_module_data;
}

static inline void
offline_module_data_free(void *data)
{
    offline_module_data_t *mdata = (offline_module_data_t *)data;
    dr_global_free(mdata, sizeof(offline_module_data_t));
}

static void
event_module_load_analysis(void *drcontext, const module_data_t *info,
                                    bool loaded)
{
    dr_mutex_lock(module_data_lock);
    void *offline_data =
        hashtable_lookup(&global_module_data_table, (void *)info->start);
    if (offline_data == NULL) {
        offline_data = (void *)offline_module_data_create(info);
        hashtable_add(&global_module_data_table, (void *)(ptr_int_t)info->start,
                        offline_data);
    }
    dr_mutex_unlock(module_data_lock);
}

static void
event_thread_start(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_global_alloc(sizeof(per_thread_t));
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);
    pt->nodeCount = 0;
    pt->tlsHPCRunCCTRoot = NULL;
    pt->id = drcctlib_priv_share_get_thread_id();
}

static void
event_thread_end(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    dr_global_free(pt, sizeof(per_thread_t));
}

/*======APIs to support hpcviewer format======*/
/*
 * Initialize the formatting preparation
 * (called by the clients)
 * TODO: initialize metric table, provide custom metric merge functions
 */
DR_EXPORT
void
hpcrun_format_init(const char *app_name, bool metric_cct)
{
    global_hpc_fmt_config.filename = app_name;
    // Create the measurement directory
    global_hpc_fmt_config.dirName =
        "hpctoolkit-" + global_hpc_fmt_config.filename + "-measurements";
    mkdir(global_hpc_fmt_config.dirName.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    // the current metric cursor is set to 1
    global_hpc_fmt_config.metric_num = 0;
    global_hpc_fmt_config.metric_cct = metric_cct;
    if (metric_cct) {
        hpcrun_create_metric("CCT");
    }
    module_data_lock = dr_mutex_create();
    hashtable_init_ex(&global_module_data_table, OFFLINE_MODULE_DATA_TABLE_HASH_BITS,
                          HASH_INTPTR, false /*!strdup*/, false /*!synch*/,
                          offline_module_data_free, NULL, NULL);
    drmgr_init();
    drmgr_register_module_load_event(event_module_load_analysis);
    tls_idx = drmgr_register_tls_field();
    drmgr_priority_t thread_init_pri = { sizeof(thread_init_pri), "hpcviewer_format-thread_init",
                                         NULL, NULL, DRCCTLIB_THREAD_EVENT_PRI + 100 };
    drmgr_priority_t thread_exit_pri = { sizeof(thread_exit_pri), "hpcviewer_format-thread_exit",
                                         NULL, NULL, DRCCTLIB_THREAD_EVENT_PRI + 100 };
    drmgr_register_thread_init_event_ex(event_thread_start, &thread_init_pri);
    drmgr_register_thread_exit_event_ex(event_thread_end, &thread_exit_pri);
}

DR_EXPORT
void
hpcrun_format_exit()
{
    drmgr_unregister_module_load_event(event_module_load_analysis);
    drmgr_unregister_tls_field(tls_idx);
    drmgr_unregister_thread_init_event(event_thread_start);
    drmgr_unregister_thread_exit_event(event_thread_end);
    drmgr_exit();

    hashtable_delete(&global_module_data_table);
    dr_mutex_destroy(module_data_lock);

}

/*
 * API to create new metric
 */
DR_EXPORT
int
hpcrun_create_metric(const char *name)
{
    int t = global_hpc_fmt_config.metric_num;
    strcpy(global_hpc_fmt_config.metric_name_arry[global_hpc_fmt_config.metric_num++], name);
    return t;
}

/*
 * Write the calling context tree of 'threadid' thread
 * (Called from client program)
 */
DR_EXPORT
int
write_thread_all_cct_hpcrun_format(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    FILE *fs = lazy_open_data_file(pt->id);
    if (!fs)
        return -1;
    cct_bb_node_t *root_bb_node = 
        drcctlib_priv_share_get_thread_root_bb_node(pt->id);

    vector<hpcviewer_format_ip_node_t *> fmt_ip_node_vector;
    for (slot_t i = 0; i < root_bb_node->max_slots; i++) {
        cct_ip_node_t *ip_node =
            drcctlib_priv_share_trans_ctxt_hndl_to_ip_node(root_bb_node->child_ctxt_start_idx + i);
        hpcviewer_format_ip_node_t *fmt_ip_node =
            constructIPNodeFromIP(NULL, (app_pc)0, &pt->nodeCount);
        fmt_ip_node_vector.push_back(fmt_ip_node);
        if (drcctlib_priv_share_get_ip_node_callee_splay_tree_root(ip_node)) {
            if (global_hpc_fmt_config.metric_cct) {
                fmt_ip_node->metricVal[0] = 0;
            }
            tranverseIPs(fmt_ip_node, drcctlib_priv_share_get_ip_node_callee_splay_tree_root(ip_node),
                         &pt->nodeCount);
        } else {
            fmt_ip_node->ID = -fmt_ip_node->ID;
            if (global_hpc_fmt_config.metric_cct) {
                fmt_ip_node->metricVal[0] = 1;
            }
        }
    }
    hpcfmt_int8_fwrite(pt->nodeCount, fs);
    tranverseNewCCT(&fmt_ip_node_vector, fs);
    hpcio_fclose(fs);
    return 0;
}

// This API is used to output a hpcrun CCT with selected call paths
DR_EXPORT
int
build_thread_custom_cct_hpurun_format(vector<HPCRunCCT_t *> &run_cct_list,
                                      void *drcontext)
{

    // build the hpcrun-style CCT
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    // initialize the root node (dummy node)
    if (!pt->tlsHPCRunCCTRoot) {
        pt->tlsHPCRunCCTRoot = new hpcviewer_format_ip_node_t();
        pt->tlsHPCRunCCTRoot->childIPNodes.clear();
        pt->tlsHPCRunCCTRoot->IPAddress = 0;
        pt->tlsHPCRunCCTRoot->ID = get_fmt_ip_node_new_id();
        if (global_hpc_fmt_config.metric_num > 0) {
            pt->tlsHPCRunCCTRoot->metricVal =
                new uint64_t[global_hpc_fmt_config.metric_num];
            for (int i = 0; i < global_hpc_fmt_config.metric_num; i++)
                pt->tlsHPCRunCCTRoot->metricVal[i] = 0;
        }
        pt->nodeCount = 1;
    }

    hpcviewer_format_ip_node_t *root = pt->tlsHPCRunCCTRoot;
    vector<HPCRunCCT_t *>::iterator it;
    for (it = run_cct_list.begin(); it != run_cct_list.end(); ++it) {
        hpcrun_insert_path(root, *it, &pt->nodeCount);
    }
    reset_leaf_node_id(pt->tlsHPCRunCCTRoot);
    return 0;
}

// output the CCT
DR_EXPORT
int
write_thread_custom_cct_hpurun_format(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    FILE *fs = lazy_open_data_file(pt->id);
    if (!fs)
        return -1;

    hpcviewer_format_ip_node_t *fmt_root_ip = pt->tlsHPCRunCCTRoot;

    vector<hpcviewer_format_ip_node_t *> fmt_ip_node_vector;
    for (uint32_t i = 0; i < fmt_root_ip->childIPNodes.size(); i++) {
        fmt_ip_node_vector.push_back(fmt_root_ip->childIPNodes[i]);
    }

    hpcfmt_int8_fwrite(pt->nodeCount, fs);
    IPNode_fwrite(fmt_root_ip, fs);
    tranverseNewCCT(&fmt_ip_node_vector, fs);
    hpcio_fclose(fs);
    return 0;
}

// This API is used to output a hpcrun CCT with selected call paths
DR_EXPORT
int
build_progress_custom_cct_hpurun_format(vector<HPCRunCCT_t *> &run_cct_list)
{
    // initialize the root node (dummy node)
    global_hpc_fmt_config.gHPCRunCCTRoot = new hpcviewer_format_ip_node_t();
    global_hpc_fmt_config.gHPCRunCCTRoot->childIPNodes.clear();
    global_hpc_fmt_config.gHPCRunCCTRoot->IPAddress = 0;
    global_hpc_fmt_config.gHPCRunCCTRoot->ID = get_fmt_ip_node_new_id();
    if (global_hpc_fmt_config.metric_num > 0) {
        global_hpc_fmt_config.gHPCRunCCTRoot->metricVal =
            new uint64_t[global_hpc_fmt_config.metric_num];
        for (int i = 0; i < global_hpc_fmt_config.metric_num; i++)
            global_hpc_fmt_config.gHPCRunCCTRoot->metricVal[i] = 0;
    }
    global_hpc_fmt_config.nodeCount = 1;

    hpcviewer_format_ip_node_t *root = global_hpc_fmt_config.gHPCRunCCTRoot;
    vector<HPCRunCCT_t *>::iterator it;
    for (it = run_cct_list.begin(); it != run_cct_list.end(); ++it) {
        hpcrun_insert_path(root, *it, &global_hpc_fmt_config.nodeCount);
    }
    reset_leaf_node_id(global_hpc_fmt_config.gHPCRunCCTRoot);
    return 0;
}

// output the CCT
DR_EXPORT
int
write_progress_custom_cct_hpurun_format()
{
    FILE *fs = lazy_open_data_file(0);
    if (!fs)
        return -1;
    hpcviewer_format_ip_node_t *fmt_root_ip = global_hpc_fmt_config.gHPCRunCCTRoot;
    vector<hpcviewer_format_ip_node_t *> fmt_ip_node_vector;
    for (uint32_t i = 0; i < fmt_root_ip->childIPNodes.size(); i++) {
        fmt_ip_node_vector.push_back(fmt_root_ip->childIPNodes[i]);
    }

    hpcfmt_int8_fwrite(global_hpc_fmt_config.nodeCount, fs);
    IPNode_fwrite(fmt_root_ip, fs);
    tranverseNewCCT(&fmt_ip_node_vector, fs);
    hpcio_fclose(fs);
    return 0;
}

// ************************************************************