/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */
#include <vector>
#include <string>
#include <string.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drsyms.h"
#include "drwrap.h"
#include "drcctlib.h"

#include "dr_go_wrap.h"
#include "elf_utils.h"
#include "cgo_funcs.h"

using namespace std;

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("goroutines", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("goroutines", _FORMAT, ##_ARGS)

#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    ifdef CCTLIB_64
#        define OPND_CREATE_CCT_INT OPND_CREATE_INT64
#    else
#        define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#    endif
#endif

typedef struct _mutex_ctxt_t{
    app_pc state_addr;
    context_handle_t create_context;
} mutex_ctxt_t;

typedef struct _mem_ref_t {
    app_pc addr;
    uint64_t state;
} mem_ref_t;

typedef struct _per_thread_t {
    thread_id_t thread_id;
    mem_ref_t *cur_buf_list;
    void *cur_buf;
    vector<context_handle_t> call_rt_exec_list;
    vector<int64_t> goid_list;
    vector<vector<int64_t>> go_ancestors_list;
} per_thread_t;

#define TLS_MEM_REF_BUFF_SIZE 100

static int tls_idx;
enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static reg_id_t tls_seg;
static uint tls_offs;
#define TLS_SLOT(tls_base, enum_val) (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base, type, offs) *(type **)TLS_SLOT(tls_base, offs)
#define MINSERT instrlist_meta_preinsert

static file_t gTraceFile;
static void *thread_sync_lock;

static std::vector<std::string> blacklist;
static go_moduledata_t* go_firstmoduledata;
static vector<mutex_ctxt_t> mutex_ctxt_list;


// client want to do
void
CheckLockState(void *drcontext, int64_t cur_goid, context_handle_t cur_ctxt_hndl, mem_ref_t *ref)
{
    app_pc addr = ref->addr;
    // DRCCTLIB_PRINTF("addr %p", ref->addr);
    for (size_t i = 0; i < mutex_ctxt_list.size(); i++) {
        if (addr == mutex_ctxt_list[i].state_addr) {
            DRCCTLIB_PRINTF("GOID(%d) LOCK %d(%d)", cur_goid, mutex_ctxt_list[i].create_context, ref->state);
            break;
        }
    }
}

void
CheckUnlockState(void *drcontext, int64_t cur_goid, context_handle_t cur_ctxt_hndl, mem_ref_t *ref)
{
    app_pc addr = ref->addr;
    // DRCCTLIB_PRINTF("addr %p", ref->addr);
    for (size_t i = 0; i < mutex_ctxt_list.size(); i++) {
        if (addr == mutex_ctxt_list[i].state_addr) {
            DRCCTLIB_PRINTF("GOID(%d) Unlock %d(%d)", cur_goid, mutex_ctxt_list[i].create_context, ref->state);
            break;
        }
    }
}

// dr clean call
void
InsertCleancall(int32_t slot, int32_t num, int32_t state)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    int64_t cur_goid = 0;
    if(pt->goid_list.size() > 0) {
        cur_goid = pt->goid_list.back();
    }
    for (int i = 0; i < num; i++) {
        if (pt->cur_buf_list[i].addr != 0 && pt->cur_buf_list[i].state == 0) {
            if(state == 1) {
                CheckLockState(drcontext, cur_goid, cur_ctxt_hndl, &pt->cur_buf_list[i]);
            } else if (state == 2) {
                CheckUnlockState(drcontext, cur_goid, cur_ctxt_hndl, &pt->cur_buf_list[i]);
            }
        }
    }
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
}

// insert
static void
InstrumentMem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref,
              reg_id_t free_reg, uint64_t state)
{
    /* We need two scratch registers */
    reg_id_t reg_mem_ref_ptr;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_mem_ref_ptr) !=
        DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_reserve_register != DRREG_SUCCESS");
    }
    if (!drutil_insert_get_mem_addr(drcontext, ilist, where, ref, free_reg,
                                    reg_mem_ref_ptr)) {
        MINSERT(ilist, where,
                XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                      OPND_CREATE_CCT_INT(0)));
    }
    dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg,
                           tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, addr)),
                opnd_create_reg(free_reg)));
    
    // store mem_ref_t->addr
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(state)));
    MINSERT(ilist, where,
            XINST_CREATE_store(
                drcontext, OPND_CREATE_MEMPTR(reg_mem_ref_ptr, offsetof(mem_ref_t, state)),
                opnd_create_reg(free_reg)));

#ifdef ARM_CCTLIB
    MINSERT(ilist, where,
            XINST_CREATE_load_int(drcontext, opnd_create_reg(free_reg),
                                  OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             opnd_create_reg(free_reg)));
#else
    MINSERT(ilist, where,
            XINST_CREATE_add(drcontext, opnd_create_reg(reg_mem_ref_ptr),
                             OPND_CREATE_CCT_INT(sizeof(mem_ref_t))));
#endif
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg,
                            tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_mem_ref_ptr);
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_mem_ref_ptr) !=
        DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("InstrumentMem drreg_unreserve_register != DRREG_SUCCESS");
    }
}


// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{
    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;
    int64_t state = 0;
    if (instr_get_prefix_flag(instr, PREFIX_LOCK) &&
        (instr_get_opcode(instr) == OP_cmpxchg ||
         instr_get_opcode(instr) == OP_cmpxchg8b ||
         instr_get_opcode(instr) == OP_cmpxchg16b)) {
        state = 1;
    }

    if (instr_get_prefix_flag(instr, PREFIX_LOCK) &&
        instr_get_opcode(instr) == OP_xadd) {
        state = 2;
    }
    if (state == 0){
        return;
    }
    int num = 0;
#ifdef x86_CCTLIB
    if (drreg_reserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("instrument_before_every_instr_meta_instr "
                              "drreg_reserve_aflags != DRREG_SUCCESS");
    }
#endif
    reg_id_t reg_temp;
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_temp) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "InstrumentInsCallback drreg_reserve_register != DRREG_SUCCESS");
    }
    for (int i = 0; i < instr_num_srcs(instr); i++) {
        if (opnd_is_memory_reference(instr_get_src(instr, i))) {
            InstrumentMem(drcontext, bb, instr, instr_get_src(instr, i), reg_temp, 0);
            num++;
        }
    }
    for (int i = 0; i < instr_num_dsts(instr); i++) {
        if (opnd_is_memory_reference(instr_get_dst(instr, i))) {
            InstrumentMem(drcontext, bb, instr, instr_get_dst(instr, i), reg_temp, 1);
            num++;
        }
    }
    if (drreg_unreserve_register(drcontext, bb, instr, reg_temp) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "InstrumentInsCallback drreg_unreserve_register != DRREG_SUCCESS");
    }
#ifdef x86_CCTLIB
    if (drreg_unreserve_aflags(drcontext, bb, instr) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS("drreg_unreserve_aflags != DRREG_SUCCESS");
    }
#endif
    dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 3,
                        OPND_CREATE_CCT_INT(slot), OPND_CREATE_CCT_INT(num), OPND_CREATE_CCT_INT(state));
    // }
}

static void
WrapBeforeRTExecute(void *wrapcxt, void **user_data)
{
    void *drcontext = (void *)drwrap_get_drcontext(wrapcxt);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    go_g_t* go_g_ptr = (go_g_t*)dgw_get_go_func_arg(wrapcxt, 0);
    context_handle_t cur_context = drcctlib_get_context_handle(drcontext);
    pt->call_rt_exec_list.push_back(cur_context);
    pt->goid_list.push_back(go_g_ptr->goid);

    vector<int64_t> ancestors;
    go_slice_t* ancestors_ptr = go_g_ptr->ancestors;
    if (ancestors_ptr != NULL) {
        go_ancestor_info_t* ancestor_infor_array = (go_ancestor_info_t*)ancestors_ptr->data;
        for(int i = 0; i < ancestors_ptr->len; i++) {
                ancestors.push_back(ancestor_infor_array[i].goid);
        }
    }
    pt->go_ancestors_list.push_back(ancestors);
}

static void
WrapBeforeRTNewObj(void *wrapcxt, void **user_data)
{
    go_type_t* go_type_ptr = (go_type_t*)dgw_get_go_func_arg(wrapcxt, 0);
    *user_data = (void*)(go_type_ptr);
}

static void
WrapEndRTNewObj(void *wrapcxt, void *user_data)
{
    go_type_t* go_type_ptr = (go_type_t*)user_data;
    string type_str = cgo_get_type_name_string(go_type_ptr, go_firstmoduledata);
    if(strcmp(type_str.c_str(), "sync.Mutex") == 0) {
        go_type_sync_mutex_t* ret_ptr = (go_type_sync_mutex_t*)dgw_get_go_func_retaddr(wrapcxt, 1, 0);
        void* drcontext = (void *)drwrap_get_drcontext(wrapcxt); 
        context_handle_t cur_context = drcctlib_get_context_handle(drcontext);
        mutex_ctxt_t mutxt_ctxt = {(app_pc)(&(ret_ptr->state)), cur_context};
        // DRCCTLIB_PRINTF("mutxt_ctxt %p %d", mutxt_ctxt.state_addr, mutxt_ctxt.create_context);
        mutex_ctxt_list.push_back(mutxt_ctxt);
    }
}

static go_moduledata_t*
GetGoFirstmoduledata(const module_data_t *info)
{
    file_t fd = dr_open_file(info->full_path, DR_FILE_READ);
    uint64 file_size;
    if (fd == INVALID_FILE) {
        if (strcmp(info->full_path, "[vdso]") != 0) {
            DRCCTLIB_PRINTF("------ unable to open %s", info->full_path);
        }
        return NULL;
    }
    if (!dr_file_size(fd, &file_size)) {
        DRCCTLIB_PRINTF("------ unable to get file size %s", info->full_path);
        return NULL;
    }
    size_t map_size = file_size;
    void *map_base = dr_map_file(fd, &map_size, 0, NULL, DR_MEMPROT_READ, DR_MAP_PRIVATE);
    /* map_size can be larger than file_size */
    if (map_base == NULL || map_size < file_size) {
        DRCCTLIB_PRINTF("------ unable to map %s", info->full_path);
        return NULL;
    }
    go_moduledata_t* firstmoduledata = NULL;
    // in memory
    Elf *elf = elf_memory((char *)map_base, map_size); // Initialize 'elf' pointer to our file descriptor
    if(find_elf_section_by_name(elf, ".go.buildinfo")) {
        uint64_t gopclntab_addr = 0;
        Elf_Scn *gopclntab_scn = find_elf_section_by_name(elf, ".gopclntab");
        if(gopclntab_scn) {
            Elf_Shdr *section_header = elf_getshdr(gopclntab_scn);
            gopclntab_addr = section_header->sh_addr;
            // DRCCTLIB_PRINTF(".gopclntab start addr %p", gopclntab_addr);
        }
        Elf_Scn *noptrdata_scn = find_elf_section_by_name(elf, ".noptrdata");
        if(noptrdata_scn) {
            Elf_Shdr *section_header = elf_getshdr(noptrdata_scn);
            uint64_t start_addr = section_header->sh_addr;
            uint64_t end_addr = start_addr + section_header->sh_size * 8;
            // DRCCTLIB_PRINTF("module start addr %p, end addr %p", start_addr, end_addr);
            for(uint64_t temp = start_addr; temp < end_addr; temp += 8) {
                if (*((uint64_t*)temp)== gopclntab_addr) {
                    firstmoduledata = (go_moduledata_t*) temp;
                    break;
                }
            }
        }
    }
    dr_unmap_file(map_base, map_size);
    dr_close_file(fd);
    return firstmoduledata;
}


static inline app_pc
moudle_get_function_entry(const module_data_t *info, const char *func_name,
                          bool check_internal_func)
{
    app_pc functionEntry;
    if (check_internal_func) {
        size_t offs;
        if (drsym_lookup_symbol(info->full_path, func_name, &offs, DRSYM_DEMANGLE) ==
            DRSYM_SUCCESS) {
            functionEntry = offs + info->start;
        } else {
            functionEntry = NULL;
        }
    } else {
        functionEntry = (app_pc)dr_get_proc_address(info->handle, func_name);
    }
    return functionEntry;
}

static void
OnMoudleLoad(void *drcontext, const module_data_t *info,
                                    bool loaded)
{
    const char *modname = dr_module_preferred_name(info);
    for (std::vector<std::string>::iterator i = blacklist.begin();
            i != blacklist.end(); ++i) {
        if(strstr(modname, (*i).c_str())) {
            return;
        }
    }
    if(go_firstmoduledata == NULL) {
        go_firstmoduledata = GetGoFirstmoduledata(info);
    }
    app_pc func_rt_newobj_entry = moudle_get_function_entry(info, "runtime.newobject", true);
    if (func_rt_newobj_entry != NULL) {
        drwrap_wrap(func_rt_newobj_entry, WrapBeforeRTNewObj, WrapEndRTNewObj);
    }

    app_pc func_entry = moudle_get_function_entry(info, "runtime.execute", true);
    if (func_entry != NULL) {
        drwrap_wrap(func_entry, WrapBeforeRTExecute, NULL);
    }
    // DRCCTLIB_PRINTF("finish module name %s", modname);
}

static void
PrintAllRTExec(per_thread_t *pt)
{
    dr_mutex_lock(thread_sync_lock);
    for (uint64_t i = 0; i < pt->goid_list.size(); i++) {
        context_handle_t exec_ctxt = pt->call_rt_exec_list[i];
        dr_fprintf(gTraceFile, "\nthread(%ld) runtime.execute to test_goid(%d)", pt->thread_id, pt->goid_list[i]);    
        drcctlib_print_ctxt_hndl_msg(gTraceFile, exec_ctxt, false, false);

        if(pt->go_ancestors_list[i].size() > 0) {
            dr_fprintf(gTraceFile, "created by Goroutine(s) ");
            for (uint64_t j = 0; j < pt->go_ancestors_list[i].size(); j++) {
                if (j) {
                    dr_fprintf(gTraceFile, " -> ");
                }
                dr_fprintf(gTraceFile, "%ld", pt->go_ancestors_list[i][j]);
            }
            dr_fprintf(gTraceFile, "\n");
        }

        dr_fprintf(gTraceFile,
                   "====================================================================="
                   "===========\n");
        drcctlib_print_full_cct(gTraceFile, exec_ctxt, true, true,
                                -1);
        dr_fprintf(gTraceFile,
                   "====================================================================="
                   "===========\n\n\n");
    }
    dr_mutex_unlock(thread_sync_lock);
}

static void
InitMoudlesBlacklist()
{
    blacklist.push_back("libdrcctlib_goroutines.so");
    blacklist.push_back("libdynamorio.so");
    blacklist.push_back("linux-vdso.so");
}

static void
ClientThreadStart(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    if (pt == NULL) {
        DRCCTLIB_EXIT_PROCESS("pt == NULL");
    }
    drmgr_set_tls_field(drcontext, tls_idx, (void *)pt);
    pt->thread_id = dr_get_thread_id(drcontext);
    pt->cur_buf = dr_get_dr_segment_base(tls_seg);
    pt->cur_buf_list =
        (mem_ref_t *)dr_global_alloc(TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    BUF_PTR(pt->cur_buf, mem_ref_t, INSTRACE_TLS_OFFS_BUF_PTR) = pt->cur_buf_list;
    
}

static void
ClientThreadEnd(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    PrintAllRTExec(pt);
    dr_global_free(pt->cur_buf_list, TLS_MEM_REF_BUFF_SIZE * sizeof(mem_ref_t));
    dr_thread_free(drcontext, pt, sizeof(per_thread_t));
}


bool
InterestInstrFilter(instr_t *instr)
{
    return  instr_get_prefix_flag(instr, PREFIX_LOCK) && 
        (instr_get_opcode(instr) == OP_cmpxchg ||
        instr_get_opcode(instr) == OP_cmpxchg8b ||
        instr_get_opcode(instr) == OP_cmpxchg16b ||
        instr_get_opcode(instr) == OP_xadd);
}

static void
ClientInit(int argc, const char *argv[])
{
    char name[MAXIMUM_PATH] = "";
    DRCCTLIB_INIT_LOG_FILE_NAME(name, "drcctlib_goroutines", "out");
    DRCCTLIB_PRINTF("Creating log file at:%s", name);

    gTraceFile = dr_open_file(name, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    DR_ASSERT(gTraceFile != INVALID_FILE);
    // print the arguments passed
    dr_fprintf(gTraceFile, "\n");
    for (int i = 0; i < argc; i++) {
        dr_fprintf(gTraceFile, "%d %s ", i, argv[i]);
    }
    dr_fprintf(gTraceFile, "\n");

    if (!drmgr_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "unable to initialize drmgr");
    }
    drreg_options_t ops = { sizeof(ops), 4 /*max slots needed*/, false };
    if (drreg_init(&ops) != DRREG_SUCCESS) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance_client_cache unable to initialize drreg");
    }
    if (!drutil_init()) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance_client_cache unable to initialize drutil");
    }
    if (!drwrap_init()) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "unable to initialize drwrap");
    }

    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "drmgr_register_tls_field fail");
    }
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, INSTRACE_TLS_COUNT, 0)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance_client_cache dr_raw_tls_calloc fail");
    }
    drmgr_register_thread_init_event(ClientThreadStart);
    drmgr_register_thread_exit_event(ClientThreadEnd);

    drmgr_priority_t before_drcctlib_module_load = { sizeof(before_drcctlib_module_load), "before_drcctlib_module_load",
                                         NULL, NULL, DRCCTLIB_MODULE_REGISTER_PRI + 1 };
    drmgr_register_module_load_event_ex(OnMoudleLoad, &before_drcctlib_module_load);

    drcctlib_init(InterestInstrFilter, INVALID_FILE, InstrumentInsCallback,
                  false);
    if (drsym_init(0) != true) {
        DRCCTLIB_EXIT_PROCESS("ERROR: drcctlib_goroutines "
                              "unable to initialize drsym");
    }
    thread_sync_lock = dr_mutex_create();
    InitMoudlesBlacklist();
}

static void
ClientExit(void)
{
    drcctlib_exit();

    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DRCCTLIB_EXIT_PROCESS(
            "ERROR: drcctlib_reuse_distance_client_cache dr_raw_tls_calloc fail");
    }

    if (!drmgr_unregister_thread_init_event(ClientThreadStart) ||
        !drmgr_unregister_thread_exit_event(ClientThreadEnd) ||
        !drmgr_unregister_tls_field(tls_idx)) {
        DRCCTLIB_PRINTF(
            "ERROR: drcctlib_goroutines failed to "
            "unregister in ClientExit");
    }

    if (drsym_exit() != DRSYM_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drsym");
    }
    drwrap_exit();
    drmgr_exit();
    if (drreg_exit() != DRREG_SUCCESS) {
        DRCCTLIB_PRINTF("failed to exit drreg");
    }
    drutil_exit();
    dr_mutex_destroy(thread_sync_lock);
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name(
        "DynamoRIO Client 'drcctlib_goroutines'",
        "http://dynamorio.org/issues");
    ClientInit(argc, argv);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif