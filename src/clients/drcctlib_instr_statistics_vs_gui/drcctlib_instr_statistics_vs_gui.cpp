/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include <iterator>
#include <vector>
#include <map>

#include "dr_api.h"
#include "drcctlib.h"

#define DRCCTLIB_PRINTF(_FORMAT, _ARGS...) \
    DRCCTLIB_PRINTF_TEMPLATE("instr_statistics", _FORMAT, ##_ARGS)
#define DRCCTLIB_EXIT_PROCESS(_FORMAT, _ARGS...) \
    DRCCTLIB_CLIENT_EXIT_PROCESS_TEMPLATE("instr_statistics", _FORMAT, ##_ARGS)

#ifdef ARM_CCTLIB
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT
#else
#    define OPND_CREATE_CCT_INT OPND_CREATE_INT32
#endif

#define MAX_CLIENT_CCT_PRINT_DEPTH 10
#define TOP_REACH_NUM_SHOW 200

uint64_t *gloabl_hndl_call_num;
static file_t flameGraphJson;
static file_t ctxtMapJson;
static file_t callPathJson;

using namespace std;

// client want to do
void
DoWhatClientWantTodo(void *drcontext, context_handle_t cur_ctxt_hndl)
{
    // use {cur_ctxt_hndl}
    gloabl_hndl_call_num[cur_ctxt_hndl]++;
}

// dr clean call
void
InsertCleancall(int32_t slot)
{
    void *drcontext = dr_get_current_drcontext();
    context_handle_t cur_ctxt_hndl = drcctlib_get_context_handle(drcontext, slot);
    DoWhatClientWantTodo(drcontext, cur_ctxt_hndl);
}

// analysis
void
InstrumentInsCallback(void *drcontext, instr_instrument_msg_t *instrument_msg)
{

    instrlist_t *bb = instrument_msg->bb;
    instr_t *instr = instrument_msg->instr;
    int32_t slot = instrument_msg->slot;

    dr_insert_clean_call(drcontext, bb, instr, (void *)InsertCleancall, false, 1, OPND_CREATE_CCT_INT(slot));
}

static inline void
InitGlobalBuff()
{
    gloabl_hndl_call_num = (uint64_t *)dr_raw_mem_alloc(
        CONTEXT_HANDLE_MAX * sizeof(uint64_t), DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    if (gloabl_hndl_call_num == NULL) {
        DRCCTLIB_EXIT_PROCESS(
            "init_global_buff error: dr_raw_mem_alloc fail gloabl_hndl_call_num");
    }
}

static inline void
FreeGlobalBuff()
{
    dr_raw_mem_free(gloabl_hndl_call_num, CONTEXT_HANDLE_MAX * sizeof(uint64_t));
}

static void
ClientInit(int argc, const char *argv[])
{
    flameGraphJson = dr_open_file("flame-graph.json", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    ctxtMapJson = dr_open_file("ctxt-map.json", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    callPathJson = dr_open_file("call-path.json", DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);

    InitGlobalBuff();
    drcctlib_init(DRCCTLIB_FILTER_ALL_INSTR, INVALID_FILE, InstrumentInsCallback, false);
}

typedef struct _output_format_t {
    context_handle_t handle;
    uint64_t count;
} output_format_t;

typedef struct _tree_item_t {
    context_handle_t handle;
    uint64_t value;
    vector<struct _tree_item_t*>* child_list;
} tree_item_t;

static void
PrintTreeItem(tree_item_t* item){
    if (!item) {
        return;
    }
    inner_context_t * cct_list = drcctlib_get_cct(item->handle, 0);
    if(cct_list != NULL) {
        dr_fprintf(flameGraphJson, "\n{");
        dr_fprintf(flameGraphJson, "\n\"ctxt_hndl\": \"%llu\",", item->handle);
        dr_fprintf(flameGraphJson, "\n\"name\": \"%s:%d(%s)\",", cct_list->func_name, cct_list->line_no,cct_list->code_asm);
        dr_fprintf(flameGraphJson, "\n\"value\": %llu,", item->value);
        dr_fprintf(flameGraphJson, "\n\"children\": [");
        vector<tree_item_t*>::iterator c_it = (*(item->child_list)).begin();
        for(; c_it != (*(item->child_list)).end(); ) {
            PrintTreeItem(*c_it);
            c_it++;
            if(c_it != (*(item->child_list)).end()) {
                dr_fprintf(flameGraphJson, ",");
            }
        }
        dr_fprintf(flameGraphJson, "]\n}");
    }
}

static void
ClientExit(void)
{
    output_format_t *output_list =
        (output_format_t *)dr_global_alloc(TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        output_list[i].handle = 0;
        output_list[i].count = 0;
    }
    context_handle_t max_ctxt_hndl = drcctlib_get_global_context_handle_num();
    for (context_handle_t i = 0; i < max_ctxt_hndl; i++) {
        if (gloabl_hndl_call_num[i] <= 0) {
            continue;
        }
        if (gloabl_hndl_call_num[i] > output_list[0].count) {
            uint64_t min_count = gloabl_hndl_call_num[i];
            int32_t min_idx = 0;
            for (int32_t j = 1; j < TOP_REACH_NUM_SHOW; j++) {
                if (output_list[j].count < min_count) {
                    min_count = output_list[j].count;
                    min_idx = j;
                }
            }
            output_list[0].count = min_count;
            output_list[0].handle = output_list[min_idx].handle;
            output_list[min_idx].count = gloabl_hndl_call_num[i];
            output_list[min_idx].handle = i;
        }
    }

    output_format_t temp;
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        for (int32_t j = i; j < TOP_REACH_NUM_SHOW; j++) {
            if (output_list[i].count < output_list[j].count) {
                temp = output_list[i];
                output_list[i] = output_list[j];
                output_list[j] = temp;
            }
        }
    }

    map<context_handle_t, tree_item_t*> tree_item_map;
    tree_item_t* tree_root = NULL;
    for (int32_t i = 0; i < TOP_REACH_NUM_SHOW; i++) {
        inner_context_t * cct_list = drcctlib_get_full_cct(output_list[i].handle);
        inner_context_t * cur_list = cct_list;
        tree_item_t* last_tree_item = NULL;
        while (cur_list != NULL) {
            map<context_handle_t, tree_item_t*>::iterator it = tree_item_map.find(cur_list->ctxt_hndl);
            if(it != tree_item_map.end()) {
                it->second->value += output_list[i].count;
                if(last_tree_item) {
                    vector<tree_item_t*>::iterator c_it = (*(it->second->child_list)).begin();
                    for(; c_it != (*(it->second->child_list)).end(); c_it++) {
                        if((*c_it) == last_tree_item) {
                            break;
                        }
                    }
                    if(c_it == (*(it->second->child_list)).end()) {
                        (*(it->second->child_list)).push_back(last_tree_item);
                    }
                }
                last_tree_item = it->second;
            } else {
                tree_item_t* tree_item = (tree_item_t*)malloc(sizeof(tree_item_t));
                tree_item->handle = cur_list->ctxt_hndl;
                tree_item->value = output_list[i].count;
                tree_item->child_list = new vector<tree_item_t*>();
                if(last_tree_item) {
                    (*(tree_item->child_list)).push_back(last_tree_item);
                }
                tree_item_map.insert(pair<context_handle_t, tree_item_t*>(cur_list->ctxt_hndl, tree_item));
                last_tree_item = tree_item;
            }
            tree_root = last_tree_item;
            cur_list = cur_list->pre_ctxt;
        }
        drcctlib_free_cct(cct_list);
    }
    PrintTreeItem(tree_root);

    dr_fprintf(ctxtMapJson, "{");
    for (map<context_handle_t, tree_item_t*>::iterator it = tree_item_map.begin(); it != tree_item_map.end(); it++) {
        inner_context_t * cct_list = drcctlib_get_cct(it->first, 0);
        if(cct_list != NULL) {
            dr_fprintf(ctxtMapJson, "\n    \"%llu\":{", cct_list->ctxt_hndl);
            dr_fprintf(ctxtMapJson, "\n        \"pc\": \"%p\",", cct_list->ip);
            dr_fprintf(ctxtMapJson, "\n        \"name\": \"%s\",", cct_list->func_name);
            dr_fprintf(ctxtMapJson, "\n        \"file_path\": \"%s\",", cct_list->file_path);
            dr_fprintf(ctxtMapJson, "\n        \"asm\": \"%s\",", cct_list->code_asm);
            dr_fprintf(ctxtMapJson, "\n        \"line_no\": %d,", cct_list->line_no);
            dr_fprintf(ctxtMapJson, "\n        \"value\": %llu", it->second->value);
            dr_fprintf(ctxtMapJson, "\n    }");
            if (it != tree_item_map.end()) {
                dr_fprintf(ctxtMapJson, ",");
            }
        }
        drcctlib_free_cct(cct_list);
    }
    dr_fprintf(ctxtMapJson, "}");

    dr_fprintf(callPathJson, "{");
    for (map<context_handle_t, tree_item_t*>::iterator it = tree_item_map.begin(); it != tree_item_map.end(); ) {
        inner_context_t * cct_list = drcctlib_get_full_cct(it->first, -1);
        if (cct_list == NULL) {
            continue;
        }
        inner_context_t * cur_list = cct_list;
        dr_fprintf(callPathJson, "\n    \"%llu\":[\n        ", cct_list->ctxt_hndl);
        cur_list = cur_list->pre_ctxt;
        while (cur_list != NULL) {
            dr_fprintf(callPathJson, "\"%llu\"", cur_list->ctxt_hndl);
            cur_list = cur_list->pre_ctxt;
            if (cur_list != NULL) {
                dr_fprintf(callPathJson, ",");
            }
        }
        dr_fprintf(callPathJson, "\n    ]");
        drcctlib_free_cct(cct_list);
        it++;
        if (it != tree_item_map.end()) {
            dr_fprintf(callPathJson, ",");
        }
    }
    dr_fprintf(callPathJson, "\n}");

    for (map<context_handle_t, tree_item_t*>::iterator it = tree_item_map.begin(); it != tree_item_map.end(); it++) {
        delete it->second->child_list;
        free(it->second);
    }

    dr_global_free(output_list, TOP_REACH_NUM_SHOW * sizeof(output_format_t));
    FreeGlobalBuff();
    drcctlib_exit();

    dr_close_file(flameGraphJson);
    dr_close_file(ctxtMapJson);
    dr_close_file(callPathJson);
}

#ifdef __cplusplus
extern "C" {
#endif

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("DynamoRIO Client 'drcctlib_instr_statistics_vs_gui'",
                       "http://dynamorio.org/issues");

    ClientInit(argc, argv);
    dr_register_exit_event(ClientExit);
}

#ifdef __cplusplus
}
#endif