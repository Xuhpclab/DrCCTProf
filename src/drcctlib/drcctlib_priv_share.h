/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _DRCCTLIB_PRIV_SHARE_H_
#define _DRCCTLIB_PRIV_SHARE_H_

#include <vector>

#include "drcctlib_defines.h"
#include "drcctlib_utils.h"
#include "splay_tree.h"

#define bb_key_t int32_t
#define slot_t int32_t
#define state_t int32_t

typedef struct _cct_bb_node_t {
    bb_key_t key;
    struct _cct_bb_node_t *parent_bb;
    context_handle_t child_ctxt_start_idx;
    slot_t max_slots;
    splay_node_t *callee_splay_tree_root;
#ifdef IPNODE_STORE_BNODE_IDX
    int32_t cache_index;
#endif
#ifdef DRCCTLIB_DEBUG_LOG_CCT_INFO
    int32_t callee_tree_size;
#endif
} cct_bb_node_t;

typedef struct _cct_ip_node_t {
#ifdef IPNODE_STORE_BNODE_IDX
    int32_t parent_bb_node_cache_index;
#else
    cct_bb_node_t *parent_bb_node;
#endif
} cct_ip_node_t;

int
drcctlib_priv_share_get_thread_id();

splay_node_t *
drcctlib_priv_share_get_ip_node_callee_splay_tree_root(cct_ip_node_t *ip);

cct_ip_node_t *
drcctlib_priv_share_trans_ctxt_hndl_to_ip_node(context_handle_t ctxt_hndl);

cct_bb_node_t *
drcctlib_priv_share_get_thread_root_bb_node(int id);

app_pc
drcctlib_priv_share_get_ip_from_ctxt(context_handle_t ctxt);

app_pc
drcctlib_priv_share_get_ip_from_ip_node(cct_ip_node_t *ip_node);

void
drcctlib_priv_share_get_full_calling_ip_vector(context_handle_t ctxt_hndl, std::vector<app_pc> &list);

#endif // _DRCCTLIB_PRIV_SHARE_H_ 

