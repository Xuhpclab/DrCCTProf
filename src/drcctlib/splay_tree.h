/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#ifndef _SPLAY_TREE_H_
#define _SPLAY_TREE_H_

#include <cstdint>
#include <cstddef>

#define splay_node_key_t int32_t

typedef struct _splay_node_t {
    splay_node_key_t key;
    void *payload;
    struct _splay_node_t *left;
    struct _splay_node_t *right;
} splay_node_t;

void
splay_node_init_cache_index(splay_node_t *node, int32_t index);

splay_node_t *
splay_tree_update(splay_node_t *root, splay_node_key_t key, splay_node_t *dummy_node,
                  splay_node_t *new_node);

splay_node_t *
splay_tree_update_test(splay_node_t *root, splay_node_key_t key, splay_node_t *dummy_node,
                       splay_node_t *new_node, int64_t *o_num);
int32_t
splay_tree_size(splay_node_t *root);

#endif //_SPLAY_TREE_H_