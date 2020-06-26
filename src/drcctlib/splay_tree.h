#ifndef _SPLAY_TREE_H_
#define _SPLAY_TREE_H_

#ifdef __cplusplus
extern "C" {
#endif
#include "drcctlib_global_share.h"

#define splay_node_key_t int32_t

typedef struct _splay_node_t {
    splay_node_key_t key;
    void *payload;
    struct _splay_node_t *left;
    struct _splay_node_t *right;
} splay_node_t;

splay_node_t *
splay_tree_update(splay_node_t *root, splay_node_key_t key, splay_node_t *dummy_node,
                  splay_node_t *new_node);

splay_node_t *
splay_tree_update_test(splay_node_t *root, splay_node_key_t key, splay_node_t *dummy_node,
                       splay_node_t *new_node, int32_t *o_num);
int32_t
splay_tree_size(splay_node_t *root);

#ifdef __cplusplus
}
#endif

#endif //_SPLAY_TREE_H_