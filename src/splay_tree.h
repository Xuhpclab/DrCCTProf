#ifndef _SPLAY_TREE_H_
#define _SPLAY_TREE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "drcctlib_global_share.h"

#define splay_node_key_t drcctlib_key_t

typedef struct _splay_node_t {
    splay_node_key_t key;
    void* payload;
    struct _splay_node_t *left;
    struct _splay_node_t *right;
    struct _splay_node_t *next;
} splay_node_t;

typedef struct _splay_tree_t{
    splay_node_t *root;
    splay_node_key_t node_num;
    void (*free_payload_func)(void *);
    splay_node_t *init_root;
} splay_tree_t;

splay_tree_t *
splay_tree_create(void (*free_payload_func)(void *));

void
splay_tree_free(splay_tree_t *tree);

splay_node_t *
splay_tree_add_and_update(splay_tree_t *tree, splay_node_key_t key);

#ifdef __cplusplus
}
#endif

#endif //_SPLAY_TREE_H_