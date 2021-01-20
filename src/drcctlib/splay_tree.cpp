/* 
 *  Copyright (c) 2020-2021 Xuhpclab. All rights reserved.
 *  Licensed under the MIT License.
 *  See LICENSE file for more information.
 */

#include "splay_tree.h"


void
splay_node_init_cache_index(splay_node_t *node, int32_t index)
{
    node->left = NULL;
    node->right = NULL;
    node->payload = NULL;
}

inline void
splay_node_init(splay_node_t *node, splay_node_key_t key)
{
    node->left = NULL;
    node->right = NULL;
    node->payload = NULL;
    node->key = key;
}

splay_node_t *
splay_tree_update(splay_node_t *root, splay_node_key_t key, splay_node_t *dummy_node,
                  splay_node_t *new_node)
{
    if (root != NULL) {
        dummy_node->left = NULL;
        dummy_node->right = NULL;
        splay_node_t *ltree_max_node, *rtree_min_node, *temp_node;
        ltree_max_node = rtree_min_node = dummy_node;
        while (key != root->key) {
            if (key < root->key) {
                if (root->left == NULL) {
                    new_node->key = key;
                    root->left = new_node;
                }
                if (key < root->left->key) {
                    temp_node = root->left;
                    root->left = temp_node->right;
                    temp_node->right = root;
                    root = temp_node;
                    if (root->left == NULL) {
                        new_node->key = key;
                        root->left = new_node;
                    }
                }
                rtree_min_node->left = root;
                rtree_min_node = root;
                root = root->left;
            } else if (key > root->key) {
                if (root->right == NULL) {
                    new_node->key = key;
                    root->right = new_node;
                }
                if (key > root->right->key) {
                    temp_node = root->right;
                    root->right = temp_node->left;
                    temp_node->left = root;
                    root = temp_node;
                    if (root->right == NULL) {
                        new_node->key = key;
                        root->right = new_node;
                    }
                }
                ltree_max_node->right = root;
                ltree_max_node = root;
                root = root->right;
            }
        }
        ltree_max_node->right = root->left;
        rtree_min_node->left = root->right;
        root->left = dummy_node->right;
        root->right = dummy_node->left;
    } else {
        new_node->key = key;
        root = new_node;
    }
    return root;
}

splay_node_t *
splay_tree_update_test(splay_node_t *root, splay_node_key_t key, splay_node_t *dummy_node,
                       splay_node_t *new_node, int64_t *o_num)
{
    if (root != NULL) {
        dummy_node->left = NULL;
        dummy_node->right = NULL;
        splay_node_t *ltree_max_node, *rtree_min_node, *temp_node;
        ltree_max_node = rtree_min_node = dummy_node;
        (*o_num)++;
        while (key != root->key) {
            if (key < root->key) {
                if (root->left == NULL) {
                    new_node->key = key;
                    root->left = new_node;
                }
                if (key < root->left->key) {
                    temp_node = root->left;
                    root->left = temp_node->right;
                    temp_node->right = root;
                    root = temp_node;
                    if (root->left == NULL) {
                        new_node->key = key;
                        root->left = new_node;
                    }
                }
                rtree_min_node->left = root;
                rtree_min_node = root;
                root = root->left;
            } else if (key > root->key) {
                if (root->right == NULL) {
                    new_node->key = key;
                    root->right = new_node;
                }
                if (key > root->right->key) {
                    temp_node = root->right;
                    root->right = temp_node->left;
                    temp_node->left = root;
                    root = temp_node;
                    if (root->right == NULL) {
                        new_node->key = key;
                        root->right = new_node;
                    }
                }
                ltree_max_node->right = root;
                ltree_max_node = root;
                root = root->right;
            }
            (*o_num)++;
        }
        ltree_max_node->right = root->left;
        rtree_min_node->left = root->right;
        root->left = dummy_node->right;
        root->right = dummy_node->left;
    } else {
        (*o_num)++;
        new_node->key = key;
        root = new_node;
    }
    return root;
}

int32_t
splay_tree_size(splay_node_t *root)
{
    if (root == NULL) {
        return 0;
    } else {
        return 1 + splay_tree_size(root->left) + splay_tree_size(root->right);
    }
}
