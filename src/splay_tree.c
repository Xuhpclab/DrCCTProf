#include "splay_tree.h"

void
splay_node_init(splay_node_t *node, splay_node_key_t key)
{
    node->left = NULL;
    node->right = NULL;
    node->next = NULL;
    node->payload = NULL;
    node->key = key;
}

splay_node_t *
splay_tree_update(splay_node_t *root, splay_node_key_t key, splay_node_t *dummy_node,
                  splay_node_t *new_node)
{
    if (root != NULL) {
        splay_node_init(dummy_node, -1);
        splay_node_t *ltree_max_node, *rtree_min_node, *temp_node;
        ltree_max_node = rtree_min_node = dummy_node;
        while (key != root->key) {
            if (key < root->key) {
                if (root->left == NULL) {
                    splay_node_init(new_node, key);
                    root->left = new_node;
                }
                if (key < root->left->key) {
                    temp_node = root->left;
                    root->left = temp_node->right;
                    temp_node->right = root;
                    root = temp_node;
                    if (root->left == NULL) {
                        splay_node_init(new_node, key);
                        root->left = new_node;
                    }
                }
                rtree_min_node->left = root;
                rtree_min_node = root;
                root = root->left;
            } else if (key > root->key) {
                if (root->right == NULL) {
                    splay_node_init(new_node, key);
                    root->right = new_node;
                }
                if (key > root->right->key) {
                    temp_node = root->right;
                    root->right = temp_node->left;
                    temp_node->left = root;
                    root = temp_node;
                    if (root->right == NULL) {
                        splay_node_init(new_node, key);
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
        splay_node_init(new_node, key);
        root = new_node;
    }
    return root;
}
