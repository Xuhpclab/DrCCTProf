#include "dr_api.h"
#include "splay_tree.h"

splay_node_t *
splay_node_create(splay_node_key_t key)
{
    splay_node_t *node = (splay_node_t *)dr_global_alloc(sizeof(splay_node_t));
    node->left = NULL;
    node->right = NULL;
    node->next = NULL;
    node->payload = NULL;
    node->key = key;
    return node;
}

splay_tree_t *
splay_tree_create(void (*free_payload_func)(void *))
{
    splay_tree_t *tree = (splay_tree_t *)dr_global_alloc(sizeof(splay_tree_t));
    tree->root = NULL;
    tree->node_num = 0;
    tree->init_root = NULL;
    tree->free_payload_func = free_payload_func;
    return tree;
}

void
splay_tree_free(splay_tree_t *tree)
{
    splay_node_t *next_free_node;
    while ((next_free_node = tree->init_root) != NULL) {
        tree->init_root = tree->init_root->next;
        (*(tree->free_payload_func))(next_free_node->payload);
        dr_global_free(next_free_node, sizeof(splay_node_t));
    }
    dr_global_free(tree, sizeof(splay_tree_t));
}

splay_node_t *
splay_tree_add_and_update(splay_tree_t *tree, splay_node_key_t key)
{
    if(tree == NULL)
    {
        dr_printf("\nsplay_tree_add_and_update tree == NULL\n");
        dr_exit_process(-1);
    }
    splay_node_t *root = tree->root;
    if (root != NULL) {
        splay_node_t *dummy_node = splay_node_create(-1);
        splay_node_t *ltree_max_node, *rtree_min_node, *temp_node;
        ltree_max_node = rtree_min_node = dummy_node;
        while (key != root->key) {
            if (key < root->key) {
                if (root->left == NULL) {
                    splay_node_t *new_node = splay_node_create(key);
                    root->left = new_node;
                }
                if (key < root->left->key) {
                    temp_node = root->left;
                    root->left = temp_node->right;
                    temp_node->right = root;
                    root = temp_node;
                    if (root->left == NULL) {
                        splay_node_t *new_node = splay_node_create(key);
                        root->left = new_node;
                    }
                }
                rtree_min_node->left = root;
                rtree_min_node = root;
                root = root->left;
            } else if (key > root->key) {
                if (root->right == NULL) {
                    splay_node_t *new_node = splay_node_create(key);
                    root->right = new_node;
                }
                if (key > root->right->key) {
                    temp_node = root->right;
                    root->right = temp_node->left;
                    temp_node->left = root;
                    root = temp_node;
                    if (root->right == NULL) {
                        splay_node_t *new_node = splay_node_create(key);
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
        dr_global_free(dummy_node, sizeof(splay_node_t));
    } else {
        splay_node_t *new_node = splay_node_create(key);
        root = new_node;
    }
    tree->root = root;
    return root;
}
