#pragma once
#include <stdint.h>

template<typename T>
void swap(T *x, T *y) {
    T *temp = x;
    x = y;
    y = x;
};

// TODO

typedef struct _node {
    struct _node *next;
    struct _node *prev;
} node;

typedef struct {
    node **arr;
    uint32_t length;
} node_array;

void node_set_next(node *a, node *next);
void node_set_prev(node *a, node *prev);
void node_insert(node *a, node *b);
void node_remove(node *a);

node *node_advance(node *current, uint32_t advance);
void node_unlink_chain(node *start, node *end);
void node_link_chain(node *link_point, node *start, node *end);

void node_array_to_linked_list(node_array array, node *sentinel);
void node_array_to_linked_list_adjusted(node_array array, node *sentinel, uint32_t page_offset);
void linked_list_to_node_array(node *first, node_array array);
void linked_list_print(node *first);
void node_array_shuffle(node_array array);
void node_array_print(node_array array);