#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "linked_list.h"

void node_set_next(node *a, node *next) {
    if (a)
        a->next = next;
}

void node_set_prev(node *a, node *prev) {
    if (a)
        a->prev = prev;
}

void node_insert(node *a, node *b) {
    node_set_next(b, a->next);
    node_set_prev(a->next, b);
    node_set_next(a, b);
    node_set_prev(b, a);
}

void node_remove(node *a) {
    node *prev = a->prev;
    node *next = a->next;
    node_set_next(prev, next);
    node_set_prev(next, prev);
}

void node_unlink_chain(node *start, node* end) {
    if (end) {
        node_set_next(start->prev, end->next);
        node_set_prev(end->next, start->prev);
    }
    else {
        node_set_next(start->prev, NULL);
    }

}

void node_link_chain(node *link_point, node *start, node* end) {
    if (end) {
        node_set_next(end, link_point->next);
        node_set_prev(link_point->next, end);
    }
    node_set_next(link_point, start);
    node_set_prev(start, link_point);
}

node *node_advance(node *current, uint32_t advance) {
    for (int i = 0; i < advance; i++)
        current = (node *)current->next;
    return current;
}

void node_array_to_linked_list(node_array array, node *sentinel) {
    node_set_next(sentinel, array.arr[0]);
    node_set_prev(array.arr[0], sentinel);
    
    for (int i = 0; i < array.length - 1; i++) {
        node_set_next(array.arr[i], array.arr[i + 1]);
        node_set_prev(array.arr[i + 1], array.arr[i]);
    }
    node_set_next(array.arr[array.length - 1], NULL);
}

node *adjust_node(node *a, uint32_t page_offset) {
    
    return (node *)((char *)a + page_offset);
}

void node_array_to_linked_list_adjusted(node_array array, node *sentinel, uint32_t page_offset) {
    node_set_next(sentinel, adjust_node(array.arr[0], page_offset));
    node_set_prev(adjust_node(array.arr[0], page_offset), sentinel);
    
    for (int i = 0; i < array.length - 1; i++) {
        node_set_next(adjust_node(array.arr[i], page_offset), adjust_node(array.arr[i + 1], page_offset));
        node_set_prev(adjust_node(array.arr[i + 1], page_offset), adjust_node(array.arr[i], page_offset));
    }
    node_set_next(adjust_node(array.arr[array.length - 1], page_offset), NULL);
}

void linked_list_to_node_array(node *first, node_array array) {
    uint32_t index = 0;
    for (node *current = first; current; current = current->next) {
        if (index < array.length) {
            array.arr[index] = current;
            index++;
        }
    }
}

void linked_list_print(node *first) {
    node *current = first;
    for (; current->next; current = current->next) {
        printf("%lu,", (uintptr_t)current);
    }
    printf("%lu\n", (uintptr_t)current);
}

void node_array_shuffle(node_array array) {
    for (int i = 0; i < array.length; i++) {
        int j = rand() % array.length;
        swap<node>(array.arr[i], array.arr[j]);
    }
}

void node_array_print(node_array array) {
    for (uint32_t i = 0; i < array.length; i++) {
        printf("%p,", array.arr[i]);
    }
    printf("\n");
}