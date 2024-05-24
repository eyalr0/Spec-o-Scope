#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "consts.h"

#ifndef __always_inline
#define __always_inline __inline__ __attribute__((__always_inline__))
#endif

#define CLEAR_CACHE_MEMORY_MULTIPLIER (14)

#define READ(addr) (*(uint64_t *)(addr))
#define FORCE_READ(addr, trash) (READ((uintptr_t)(addr) | ((trash) == 0xbaaaaad)))
#define TEMPORAL_ADD(trash, value) ((trash) += (value))

#define ADDRESS_STATES (4)

template<auto... Xs, typename F>
constexpr void for_values(F &&f) {
    (f.template operator()<Xs>(), ...);
}

namespace measure {
typedef enum {
    t_RDTSC,
    t_100US,
} measure_type;
}

typedef enum {
    L1,
    L2,
    LLC,
    RAM,
    IN_CACHE
} address_state;

struct cache_bucket {
    int cache_set;
    int slice;

    friend bool operator<(const cache_bucket &lhs, const cache_bucket &rhs) {
        if (lhs.cache_set == rhs.cache_set)
            return lhs.slice < rhs.slice;
        return lhs.cache_set < rhs.cache_set;
    }

    friend bool operator==(const cache_bucket &lhs, const cache_bucket &rhs) {
        return (lhs.cache_set == rhs.cache_set) && (lhs.slice == rhs.slice);
    }
};

void __always_inline memory_fences() {
    asm volatile("mfence\nlfence\n");
}

void __always_inline clflush(void *p) {
    __asm__ volatile(
        "clflush [%0]"
        :
        : "c"(p)
        : "rax");
}


int __always_inline get_rand_range(int lower, int upper) {
    return rand() % (upper + 1 - lower) + lower;
}

int __always_inline get_page_offset(uintptr_t address) {
    return address % PAGE_SIZE_;
}

void __always_inline cleanup_child(pid_t pid) {
	kill(pid, SIGKILL);
	waitpid(pid, 0, 0);
}

uint64_t virt_to_physical(uint64_t vaddr);
cache_bucket to_cache_bucket(uint64_t vaddr);
void print_cache_bucket(uint64_t vaddr, bool new_line = true);

uint64_t int_pow(uint64_t base, unsigned int exp);

void initialize_allocation(void **target, size_t size, int extra_flags = 0, bool private_alloc = false);
void initialize_clear_cache_allocation();
void clear_all_caches(uint64_t &trash);

void fetch_address(uintptr_t address, address_state to_state);
const char *state_to_string(address_state state);

void hexdump(const char *desc, const void *addr, const int len, int perLine);
uintptr_t mmap_symbol_from_binary(const char *path, const char *symbol);

void setaffinity(int core);
void yield_execution();
