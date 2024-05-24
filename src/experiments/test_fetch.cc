#include "consts.h"
#include "measure/measure.h"
#include "util.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <linux/mman.h>
#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>
#include <initializer_list>

#define DEFAULT_NUMBER_OF_TESTS (40000)

static uintptr_t eviction_allocation;
static uintptr_t set_addr_state(uintptr_t address, address_state to_state, uintptr_t trash) {
	memory_fences();
	switch (to_state) {
    case L1: {
        trash += FORCE_READ(address, trash);
	} break;
    case L2: {
        trash += FORCE_READ(address, trash);
        memory_fences();
		for(int r = 0; r < 3; r++) {
			for (int i = 0; i < L1D_CACHE_ASSOCIATIVITY + 3; i++) {
				trash += FORCE_READ(eviction_allocation + (i * L1D_STRIDE) + (address % L1D_STRIDE), trash);
			}
		}
	} break;
    case LLC: {
        trash += FORCE_READ(address, trash);
        memory_fences();
		for(int r = 0; r < 3; r++) {
			for (int i = 0; i < L2_CACHE_ASSOCIATIVITY + L1D_CACHE_ASSOCIATIVITY; i++) {
				trash += FORCE_READ(eviction_allocation + (i * L2_STRIDE) + (address % L2_STRIDE), trash);
			}
		}
	} break;
    case RAM: {
        clflush((void *)address);
	} break;
	default:
		assert(false);
    }
	memory_fences();

	return trash;
}

void test_fetch_once(uintptr_t memory, uint64_t &trash);
void parse_fetch_cmdline(int argc, char *argv[], int *number_of_tests);

int test_fetch(int argc, char *argv[]) {
    setaffinity(1);

    srand(time(0));

    // Allocate "Eviction allocation" used to evict from L1&L2
	initialize_allocation((void**) &eviction_allocation, 4 * 1024 * 1024, MAP_HUGETLB | MAP_HUGE_2MB);
	assert(eviction_allocation % L2_STRIDE == 0);

#if 0
    constexpr int MAX_LINES = 512;
    constexpr int LINE_COUNTS[] = {50, 75, 100, 125, 150, 175, 200, 225, 250, 275, 300, 325, 350};
    constexpr int TEST_COUNT = 10'000;
    uintptr_t large_mem = 0;
    initialize_allocation((void**) &large_mem, MAX_LINES * PAGE_SIZE_, MAP_HUGETLB | MAP_HUGE_2MB);
    assert(large_mem % L2_STRIDE == 0);

    auto line_addr = [large_mem](int idx) {
        constexpr int NUM_DCLS = PAGE_SIZE_ / DOUBLE_CACHE_LINE_SIZE;
        return large_mem + (idx * PAGE_SIZE_) + (((17 * idx) % NUM_DCLS) * DOUBLE_CACHE_LINE_SIZE);
    };

    // Setup linked list
    for(int i = 0; i < MAX_LINES - 1; i++) {
        *(uintptr_t*)line_addr(i) = line_addr(i+1);
    }
    *(uintptr_t*)line_addr(MAX_LINES - 1) = 0;

    memory_fences();

    uint64_t trash = large_mem;
    measure::Measure<measure::t_RDTSC> rdtsc_measure;

    for(address_state target_state : {L1, L2, LLC, RAM}) {
        for(int count : LINE_COUNTS) {
            uint64_t time_sum = 0;
            for(int t = 0; t < TEST_COUNT; t++) {
                // Flush lines
                for(int i = 0; i < count; i++) {
                    trash = set_addr_state(line_addr(i), RAM, trash);
                    trash = set_addr_state(line_addr(i) + CACHE_LINE_SIZE, RAM, trash);
                }

                memory_fences();

                // Setup lines
                for(int i = 0; i < count; i++) {
                    trash = set_addr_state(line_addr(i), target_state, trash);
                }

                memory_fences();

                // Measure walk
                uintptr_t start_addr = line_addr(0);
                time_sum += rdtsc_measure.measure([start_addr, count](uint64_t &trash_) {
                    uintptr_t addr = start_addr;
                    for(int i = 0; i < count; i++) {
                        addr = *(uintptr_t*)addr;
                    }
                    trash_ += addr;
                }, trash);
            }

            printf("Target: %s, count: %d, time: %.2f\n", state_to_string(target_state), count, ((double)time_sum) / TEST_COUNT);
        }
    }
#else

    int number_of_tests = DEFAULT_NUMBER_OF_TESTS;
    parse_fetch_cmdline(argc, argv, &number_of_tests);

    uintptr_t memory = 0;
    uint64_t trash = 0;
    initialize_allocation((void **)&memory, PAGE_SIZE_, MAP_HUGETLB | MAP_HUGE_2MB);

    for (int i = 0; i < number_of_tests; i++) {
        test_fetch_once(memory, trash);
    }

    measure::Measure<measure::t_RDTSC> measure_input;
    uint64_t overhead = 0;
    for (int i = 0; i < number_of_tests; i++) {
        overhead += measure_input.measure([] (uint64_t _t) { }, trash);
    }
    fprintf(stderr, "Mean overhead: %f\n", ((double) overhead) / number_of_tests);
    

    // measure::Measure<measure::t_RDTSC> measure_overhead;
    // uint64_t time_sum = 0;
    // for(int i = 0; i < number_of_tests; i++) {
    //     uint64_t result = measure_overhead.measure([&](uintptr_t trash_) {}, trash);
    //     time_sum += result;
    // }
    // printf("Average overhead: %zu\n", time_sum / number_of_tests);
#endif
    return 0;
}

void test_fetch_once(uintptr_t memory, uint64_t &trash) {
    address_state state_to_test = (address_state)get_rand_range(L1, RAM);

    memory_fences();

    uintptr_t test_address = memory + get_rand_range(0, 31) * DOUBLE_CACHE_LINE_SIZE;
    fetch_address(test_address + CACHE_LINE_SIZE, RAM);
    fetch_address(test_address, RAM);

    memory_fences();

    // fetch_address(test_address, state_to_test);
    trash = set_addr_state(test_address, state_to_test, trash);

    memory_fences();

    measure::Measure<measure::t_RDTSC> measure_input;
    uint64_t result = measure_input.measure(test_address, trash);
    printf("%4" PRId64 " %s\n", result, state_to_string(state_to_test));
}

void parse_fetch_cmdline(int argc, char *argv[], int *number_of_tests) {
    int opt;
    while ((opt = getopt(argc, argv, "c:h")) != -1) {
        switch (opt) {
        case 'c':
            *number_of_tests = atoi(optarg);
            break;
        case 'h':
            printf("Usage: %s %s [-c] [amount]\n", argv[0], argv[1]);
        default:
            exit(EXIT_FAILURE);
        }
    }
}
