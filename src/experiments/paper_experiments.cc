#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>


#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>

#include <algorithm>

#include "util.h"
#include "consts.h"
#include "aes.h"
#include "measure/measure.h"
#include "gates/gates.h"
#include "gates/classic_bt_gates.h"
#include "gates/gates_common.h"
using namespace gates;


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

static void (*map_callable_shellcode(size_t size))() {
	size_t full_size = size + 1; // ret instruction
	uint8_t* area = (uint8_t*) mmap(NULL, full_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(area != MAP_FAILED);
	area[size] = 0xC3; // ret
	return (void(*)()) area;
}

constexpr uint64_t rdtsc_freq = 1'800'000'000;
constexpr uint64_t cpu_freq =   3'400'000'000;
constexpr double adj_factor = ((double)cpu_freq) / rdtsc_freq;
static int test_rdtscp_latency(int argc, char *argv[]) {

	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	uintptr_t trash = (uintptr_t) argc;

	constexpr uint64_t test_count = 50'000;

	uint8_t rdtscp[] = {0x0f, 0x01, 0xf9}; // rdtscp
	constexpr size_t RDTSCP_CHAIN_LENGTH = 10'000;

	auto chain = map_callable_shellcode(sizeof(rdtscp) * RDTSCP_CHAIN_LENGTH);
	for(int i = 0; i < RDTSCP_CHAIN_LENGTH; i++) {
		((uint8_t*)chain)[i * 3 + 0] = rdtscp[0];
		((uint8_t*)chain)[i * 3 + 1] = rdtscp[1];
		((uint8_t*)chain)[i * 3 + 2] = rdtscp[2];
	}

	printf("Measuring cycle count of `rdtscp`\n");
	uint64_t time_sum = 0;
	for(uint64_t t = 0; t < test_count; t++) {
		// if(t%1000 == 0) printf("*\n");
		uint64_t start_ = rdtsc_measure.start(trash);

        asm volatile ("call %0\n" :: "r"(chain):"eax","edx","ecx");

        uint64_t end_ = rdtsc_measure.end(trash);
        uint64_t result = rdtsc_measure.val(start_, end_, trash);
		time_sum += result;
	}
	printf("Average cycle count: %.3f\n", (time_sum * adj_factor) / (test_count * RDTSCP_CHAIN_LENGTH));
	return 0;
}


inline
unsigned long 
// Attribution: https://cs.adelaide.edu.au/~yval/Mastik/
static time_mread(void *adrs) 
{
  volatile unsigned long time;
  asm volatile (
    // "lfence\n"
    "mfence\n"
    "rdtscp\n"
    "lfence\n"
    "mov esi, eax\n"
    "mov eax, [%1]\n"
    "rdtscp\n"
    "sub eax, esi\n"
    : "=&a" (time)          // output
    : "r" (adrs)            // input
    : "ecx", "edx", "esi"); // clobber registers

  return time;
}
constexpr size_t RATE_REPEAT_COUNT = 1260;
static uint64_t test_ps_github_rate(uint64_t& trash, uintptr_t test_line) {
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	uint64_t time = rdtsc_measure.measure([&](uint64_t &trash_) {
		uintptr_t trash = trash_;

		int i = 0;
		unsigned long delta = 0;
		while(i++ < RATE_REPEAT_COUNT && delta < 10000) {
			delta = time_mread((void*)test_line);
		}

		trash_ = trash;
	}, trash);

	return time;
}

static uint64_t test_ps_antoon_rate(uint64_t& trash, uintptr_t test_line) {
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	uint64_t time = rdtsc_measure.measure([&](uint64_t &trash_) {
		uintptr_t trash = trash_;


		int i = 0;
		unsigned long delta = 0;
		unsigned long this2;
		while(i++ < RATE_REPEAT_COUNT && delta < 10000) {
			asm volatile (
			"rdtscp\n"
			"mov esi, eax\n"
			"mov eax, [%2]\n"
			"rdtscp\n"
			"mov ecx, eax\n"
			"sub eax, esi\n"
			: "=&a" (time), "=&c"(this2)         // output
			: "r" (test_line)            // input
			: "edx", "esi"); // clobber registers
		}

		trash_ = trash;
	}, trash);

	return time;
}

static int test_gate_type(int argc, char* argv[]) {
	uintptr_t input;
	initialize_allocation((void**)&input, PAGE_SIZE_);
	*((uintptr_t*) input) = 0;
	uintptr_t output;
	initialize_allocation((void**)&output, PAGE_SIZE_);

	uintptr_t trash = (uintptr_t) input;

	measure::Measure<measure::t_RDTSC> rdtsc_measure;
	static GateBank __attribute__((aligned(128))) bank = { 0 };
	bank.inputs[0] = input;
	bank.outputs[0] = output;

	memory_fences();

	constexpr uint64_t test_count = 100'000;
	uint64_t times[test_count] = {};
	{
		printf("P+S\n");
		for(int i = 0; i < test_count; i++) {
			trash = set_addr_state(bank.inputs[0], L1, trash);

			memory_fences();

			times[i] = test_ps_github_rate(trash, input);
		}
		for(int i = 0; i < test_count; i++) {
			printf("%lu\n", times[i]);
		}
	}
	{
		printf("P+S no fences\n");
		for(int i = 0; i < test_count; i++) {
			trash = set_addr_state(bank.inputs[0], L1, trash);

			memory_fences();

			times[i] = test_ps_antoon_rate(trash, input);
		}
		for(int i = 0; i < test_count; i++) {
			printf("%lu\n", times[i]);
		}
	}
	{
		printf("BT gate\n");
		for(int t = 0; t < test_count; t++) {
			// Setup input
			trash = set_addr_state(bank.inputs[0], L1, trash);

			memory_fences();

			// Run gate
			times[t] = rdtsc_measure.measure([&](uint64_t &trash_){
				uintptr_t trash = trash_;

				for(int i = 0; i < RATE_REPEAT_COUNT; i++)
					trash = fsi_bt->apply(&bank, trash);

				trash_ = trash;
			}, trash);
		}
		for(int i = 0; i < test_count; i++) {
			printf("%lu\n", times[i]);
		}
	}
	{
		printf("CBT gate\n");
		for(int t = 0; t < test_count; t++) {
			// Setup input
			trash = set_addr_state(bank.inputs[0], L1, trash);

			memory_fences();

			// Run gate
			times[t] = rdtsc_measure.measure([&](uint64_t &trash_){
				uintptr_t trash = trash_;

				for(int i = 0; i < RATE_REPEAT_COUNT; i++)
					trash = fsi_cbt->apply(&bank, trash);

				trash_ = trash;
			}, trash);
		}
		for(int i = 0; i < test_count; i++) {
			printf("%lu\n", times[i]);
		}
	}
	{
		printf("RET gate\n");
		for(int t = 0; t < test_count; t++) {
			// Setup input
			trash = set_addr_state(bank.inputs[0], L1, trash);

			memory_fences();

			// Run gate
			times[t] = rdtsc_measure.measure([&](uint64_t &trash_){
				uintptr_t trash = trash_;

				for(int i = 0; i < RATE_REPEAT_COUNT; i++)
					trash = fsi_ret->apply(&bank, trash);

				trash_ = trash;
			}, trash);
		}
		for(int i = 0; i < test_count; i++) {
			printf("%lu\n", times[i]);
		}
	}
	return 0;
}


template<int sample_count>
static uint64_t test_fs_ps_rate(uint64_t& trash, volatile bool* trace, uintptr_t test_line) {
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	static GateBank __attribute__((aligned(128))) bank = { 0 };
	bank.inputs[0] = test_line;

	uintptr_t outputs[RATE_REPEAT_COUNT];
	for(int i = 0; i < RATE_REPEAT_COUNT; i++) {
		outputs[i] = (uintptr_t) &bank; // dummy
	}

	uint64_t time = rdtsc_measure.measure([&](uint64_t &trash_) {
		uintptr_t trash = trash_;

		// static_assert(RATE_REPEAT_COUNT % sample_count == 0);
		#pragma clang loop unroll(full)
		for(int i = 0; i < RATE_REPEAT_COUNT / sample_count; i++) {
			#pragma clang loop unroll(full)
			for(int j = 0; j < sample_count; j++) {
				bank.outputs[j] = outputs[i*sample_count + j];
			}
			trash = ret_inv_window_gate_single_samples[sample_count - 1]->apply(&bank, trash);
		}

		trash_ = trash;
	}, trash);

	return time;
}

static int test_multi_sample_rates(int argc, char* argv[]) {
	uintptr_t test_line;
	initialize_allocation((void**) &test_line, 4 * 1024);
	*(volatile uintptr_t*)test_line = 0;

	uintptr_t trash = test_line;

	trash = set_addr_state(test_line, L1, trash); // Put line in L1
	trash = set_addr_state(test_line, L1, trash); // Put line in L1


	volatile bool* trace = (volatile bool*) malloc(sizeof(bool) * RATE_REPEAT_COUNT);
	assert(trace);

	for(int i = 0; i < RATE_REPEAT_COUNT; i++) {
		trash = set_addr_state((uintptr_t) (trace + i), L1, trash);
	}

	constexpr size_t REPEAT_COUNT = 1'000'000;
	uint64_t times[REPEAT_COUNT] = {};
	{
		for_values<1,2,3,4,5,6,7,8,9,10>([&]<auto sample_count>() {
			for(int i = 0; i < REPEAT_COUNT; i++) {
				times[i] = test_fs_ps_rate<sample_count>(trash, trace, test_line);
			}
			// printf("FS_PS[%d]: Average cycles per sample: %.1f\n", sample_count, ((double)time_sum * adj_factor)/(MEAN_COUNT * RATE_REPEAT_COUNT));
			// printf("\tAverage cycles per window: %.1f\n", ((double)time_sum * adj_factor)/(MEAN_COUNT * (RATE_REPEAT_COUNT/sample_count)));
			printf("FS_PS[%d]\n", sample_count);
			for(int i = 0; i < REPEAT_COUNT; i++) {
				printf("%lu\n", times[i]);
			}
		});
	}

	return 0;
}

static int benchmark_aes_sbox(int argc, char* argv[]) {
	constexpr size_t REPEAT_COUNT = 100'000;
	constexpr size_t AES128_ROUNDS = 10;

	uintptr_t trash = (uintptr_t) argv;

	uint8_t key[16], ct[16], pt[16];
	AES_KEY aeskey;
	
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	for(int i = 0; i < REPEAT_COUNT; i++) {
		randaes(key);
		randaes(ct);
		AES_set_decrypt_key_sbox(key, 128, &aeskey);

		uint64_t t = rdtsc_measure.measure([&aeskey, &ct, &pt](uintptr_t& trash_) {
			AES_decrypt_sbox(ct, pt, &aeskey);
		}, trash);
		printf("%lu\n", t);
	}

	return 0;
}

static int benchmark_aes_ttable(int argc, char* argv[]) {
	constexpr size_t REPEAT_COUNT = 100'000;
	constexpr size_t AES128_ROUNDS = 10;

	uintptr_t trash = (uintptr_t) argv;

	uint8_t key[16], ct[16], pt[16];
	AES_KEY aeskey;
	
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	for(int i = 0; i < REPEAT_COUNT; i++) {
		randaes(key);
		randaes(ct);
		private_AES_set_decrypt_key(key, 128, &aeskey);

		uint64_t t = rdtsc_measure.measure([&aeskey, &ct, &pt](uintptr_t& trash_) {
			AES_decrypt(ct, pt, &aeskey);
		}, trash);
		printf("%lu\n", t);
	}

	return 0;
}

int paper_experiments(int argc, char *argv[]) {
	if(argc < 3) {
		fprintf(stderr, "Please provide experiment name\n");
		return 1;
	}
	
	char* expr_name = argv[2];
	if(strcmp(expr_name, "rdtscp_latency") == 0)
		return test_rdtscp_latency(argc, argv);
	if(strcmp(expr_name, "gate_type") == 0)
		return test_gate_type(argc, argv);
	if(strcmp(expr_name, "multi_sample_rates") == 0)
		return test_multi_sample_rates(argc, argv);
	if(strcmp(expr_name, "multi_sample_rates") == 0)
		return test_multi_sample_rates(argc, argv);
	if(strcmp(expr_name, "benchmark_aes_sbox") == 0)
		return benchmark_aes_sbox(argc, argv);
	if(strcmp(expr_name, "benchmark_aes_ttable") == 0)
		return benchmark_aes_ttable(argc, argv);


	fprintf(stderr, "No such experiment\n");
	return 1;
}