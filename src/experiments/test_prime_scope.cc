#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <vector>

#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>

#include "util.h"
#include "consts.h"
#include "measure/measure.h"
#include "ev/ev.h"
#include "ev/assisted_ev.h"
#include "gates/gates_common.h"
#include "primescope/primescope.h"
using namespace gates;
using namespace prime_scope;


int test_prime_time(int argc, char* argv[]) {
	// Setup
	ev::AssistedEvictionSetManager ev_manager;
    ev::EvictionSet** eviction_sets = ev_manager.find_eviction_sets(2, 1); // We ask for 2*LLC addresses because we need a contending address
	if(eviction_sets == nullptr) {
		printf("Failed to find eviction set...\n");
		return 1;
	}
	ev::EvictionSet* evset = eviction_sets[0];
	srand(0x47414c21);

	std::vector<PrimePattern> patterns = generate_prime_patterns(evset);
	printf("EVCr     | Cycles | Pattern\n");
	for(auto& pat : patterns) {
		printf("%7.3f%% | %6zu | ", pat.tested_evcr * 100, pat.tested_cycle_count);
		pat.dump();
		printf("\n");
	}

	return 0;
}

volatile bool* attack_start_signal;

int setup_basic_ps_victim(int affinity, uintptr_t target) {
	pid_t child_pid = fork();
	if(child_pid != 0) {
		return child_pid;
	}

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	setaffinity(affinity);

	uint64_t trash = target;

	// printf("Victim: ");
	// print_cache_bucket(target);

	while(true) {
		memory_fences();
		while(!*attack_start_signal) {}
		memory_fences();

		trash |= *attack_start_signal;

		trash = FORCE_READ(target, trash);

		memory_fences();
		*attack_start_signal = false | (trash == 0xDEADBEEF);
		memory_fences();
	}
}

int test_prime_scope_basic(int argc, char* argv[]) {
	// Intel Core i5-8250U: R3_S2_P1022S (EVCr: 99.998%, 1193 RDTSC cycles at 3.4GHz)
	uint8_t _pat[5] = {1, 0, 2, 2, PATTERN_TARGET};
	PrimePattern prime_pat(3, 2, _pat, 5);

	ev::AssistedEvictionSetManager ev_manager;
	ev::EvictionSet** eviction_sets = ev_manager.find_eviction_sets(2, 1); // We ask for 2*LLC addresses because we need a contending address
	if(eviction_sets == nullptr) {
		printf("Failed to find eviction set...\n");
		return 1;
	}
	ev::EvictionSet* evset = eviction_sets[0];

	attack_start_signal = (volatile bool*) mmap(NULL, PAGE_SIZE_, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	pid_t victim_pid = setup_basic_ps_victim(1, evset[1].arr[0]);
	setaffinity(2);

	measure::Measure<measure::t_RDTSC> rdtsc_measure;
	uint64_t trash = (uint64_t) evset;

	// printf("Attacker: ");
	// print_cache_bucket(evset[1].arr[0]);

	constexpr int test_count = 100'000;
	printf("Running %d tests...\n", test_count);
	int success = 0;
	int pre_success = 0;
	for(int i = 0; i < test_count; i++) {
		memory_fences();
		trash = prime_pat.access(evset[0], trash);

		if(!rdtsc_measure.in_cache(rdtsc_measure.measure(evset[0].arr[0], trash)))
			continue;
		
		if(!rdtsc_measure.in_cache(rdtsc_measure.measure(evset[0].arr[0], trash)))
			continue;

		pre_success++;

		memory_fences();
		*attack_start_signal = true | (trash == 0xDEADBEEF);
		memory_fences();
		while(*attack_start_signal) {}
		memory_fences();

		trash |= *attack_start_signal;

		// trash = FORCE_READ(evset[1].arr[0], trash);

		memory_fences();

		if(rdtsc_measure.in_cache(rdtsc_measure.measure(evset[0].arr[0], trash)))
			continue;
		
		success++;
	}

	printf("PS: %.3f%% successful (%d)\n", 100*((double)success)/test_count, pre_success);
	return 0;
}

constexpr int TRACE3_LENGTH = 64;
constexpr int EFFECTIVE_LENGTH = TRACE3_LENGTH;

enum class ProcessStatus {
	Ready,
	Finished,
};

struct AttackData {
	int start_signal; // Start is signalled by changing value from (-1) to something else
	
	unsigned victim_slowdown;

	ProcessStatus victim_status;
	ProcessStatus attacker_status[2];
	
	uint64_t attacker_time[2];
};
static volatile AttackData* attack_data; 

static pid_t setup_victim2(uintptr_t target1, uintptr_t target2, int affinity) {
	attack_data->victim_status = ProcessStatus::Ready;

	uint64_t trash = target1;

	pid_t child_pid = fork();
	if(child_pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		setaffinity(affinity);

		while(true) {
			int slowdown = -1;
			do {
				slowdown = attack_data->start_signal;
			} while(slowdown == -1);
			memory_fences();

			unsigned victim_slowdown = attack_data->victim_slowdown;

			trash ^= slowdown_chain(force_convert_double(slowdown != (-2)), 100) == 0.0;
			// uintptr_t temporal_zero1 = slowdown_chain_finegrained(slowdown != (-1), 160);
			// uintptr_t temporal_zero1 = 0;

			prevent_reorder();
			// clflush((void*)(target1 | temporal_zero1));
			// trash = FORCE_READ(target1, trash);

			prevent_reorder();
			trash ^= slowdown_chain(force_convert_double(trash != 0xDEADBEEF), victim_slowdown) == 0.0;

			prevent_reorder();
			// clflush((void*)(target2 | temporal_zero2));
			// trash = FORCE_READ(target2, trash);

			memory_fences();
			attack_data->victim_status = ProcessStatus::Finished;

			memory_fences();
			while(attack_data->victim_status != ProcessStatus::Ready) {};
			memory_fences();
		}
	}

	return child_pid;
}

static pid_t setup_prime_scope_attacker(ev::EvictionSet target, PrimePattern prime_pat, bool trace[TRACE3_LENGTH], int id, int affinity) {
	volatile ProcessStatus* status = attack_data->attacker_status + id;
	*status = ProcessStatus::Ready;

	uintptr_t trash = target.arr[0];
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	uintptr_t evset_target = target.arr[0];

	pid_t child_pid = fork();
	if(child_pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		setaffinity(affinity);


		trash = prime_pat.access(target, trash);
		while(true) {
			int slowdown = -1;
			do {
				slowdown = attack_data->start_signal;
			} while(slowdown == -1);
			memory_fences();

			// trash = slowdown_chain(force_convert_double(slowdown != -2), 200);

			int local_detection = -1;
			uint64_t time = rdtsc_measure.measure([&](uint64_t &trash_) {
				uintptr_t trash = trash_;

				int detection = -1;


				#pragma clang loop unroll(full)
				for(int i = 0; i < EFFECTIVE_LENGTH; i++) {
					uint64_t l1_t = rdtsc_measure.measure(evset_target, trash);
					if(!rdtsc_measure.in_cache(l1_t)) {
						if(detection == -1) detection = i;
					}
				}

				local_detection = detection;
				trash_ = trash;
			}, trash);

			memory_fences();

			for(int j = 0; j < TRACE3_LENGTH; j++) {
				trace[j] = 0;
				if(j == local_detection) {
					trace[j] = 1;
				}
			}

			attack_data->attacker_time[id] = time;

			memory_fences();

			trash = prime_pat.access(target, trash);

			memory_fences();
			*status = ProcessStatus::Finished;

			memory_fences();
			while(*status != ProcessStatus::Ready) {};
			memory_fences();
		}
	}

	return child_pid;
}

static pid_t setup_prime_scope_attacker_opt(ev::EvictionSet target, PrimePattern prime_pat, bool trace[TRACE3_LENGTH], int id, int affinity) {
	volatile ProcessStatus* status = attack_data->attacker_status + id;
	*status = ProcessStatus::Ready;

	uintptr_t trash = target.arr[0];
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	uintptr_t evset_target = target.arr[0];

	pid_t child_pid = fork();
	if(child_pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		setaffinity(affinity);


		trash = prime_pat.access(target, trash);
		while(true) {
			int slowdown = -1;
			do {
				slowdown = attack_data->start_signal;
			} while(slowdown == -1);
			memory_fences();

			// trash = slowdown_chain(force_convert_double(slowdown != -2), 200);

			int local_detection = -1;
			uint64_t time = rdtsc_measure.measure([&](uint64_t &trash_) {
				uintptr_t trash = trash_;

				uint64_t last_time = measure::rdtsc_strong();

				int detection = -1;

				#pragma clang loop unroll(full)
				for(int j = 0; j < EFFECTIVE_LENGTH; j++) {
					// Check if the line was flushed

					trash += READ(evset_target);

					uint64_t new_time = measure::rdtsc_strong();
					
					if((new_time - last_time) > RDTSC_THRESHOLD) {
						if(detection == -1) detection = j;
					}
					last_time = new_time;
				}

				local_detection = detection;
				trash_ = trash;
			}, trash);

			memory_fences();

			for(int j = 0; j < TRACE3_LENGTH; j++) {
				trace[j] = 0;
				if(j == local_detection) {
					trace[j] = 1;
				}
			}

			attack_data->attacker_time[id] = time;

			memory_fences();

			trash = prime_pat.access(target, trash);

			memory_fences();
			*status = ProcessStatus::Finished;

			memory_fences();
			while(*status != ProcessStatus::Ready) {};
			memory_fences();
		}
	}

	return child_pid;
}

static pid_t setup_prime_scope_attacker_nomfence(ev::EvictionSet target, PrimePattern prime_pat, bool trace[TRACE3_LENGTH], int id, int affinity) {
	volatile ProcessStatus* status = attack_data->attacker_status + id;
	*status = ProcessStatus::Ready;

	uintptr_t trash = target.arr[0];
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	uintptr_t evset_target = target.arr[0];

	pid_t child_pid = fork();
	if(child_pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		setaffinity(affinity);


		trash = prime_pat.access(target, trash);
		while(true) {
			int slowdown = -1;
			do {
				slowdown = attack_data->start_signal;
			} while(slowdown == -1);
			memory_fences();

			// trash = slowdown_chain(force_convert_double(slowdown != -2), 200);

			int local_detection = -1;
			uint64_t time = rdtsc_measure.measure([&](uint64_t &trash_) {
				uintptr_t trash = trash_;

				uint64_t last_time = measure::rdtscp_strong();

				int detection = -1;

				#pragma clang loop unroll(full)
				for(int j = 0; j < EFFECTIVE_LENGTH; j++) {
					// Check if the line was flushed

					trash += READ(evset_target);

					uint64_t new_time = measure::rdtscp_strong();
					
					if((new_time - last_time) > RDTSC_THRESHOLD) {
						if(detection == -1) detection = j;
					}
					last_time = new_time;
				}

				local_detection = detection;
				trash_ = trash;
			}, trash);

			memory_fences();

			for(int j = 0; j < TRACE3_LENGTH; j++) {
				trace[j] = 0;
				if(j == local_detection) {
					trace[j] = 1;
				}
			}

			attack_data->attacker_time[id] = time;

			memory_fences();

			trash = prime_pat.access(target, trash);

			memory_fences();
			*status = ProcessStatus::Finished;

			memory_fences();
			while(*status != ProcessStatus::Ready) {};
			memory_fences();
		}
	}

	return child_pid;
}

int test_prime_scope_trace(int argc, char* argv[]) {
	if(argc != 3) {
		fprintf(stderr, "Please supply a victim slowdown argument\n");
		return 1;
	}

	// Intel Core i5-8250U: R3_S2_P1022S (EVCr: 99.998%, 1193 RDTSC cycles at 3.4GHz)
	uint8_t _pat[5] = {1, 0, 2, 2, PATTERN_TARGET};
	PrimePattern prime_pat(3, 2, _pat, 5);

	ev::AssistedEvictionSetManager ev_manager;
	ev::EvictionSet** eviction_sets = ev_manager.find_eviction_sets(2, 2); // We ask for 2*LLC addresses because we need a contending address
	if(eviction_sets == nullptr) {
		printf("Failed to find eviction sets...\n");
		return 1;
	}
	ev::EvictionSet* evset1 = eviction_sets[0];
	ev::EvictionSet* evset2 = eviction_sets[1];

	bool* trace1 = (bool*) mmap(NULL, sizeof(bool) * TRACE3_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert(trace1 != MAP_FAILED);
	bool* trace2 = (bool*) mmap(NULL, sizeof(bool) * TRACE3_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert(trace2 != MAP_FAILED);

	memset(trace1, 0, sizeof(bool) * TRACE3_LENGTH);
	memset(trace2, 0, sizeof(bool) * TRACE3_LENGTH);
	

	attack_data = (volatile AttackData*) mmap(NULL, PAGE_SIZE_, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	attack_data->start_signal = -1;
	attack_data->victim_slowdown = atoi(argv[2]);

	pid_t victim_pid = setup_victim2(evset1[1].arr[0], evset2[1].arr[0], 1);
#if 1
	pid_t attacker1_pid = setup_prime_scope_attacker(evset1[0], prime_pat, trace1, 0, 2);
	pid_t attacker2_pid = setup_prime_scope_attacker(evset2[0], prime_pat, trace2, 1, 3);
#elif 0
	pid_t attacker1_pid = setup_prime_scope_attacker_opt(evset1[0], prime_pat, trace1, 0, 2);
	pid_t attacker2_pid = setup_prime_scope_attacker_opt(evset2[0], prime_pat, trace2, 1, 3);
#else
	pid_t attacker1_pid = setup_prime_scope_attacker_nomfence(evset1[0], prime_pat, trace1, 0, 2);
	pid_t attacker2_pid = setup_prime_scope_attacker_nomfence(evset2[0], prime_pat, trace2, 1, 3);
#endif
	setaffinity(0);

	uintptr_t trash = (uintptr_t) evset1[0].arr[0];

	memory_fences();

	constexpr int test_count = 10000;

	printf("Running %d tests:\n", test_count);
	int access_count1[TRACE3_LENGTH] = {0};
	int bad_samples1 = 0;
	int access_count2[TRACE3_LENGTH] = {0};
	int bad_samples2 = 0;
	int gaps[TRACE3_LENGTH] = {0};
	uint64_t time_sum1 = 0;
	uint64_t time_sum2 = 0;
	for(int t = 0; t < test_count; t++) {
		memory_fences();

		attack_data->start_signal = 1;

		memory_fences();

		while(attack_data->victim_status != ProcessStatus::Finished) {}
		while(attack_data->attacker_status[0] != ProcessStatus::Finished) {}
		while(attack_data->attacker_status[1] != ProcessStatus::Finished) {}

		memory_fences();
		
		attack_data->start_signal = -1;

		memory_fences();

		attack_data->victim_status = ProcessStatus::Ready;
		attack_data->attacker_status[0] = ProcessStatus::Ready;
		attack_data->attacker_status[1] = ProcessStatus::Ready;

		memory_fences();

		time_sum1 += attack_data->attacker_time[0];
		time_sum2 += attack_data->attacker_time[1];

		int t1 = -1;
		int t2 = -1;
		for(int i = 0; i < EFFECTIVE_LENGTH; i++) {
			if((t1 == -1) && trace1[i]) {
				t1 = i;
			}
			if((t2 == -1) && trace2[i]) {
				t2 = i;
			}
		}

		if(t1 != -1)
			access_count1[t1]++;
		if(t2 != -1)
			access_count2[t2]++;

		if((t1 != -1) && (t2 != -1) && (t2 >= t1))
			gaps[t2 - t1]++;
		
		memset(trace1, 0, sizeof(bool) * TRACE3_LENGTH);
		memset(trace2, 0, sizeof(bool) * TRACE3_LENGTH);
	}

	printf("Average measure time: %lu cycles, average sample time: %lu cycles\n", time_sum1/test_count, time_sum1/(test_count * EFFECTIVE_LENGTH));
	printf("TRACE 1\n");
	int sum = 0;
	for(int i = 0; i < TRACE3_LENGTH; i++) {
		printf(GRY " %2d: " RST "%5.1f ", i, (100*(double)access_count1[i])/test_count);
		sum += access_count1[i];
		if(i%16 == 15)
			printf("\n");
	}
	printf("Sum: %d/%d\n", sum, test_count);

	printf("Average measure time: %lu cycles, average sample time: %lu cycles\n", time_sum2/test_count, time_sum2/(test_count * EFFECTIVE_LENGTH));
	printf("TRACE 2\n");
	sum = 0;
	for(int i = 0; i < TRACE3_LENGTH; i++) {
		printf(GRY " %2d: " RST "%5.1f ", i, (100*(double)access_count2[i])/test_count);
		sum += access_count2[i];
		if(i%16 == 15)
			printf("\n");
	}
	printf("Sum: %d/%d\n", sum, test_count);

	printf("GAPS\n");
	sum = 0;
	for(int i = 0; i < TRACE3_LENGTH; i++) {
		printf(GRY " %2d: " RST "%5.1f ", i, (100*(double)gaps[i])/test_count);
		sum += gaps[i];
		if(i%16 == 15)
			printf("\n");
	}
	printf("Sum: %d/%d\n", sum, test_count);

	cleanup_child(victim_pid);
	cleanup_child(attacker1_pid);
	cleanup_child(attacker2_pid);

	return 0;
}

int test_prime_scope(int argc, char* argv[]) {
	return test_prime_time(argc, argv);
	// return test_prime_scope_basic(argc, argv);
	// return test_prime_scope_trace(argc, argv);
}