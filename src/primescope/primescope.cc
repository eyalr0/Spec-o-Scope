#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>

#include "primescope/primescope.h"
#include "measure/measure.h"

namespace prime_scope {

void PrimePattern::dump() {
    printf("R%d_S%d_P", repeat, stride);
    for(int i = 0; i < length; i++) {
        if(pattern[i] == PATTERN_TARGET) {
            printf("S");
        } else {
            printf("%d", pattern[i]);
        }
    }
}

static void mutate_repeat_subpatterns(std::vector<PrimePattern>& patterns, bool fine_tune) {
	int cur_count = patterns.size();
	for(int i = 0; i < cur_count; i++) {
		if(fine_tune && (rand() % 2 == 0)) continue;

		auto& pat = patterns[i];
		int start = rand() % pat.length;
		int sub_len = 1 + rand() % (pat.length - start);
		assert(pat.length + sub_len <= PATTERN_CAPACITY);

		uint8_t mut[PATTERN_CAPACITY];
		for(int k = 0; k < start + sub_len; k++) {
			mut[k] = pat.pattern[k];
		}
		for(int k = 0; k < sub_len; k++) {
			mut[start + sub_len + k] = pat.pattern[start + k];
		}
		for(int k = 0; k < pat.length - sub_len - start; k++) {
			mut[start + sub_len + sub_len + k] = pat.pattern[start + sub_len + k];
		}

		patterns.emplace_back(pat.repeat, pat.stride, mut, pat.length + sub_len);
	}
}

static void shuffle(uint8_t* arr, int size) {
	for(int i = size - 1; i > 0; i--) {
		int j = rand() % (i + 1);
		uint8_t tmp = arr[i];
		arr[i] = arr[j];
		arr[j] = tmp;
	}
}

static void mutate_permute_order(std::vector<PrimePattern>& patterns, int num_permutes, bool fine_tune) {
	int cur_count = patterns.size();
	for(int i = 0; i < cur_count; i++) {
		if(fine_tune && (rand() % 2 == 0)) continue;

		auto& pat = patterns[i];
		if(pat.length == 1) continue;

		int num_perms = num_permutes;
		if(pat.length == 2) num_perms = 1;
		if(pat.length == 3) num_perms = 4;
		
		for(int j = 0; j < num_perms; j++) {
			uint8_t mut[PATTERN_CAPACITY];
			memcpy(mut, pat.pattern, PATTERN_CAPACITY);
			shuffle(mut, pat.length);
			patterns.emplace_back(pat.repeat, pat.stride, mut, pat.length);
		}
	}
}

static void mutate_interleave_target(std::vector<PrimePattern>& patterns, bool fine_tune) {
	int cur_count = patterns.size();
	for(int i = 0; i < cur_count; i++) {
		if(fine_tune && (rand() % 2 == 0)) continue;

		auto& pat = patterns[i];
		int max_iter = 4;
		if(pat.length == 1) max_iter = 1;
		if(pat.length == 2) max_iter = 2;

		for(int j = 0; j < max_iter; j++) {
			int num_target = 1;
			if(pat.length > 1 && rand()%2 == 0) num_target++;
			if(pat.length > 3 && rand()%8 == 0) num_target++;

			assert(pat.length + num_target <= PATTERN_CAPACITY);

			uint8_t mut[PATTERN_CAPACITY];
			memcpy(mut, pat.pattern, PATTERN_CAPACITY);
			int length = pat.length;
			for(int k = 0; k < num_target; k++) {
				int idx = rand() % (length + 1);
				for(int a = idx; a < length; a++) {
					mut[a+1] = mut[a];
				}
				mut[idx] = PATTERN_TARGET;
				length++;
			}
			patterns.emplace_back(pat.repeat, pat.stride, mut, length);
		}
	}
}

static uint64_t test_pattern(ev::EvictionSet* evset, PrimePattern& pat, int test_count, uint64_t trash) {
	measure::Measure<measure::t_RDTSC> rdtsc_measure;

	
	int evc_count = 0;
	uint64_t time_sum = 0;

	for(int t = 0; t < test_count; t++) {
		time_sum += rdtsc_measure.measure([&](uint64_t &trash_) {
			trash = pat.access(evset[0], trash);
		}, trash);

		uint64_t t_l1 = rdtsc_measure.measure(evset[0].arr[0], trash);
		trash = FORCE_READ(evset[1].arr[0], trash);
		uint64_t t_evict = rdtsc_measure.measure(evset[0].arr[0], trash);

		if(rdtsc_measure.in_cache(t_l1) && !rdtsc_measure.in_cache(t_evict)) {
			evc_count++;
		}
	}

	pat.tested_evcr = ((float)evc_count)/test_count;
	pat.tested_cycle_count = time_sum/test_count;

	return trash;
}

static void test_patterns(ev::EvictionSet* evset, std::vector<PrimePattern>& patterns, int test_count) {
	uint64_t trash = (uint64_t) evset;
	for(int i = 0; i < patterns.size(); i++) {
		trash = test_pattern(evset, patterns[i], test_count, trash);
		if(i % 500 == 0) {
			printf("\tPT: [test_patterns %d/%zu]\n", i, patterns.size());
		}
	}
}

static void filter_evcr(std::vector<PrimePattern>& patterns, int count) {
	assert(count <= patterns.size());

	std::sort(patterns.begin(), patterns.end(), [](PrimePattern const& a, PrimePattern const& b) {
		return a.tested_evcr > b.tested_evcr;
	});

	patterns.erase(patterns.begin() + count, patterns.end());
}

static void filter_time(std::vector<PrimePattern>& patterns, int count) {
	assert(count <= patterns.size());

	std::sort(patterns.begin(), patterns.end(), [](PrimePattern const& a, PrimePattern const& b) {
		return a.tested_cycle_count < b.tested_cycle_count;
	});

	patterns.erase(patterns.begin() + count, patterns.end());
}

// "PrimeTime"
std::vector<PrimePattern> generate_prime_patterns(ev::EvictionSet* evset) {
	std::vector<PrimePattern> patterns;
	patterns.reserve(50'000);

	// 1. Generate initial patterns
	uint8_t pattern[PATTERN_CAPACITY];
	for(int i = 0; i < PATTERN_CAPACITY; i++) {
		pattern[i] = i;
	}
	for(int r = 1; r <= 8; r++) {
		for(int s = 1; s <= 4; s++) {
			for(int l = 1; l < 5; l++) {
				patterns.emplace_back(r, s, pattern, l);
			}
		}
	}

	printf("PT: %zu initial patterns\n", patterns.size());

	// 2. Mutation:
	//	- Repeated access to (sub-)patterns
	// 	- Permutation of access orders
	//	- Interleaving of target accesses
	mutate_repeat_subpatterns(patterns, false);
	mutate_permute_order(patterns, 16, false);
	mutate_interleave_target(patterns, false);

	printf("PT: %zu initial mutated patterns\n", patterns.size());

	// 3. Measurements: Test 10'000 times
	//	- Filter to 150 highest EVCr
	//	- Filter to 100 fastest
	test_patterns(evset, patterns, 10'000);
	filter_evcr(patterns, 150);
	filter_time(patterns, 100);

	printf("PT: Filtered to top %zu patterns\n", patterns.size());

	// 4. Further mutation of candidates
	mutate_repeat_subpatterns(patterns, true);
	mutate_permute_order(patterns, 4, true);
	mutate_interleave_target(patterns, true);

	printf("PT: %zu further mutated patterns\n", patterns.size());

	// 5. Measurements: Test 100'000 times
	//	- Filter to 150 highest EVCr
	//	- Filter to 100 fastest
	test_patterns(evset, patterns, 100'000);
	filter_evcr(patterns, 150);
	filter_time(patterns, 100);

	std::vector<PrimePattern> results(patterns); // Note: Copy to free the reserved memory
	return results;
}

}