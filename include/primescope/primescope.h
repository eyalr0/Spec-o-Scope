#pragma once

#include <stdint.h>
#include <stddef.h>
#include <vector>

#include "ev/ev.h"

namespace prime_scope {

constexpr size_t PATTERN_CAPACITY = 20;
constexpr uint8_t PATTERN_TARGET = 0xFF;
struct PrimePattern {
	uint8_t repeat;
	uint8_t stride;
	uint8_t width; // The largest offset from i
	uint8_t length;
	uint8_t pattern[PATTERN_CAPACITY] = {}; // 0xFF denotes the target, other values denote offset from i
	double tested_evcr;
	uint64_t tested_cycle_count;

	constexpr PrimePattern(uint8_t repeat, uint8_t stride, const uint8_t* pattern, size_t length):
		repeat(repeat), stride(stride), length(length), tested_evcr(0), tested_cycle_count(-1) {
		assert(length <= PATTERN_CAPACITY);

		width = 0;
		for(int i = 0; i < length; i++) {
			this->pattern[i] = pattern[i];
			if(pattern[i] != PATTERN_TARGET && pattern[i] > width) {
				width = pattern[i];
			}
		}
	}

	void dump();

	uint64_t __attribute_noinline__ access(ev::EvictionSet const& evset, uint64_t trash) const {
		for(int r = 0; r < repeat; r++) {
			for(int i = 0; i < LLC_CACHE_ASSOCIATIVITY - width; i++) {
				for(int j = 0; j < length; j++) {
					int off = pattern[j];
					if(off == PATTERN_TARGET) {
						trash = FORCE_READ(evset.arr[0], trash);
					} else {
						trash = FORCE_READ(evset.arr[i + off], trash);
					}
				}
			}
		}

		return trash;
	}
};

std::vector<PrimePattern> generate_prime_patterns(ev::EvictionSet* evset);

// Intel Core i5-8250U: R3_S2_P1022S (EVCr: 99.998%, 1193 RDTSC cycles at 3.4GHz)
constexpr uint8_t _optimal_pat[5] = {1, 0, 2, 2, PATTERN_TARGET};
constexpr PrimePattern optimal_prime_pat(3, 2, _optimal_pat, 5);

}