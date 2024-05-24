#pragma once

#include <stdint.h>
#include "consts.h"

constexpr const char* AES_BREAK_SHM_NAME = "aes_break_shm";
constexpr int TRACE_LENGTH = ATTACK_TRACE_LENGTH;
constexpr int PAGE1_CACHELINE = 15;


enum class ProcessStatus {
    Prep,
	CopyCiphertext,
	CopyKey,
	GotKey,
	Ready,
	Finished,
};

struct AESAttackData {
	bool start_signal;
	
	unsigned start_phase;
	unsigned parameter;

	ProcessStatus victim_status;
	ProcessStatus attacker_status[2];

	uint8_t next_ciphertext[16];
	uint8_t next_key[32];
	bool aes_256 = false;

    bool attacker_trace[2][TRACE_LENGTH];
};
static_assert(sizeof(AESAttackData) <= PAGE_SIZE_);


uintptr_t __always_inline map_shm(int shm, size_t size, off_t offset) {
	uintptr_t m = (uintptr_t) mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm, offset);
	assert(m != (uintptr_t) MAP_FAILED);
	return m;
}
