#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "util.h"
#include "consts.h"
#include "aes_attack.h"
#include "gates/gates_common.h"
using namespace gates;

#define DO_FOR_120(x) \
	x(0); x(1); x(2); x(3); x(4); x(5); x(6); x(7); x(8); x(9); \
	x(10); x(11); x(12); x(13); x(14); x(15); x(16); x(17); x(18); x(19); \
	x(20); x(21); x(22); x(23); x(24); x(25); x(26); x(27); x(28); x(29); \
	x(30); x(31); x(32); x(33); x(34); x(35); x(36); x(37); x(38); x(39); \
	x(40); x(41); x(42); x(43); x(44); x(45); x(46); x(47); x(48); x(49); \
	x(50); x(51); x(52); x(53); x(54); x(55); x(56); x(57); x(58); x(59); \
	x(60); x(61); x(62); x(63); x(64); x(65); x(66); x(67); x(68); x(69); \
	x(70); x(71); x(72); x(73); x(74); x(75); x(76); x(77); x(78); x(79); \
	x(80); x(81); x(82); x(83); x(84); x(85); x(86); x(87); x(88); x(89); \
	x(90); x(91); x(92); x(93); x(94); x(95); x(96); x(97); x(98); x(99); \
	x(100); x(101); x(102); x(103); x(104); x(105); x(106); x(107); x(108); x(109); \
	x(110); x(111); x(112); x(113); x(114); x(115); x(116); x(117); x(118); x(119);

int slowdown_chain_finegrained_switch(int non_temporal_zero, const int slowdown_param) {
    switch(slowdown_param) {
#define SDC_CASE(i) \
		case i: return slowdown_chain_finegrained(non_temporal_zero, i+1);
		DO_FOR_120(SDC_CASE)
	}
	return 0;
}

int main() {
	// Open shared memory
	int shm = shm_open(AES_BREAK_SHM_NAME, O_RDWR, 0666);
	assert(shm >= 0);
	uintptr_t page1 = map_shm(shm, PAGE_SIZE_, 0);
	uintptr_t page2 = map_shm(shm, PAGE_SIZE_, PAGE_SIZE_);
	volatile AESAttackData* adata = (volatile AESAttackData*) map_shm(shm, sizeof(AESAttackData), 2*PAGE_SIZE_);

	// Setup second line
	uintptr_t second_line = page2 + 37 * CACHE_LINE_SIZE;

	// Simulate attack trigger
	uintptr_t input1 = page1 + PAGE1_CACHELINE*CACHE_LINE_SIZE;

	/// Setup ends, operation begins

	int d = 0;

	uint64_t trash = (uint64_t) adata;
	while(true) {
		memory_fences();
		ProcessStatus stat;
		while(true) {
			stat = adata->victim_status;
			if(stat == ProcessStatus::CopyCiphertext)
				break;
		}
		memory_fences();

		d = adata->parameter;

		memory_fences();

		unsigned init_slowdown = adata->start_phase;
		adata->victim_status = ProcessStatus::Ready;

		memory_fences();
		while(!adata->start_signal) {}
		memory_fences();

		trash ^= slowdown_chain(force_convert_double(init_slowdown != (-2)), init_slowdown) == 0.0;

		uintptr_t race_start = trash == 0xDEADBEEF;
		create_fake_dependency(race_start);

		prevent_reorder();
		// Simulate start trigger
		uintptr_t o1 = READ(input1 + race_start);

		prevent_reorder();

		// Offset start of decryption
		uintptr_t slow = slowdown_chain_finegrained_switch(race_start, d);
		uintptr_t o2 = READ(second_line + slow);

		prevent_reorder();
		trash = o1 ^ o2;

		memory_fences();
		adata->victim_status = ProcessStatus::Finished;

		memory_fences();
		while(true) {
			auto stat = adata->victim_status;
			if(stat == ProcessStatus::Prep || stat == ProcessStatus::CopyCiphertext)
				break;
		};
		memory_fences();
	}

	return 0;
}