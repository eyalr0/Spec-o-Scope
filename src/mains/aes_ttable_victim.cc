#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "util.h"
#include "consts.h"
#include "aes_attack.h"
#include "aes.h"
#include "gates/gates_common.h"
using namespace gates;

#define AESSIZE 16
typedef uint8_t aes_t[AESSIZE];

int main() {
	// Setup AES key
	aes_t output;
	uint8_t key[32];
	tobinary("99696f874385da79659bf0294f365347", key);
	AES_KEY aeskey;
	private_AES_set_decrypt_key(key, 128, &aeskey);

	// Open shared memory
	int shm = shm_open(AES_BREAK_SHM_NAME, O_RDWR, 0666);
	assert(shm >= 0);
	uintptr_t page1 = map_shm(shm, PAGE_SIZE_, 0);
	uintptr_t page2 = map_shm(shm, PAGE_SIZE_, PAGE_SIZE_);
	volatile AESAttackData* adata = (volatile AESAttackData*) map_shm(shm, sizeof(AESAttackData), 2*PAGE_SIZE_);

	// Setup Shared T-Tables
	char* Td0_shared = (char*)page2;
	memcpy(Td0_shared, Td0_, sizeof(Td0_));
	char* Td1_shared = Td0_shared + sizeof(Td0_);
	memcpy(Td1_shared, Td1_, sizeof(Td1_));
	char* Td2_shared = Td1_shared + sizeof(Td1_);
	memcpy(Td2_shared, Td2_, sizeof(Td2_));
	char* Td3_shared = Td2_shared + sizeof(Td2_);
	memcpy(Td3_shared, Td3_, sizeof(Td3_));

	Td0 = (uint32_t*) Td0_shared;
	Td1 = (uint32_t*) Td1_shared;
	Td2 = (uint32_t*) Td2_shared;
	Td3 = (uint32_t*) Td3_shared;


	// // Simulate attack trigger
	// uintptr_t input1 = page1 + PAGE1_CACHELINE*CACHE_LINE_SIZE;
	

	/// Setup ends, operation begins

	aes_t input;
	uint64_t trash = (uint64_t) adata;
	while(true) {
		memory_fences();
		ProcessStatus stat;
		while(true) {
			stat = adata->victim_status;
			if(stat == ProcessStatus::CopyCiphertext || stat == ProcessStatus::CopyKey)
				break;
		}
		memory_fences();

		if(stat == ProcessStatus::CopyKey) {
			for(int i = 0; i < 32; i++) {
				key[i] = adata->next_key[i];
			}
			int bits = (adata->aes_256)?256:128;
			private_AES_set_decrypt_key(key, bits, &aeskey);

			memory_fences();
			adata->victim_status = ProcessStatus::GotKey;
			memory_fences();

			while(adata->victim_status != ProcessStatus::CopyCiphertext);
			memory_fences();
		}

		for(int i = 0; i < AESSIZE; i++){
			input[i] = adata->next_ciphertext[i];
		}

		memory_fences();

		trash = FORCE_READ(input, trash);

		memory_fences();

		adata->victim_status = ProcessStatus::Ready;

		memory_fences();
		while(!adata->start_signal) {}
		memory_fences();

		unsigned init_slowdown = adata->start_phase;

		trash ^= slowdown_chain(force_convert_double(init_slowdown != (-2)), init_slowdown) == 0.0;

		uintptr_t race_start = trash == 0xDEADBEEF;
		create_fake_dependency(race_start);

		prevent_reorder();
		// // Simulate start trigger
		// uintptr_t o1 = READ(input1 + race_start);

		prevent_reorder();

		// Offset start of decryption
		uintptr_t slow = slowdown_chain(force_convert_double(race_start), 3) == 1.0;

		AES_decrypt(((uint8_t*)input) + slow, output, &aeskey);

		for(int i = 0; i < AESSIZE; i++)
			create_fake_dependency(output[i]);

		prevent_reorder();
		// trash = o1 ^ output[0];
		trash = output[0];

		memory_fences();
		adata->victim_status = ProcessStatus::Finished;

		memory_fences();
		while(true) {
			auto stat = adata->victim_status;
			if(stat == ProcessStatus::Prep || stat == ProcessStatus::CopyCiphertext || stat == ProcessStatus::CopyKey)
				break;
		};
		memory_fences();
	}

	return 0;
}