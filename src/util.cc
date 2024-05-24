#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <sched.h>

#include "consts.h"
#include "util.h"

uintptr_t clear_caches_memory = 0;
size_t clear_caches_memory_size = 0;

#define PAGE_BITS (12)
#define CACHE_LINE_BITS (6)

int pagemap_fd = -1;

#ifndef WASM
uint64_t virt_to_physical(uint64_t vaddr) {

    if (pagemap_fd == -1)
        pagemap_fd = open("/proc/self/pagemap", O_RDONLY);

    unsigned long paddr = -1;
    unsigned long index = (vaddr / PAGE_SIZE_) * sizeof(paddr);
    if (pread(pagemap_fd, &paddr, sizeof(paddr), index) != sizeof(paddr)) {
        return -1;
    }
    unsigned long original_paddr = paddr;
    paddr &= 0x7fffffffffffff;

    if(paddr == 0) {
        fprintf(stderr, "virt_to_physical fail on vaddr=%p paddr=%lx!\n", (void*)vaddr, original_paddr);
        assert(false);
    }


    return (paddr << PAGE_BITS) | (vaddr & (PAGE_SIZE_ - 1));
}
#else
#ifndef CHROME
uint64_t virt_to_physical(uintptr_t vaddr) {
    uint64_t paddr = EM_ASM_INT((return %CustomFn(3, $0 | 0)), vaddr);
    return (paddr << PAGE_BITS) | (vaddr & (PAGE_SIZE_ - 1));
}
#else
uint64_t virt_to_physical(uintptr_t vaddr) { return 0; }
#endif
#endif

unsigned int count_bits(uint64_t n) {
    unsigned int count = 0;
    while (n) {
        n &= (n - 1);
        count++;
    }
    return count;
}

unsigned int nbits(uint64_t n) {
    unsigned int ret = 0;
    n = n >> 1;
    while (n > 0) {
        n >>= 1;
        ret++;
    }
    return ret;
}

uint64_t physical_to_slice(uint64_t paddr) {
    unsigned long long ret = 0;
    unsigned long long mask[3] = { 0x1b5f575440ULL, 0x2eb5faa880ULL, 0x3cccc93100ULL }; // according to Maurice et al.
    int bits = nbits(LLC_SLICES);
    switch (bits) {
    case 3:
        ret = (ret << 1) | (unsigned long long)(count_bits(mask[2] & paddr) % 2);
    case 2:
        ret = (ret << 1) | (unsigned long long)(count_bits(mask[1] & paddr) % 2);
    case 1:
        ret = (ret << 1) | (unsigned long long)(count_bits(mask[0] & paddr) % 2);
    default:
        break;
    }
    return ret;
}

const int cache_sets = LLC_CACHE_SIZE / CACHE_LINE_SIZE / LLC_CACHE_ASSOCIATIVITY / LLC_SLICES;

uint64_t physical_to_cacheset(uint64_t paddr) {
    return (paddr >> CACHE_LINE_BITS) & (cache_sets - 1);
}

cache_bucket to_cache_bucket(uint64_t vaddr) {
    uint64_t paddr = virt_to_physical(vaddr);
    return (cache_bucket) { .cache_set = static_cast<int>(physical_to_cacheset(paddr)), .slice = static_cast<int>(physical_to_slice(paddr)) };
}

void print_cache_bucket(uint64_t vaddr, bool new_line) {
    cache_bucket bucket = to_cache_bucket(vaddr);
    printf("(%d, %d)%s", bucket.cache_set, bucket.slice, new_line ? "\n" : "");
}

uint64_t int_pow(uint64_t base, unsigned int exp) {
    uint64_t result = 1;
    while (exp) {
        if (exp & 1)
            result *= base;
        exp >>= 1;
        base *= base;
    }
    return result;
}

void initialize_allocation(void **target, size_t size, int extra_flags, bool private_alloc) {
    static int defining_const = 0xabcd00;

    void *result = mmap(NULL, size, PROT_READ | PROT_WRITE, (private_alloc?MAP_PRIVATE:MAP_SHARED) | MAP_ANONYMOUS | extra_flags, 0, 0);
    assert(result != MAP_FAILED);
    for (int i = 0; i < size / PAGE_SIZE_; i++) {
        snprintf((char *)result + PAGE_SIZE_ * i, PAGE_SIZE_, "%d %d", i, defining_const);
        for (int j = 0; j < PAGE_SIZE_ / CACHE_LINE_SIZE; j++) {
            *(int *)((uintptr_t)result + PAGE_SIZE_ * i + j * CACHE_LINE_SIZE + 32) = 0x1234;
        }
    }
    *target = result;
    defining_const += 1;
}

void initialize_clear_cache_allocation() {
    if (!clear_caches_memory) {
        clear_caches_memory_size = LLC_CACHE_SIZE * CLEAR_CACHE_MEMORY_MULTIPLIER;
        initialize_allocation((void **)&clear_caches_memory, clear_caches_memory_size);
    }
}

void clear_all_caches(uint64_t &trash) {
    uintptr_t local_clear_caches_memory = clear_caches_memory;
    int local_clear_caches_memory_size = clear_caches_memory_size;
    local_clear_caches_memory = local_clear_caches_memory | (trash == 0xbaaaad);
    for (int i = 0; i < local_clear_caches_memory_size; i += DOUBLE_CACHE_LINE_SIZE) {
        TEMPORAL_ADD(trash, *(uintptr_t *)(local_clear_caches_memory + i));
    }
    local_clear_caches_memory = local_clear_caches_memory | (trash == 0xbaaaad);
    for (int i = CACHE_LINE_SIZE; i < local_clear_caches_memory_size; i += DOUBLE_CACHE_LINE_SIZE) {
        TEMPORAL_ADD(trash, *(uintptr_t *)(local_clear_caches_memory + i));
    }
}

template<int size>
struct non_cow_memory {
    constexpr non_cow_memory()
        : arr() {
        for (int i = 0; i < size; i += CACHE_LINE_SIZE) {
            arr[i] = 0xf0 + i / PAGE_SIZE_;
        }
    }
    char __attribute__((aligned(PAGE_SIZE_))) arr[size];
};

void fetch_address(uintptr_t address, address_state to_state) {
    constexpr auto l1_eviction_set = non_cow_memory<PAGE_SIZE_ * L1D_CACHE_ASSOCIATIVITY>();
    switch (to_state) {
    case L1:
        asm volatile("" ::"r"(*(uintptr_t *)address));
        break;
    case L2:
        asm volatile("" ::"r"(*(uintptr_t *)address));
        memory_fences();
        for (int i = 0; i < L1D_CACHE_ASSOCIATIVITY; i++) {
            asm volatile("" ::"r"(l1_eviction_set.arr[(i * PAGE_SIZE_) + (address & 0xfff)]));
        }
        break;
    case LLC:
    case IN_CACHE:
        asm volatile("" ::"r"(*(uintptr_t *)(address ^ CACHE_LINE_SIZE)));
        break;
    case RAM:
        clflush((void *)address);
    }
}

const char *state_to_string(address_state state) {
    switch (state) {
    case L1:
        return RED "L1" RST;
    case L2:
        return RED "L2" RST;
    case LLC:
        return RED "LLC" RST;
    case RAM:
        return GRN "RAM" RST;
    case IN_CACHE:
        return RED "IC" RST;
    }
}

void hexdump(const char *desc, const void *addr, const int len, int perLine) {
    // Silently ignore silly per-line values.

    if (perLine < 4 || perLine > 64)
        perLine = 16;

    int i;
    unsigned char buff[perLine + 1];
    const unsigned char *pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL)
        printf("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of perLine means new or first line (with line offset).

        if ((i % perLine) == 0) {
            // Only print previous-line ASCII buffer for lines beyond first.

            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset of current line.

            printf("  %04x ", i);
        }

        // Now the hex code for the specific character.

        printf(" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % perLine] = '.';
        else
            buff[i % perLine] = pc[i];
        buff[(i % perLine) + 1] = '\0';
    }

    // Pad out last line if not exactly perLine characters.

    while ((i % perLine) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf("  %s\n", buff);
}

uintptr_t mmap_symbol_from_binary(const char *path, const char *symbol) {
    char command_buffer[PAGE_SIZE_] = { 0 };

    // This is an obvious shell injection, I really am not careful :P
    assert(snprintf(command_buffer, PAGE_SIZE_ - 1, "readelf -s %s | grep %s | awk '{print $2}'", path, symbol) > 0);

    uint64_t file_offset = 0;
    FILE *result = popen(command_buffer, "r");
    assert(fscanf(result, "%" PRIx64, &file_offset) == 1);
    pclose(result);

    assert(file_offset != 0);
    int fd = open(path, O_RDONLY);
    assert(fd != -1);

    uintptr_t mmap_result = (uintptr_t)mmap(0, PAGE_SIZE_, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, file_offset & ~(PAGE_SIZE_ - 1));
    close(fd);

    assert(mmap_result != -1);

    return mmap_result + (file_offset & (PAGE_SIZE_ - 1));
}

void setaffinity(int core) {
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(core, &set);
	assert(sched_setaffinity(0, sizeof(cpu_set_t), &set) == 0);
}

void yield_execution() {
    sched_yield();
}