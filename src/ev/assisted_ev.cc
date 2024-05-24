#include "ev/assisted_ev.h"
#include <set>

namespace ev {

#define PAGES (12000)
#define ALLOCATION_SIZE (PAGES * PAGE_SIZE_)

auto _amp = amplification::TrivialNoAmplification();
amplification::Amplification &amp = _amp;

AssistedEvictionSetManager::AssistedEvictionSetManager(bool private_alloc)
    : EvictionSetManager(amp, ALLOCATION_SIZE, measure::t_RDTSC, 0, private_alloc) {
}

EvictionSet *AssistedEvictionSetManager::reduce_eviction_set(uintptr_t target, int retries) {
    return find_multiple_eviction_sets(to_cache_bucket(target), 1, target % PAGE_SIZE_);
}

uintptr_t AssistedEvictionSetManager::get_page(int index) {
    return eviction_set_memory + index * PAGE_SIZE_;
}

EvictionSet *AssistedEvictionSetManager::find_multiple_eviction_sets(cache_bucket target, int amount, int page_offset) {
    EvictionSet *result = new EvictionSet[amount];
    int current_index = 0;

    for (int i = 0; i < PAGES; i++) {
        uintptr_t candidate = get_page(i) + page_offset;
        if (to_cache_bucket(candidate) != target)
            continue;
        
        result[current_index / LLC_CACHE_ASSOCIATIVITY].arr[current_index % LLC_CACHE_ASSOCIATIVITY] = candidate;
        current_index++;
        
        if (current_index == amount * LLC_CACHE_ASSOCIATIVITY)
            return result;
    }

    delete[] result;
    return nullptr;
}

EvictionSet **AssistedEvictionSetManager::find_eviction_sets(int per_bucket, int amount) {
    EvictionSet **result = new EvictionSet *[amount];
    std::set<cache_bucket> cache_buckets;
    int found_so_far = 0;

    for (int i = 0; i < PAGES; i++) {
        uintptr_t target = get_page(i);
        cache_bucket curr = to_cache_bucket(target);
        if (!cache_buckets.contains(curr)) {
            EvictionSet *eviction_sets = find_multiple_eviction_sets(curr, per_bucket);
            if (eviction_sets == nullptr)
                continue;

            cache_buckets.emplace(curr);
            result[found_so_far++] = eviction_sets;
        }

        if (found_so_far == amount)
            return result;
    }

    // Fail flow, clean up.
    for (int i = 0; i < found_so_far; i++)
        delete[] result[i];
    delete[] result;
    return nullptr;
}

}