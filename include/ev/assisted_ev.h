#pragma once
#include "consts.h"
#include "ev.h"
#include "util.h"

namespace ev {

class AssistedEvictionSetManager : public EvictionSetManager {
public:
    AssistedEvictionSetManager(bool private_alloc = true);

    EvictionSet *reduce_eviction_set(uintptr_t target, int retries = 1);
    EvictionSet **find_eviction_sets(int per_bucket, int amount);

private:
    EvictionSet *find_multiple_eviction_sets(cache_bucket target, int amount, int page_offset = 0);
    uintptr_t get_page(int index);
};

}