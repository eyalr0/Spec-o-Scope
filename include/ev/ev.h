#pragma once
#include "amplification/amplification.h"
#include "consts.h"
#include "linked_list.h"
#include <stddef.h>
#include <stdint.h>

namespace ev {

#define DEFAULT_ALLOCATION_SIZE (3 * LLC_CACHE_SIZE)
#define DEFAULT_MEASURE_WITH (measure::t_RDTSC)

class EvictionSet {
public:
    uintptr_t arr[LLC_CACHE_ASSOCIATIVITY];

    int eviction_set_page_offset() {
        return arr[0] % PAGE_SIZE_;
    }
};

template<int PROBE_TRIALS, class MEASURE_CLASS>
class ProbeParameters {
public:
    static constexpr int probe_trials = PROBE_TRIALS;
    using MeasureClass = MEASURE_CLASS;
};

class EvictionSetManager {
public:
    EvictionSetManager(amplification::Amplification &amplification, measure::measure_type measure_with = DEFAULT_MEASURE_WITH);
    EvictionSetManager(amplification::Amplification &amplification, size_t allocation_size, measure::measure_type measure_with = DEFAULT_MEASURE_WITH, int extra_flags = 0, bool private_alloc = true);

    EvictionSet *reduce_eviction_set(uintptr_t target, int retries = 1);
    EvictionSet **find_eviction_sets(int per_bucket, int amount);

protected:
    uintptr_t eviction_set_memory;

private:
    amplification::Amplification &m_amplification;
    measure::measure_type m_measure_with;
    template<measure::measure_type type>
    EvictionSet *reduce_eviction_set(uintptr_t target, int retries);
    template<class probe_parameters>
    bool reduce_eviction_set(node *sentinel, uint32_t length, uintptr_t evictee, typename probe_parameters::MeasureClass m);
};

}