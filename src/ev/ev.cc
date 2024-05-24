#include "ev/ev.h"
#include "consts.h"
#include "measure/measure.h"
#include "util.h"

namespace ev {

#define INITIAL_SAMPLE_SIZE (3000)

#define BACKTRACKING_MAXIMUM (70)
static int backtrack_count = 0;

EvictionSetManager::EvictionSetManager(amplification::Amplification &amplification, measure::measure_type measure_with)
    : m_amplification(amplification)
    , m_measure_with(measure_with) {
    initialize_allocation((void **)&eviction_set_memory, DEFAULT_ALLOCATION_SIZE);
}

EvictionSetManager::EvictionSetManager(amplification::Amplification &amplification, size_t allocation_size, measure::measure_type measure_with, int extra_flags, bool private_alloc)
    : m_amplification(amplification)
    , m_measure_with(measure_with) {
    initialize_allocation((void **)&eviction_set_memory, allocation_size, extra_flags, private_alloc);
}

EvictionSet *EvictionSetManager::reduce_eviction_set(uintptr_t target, int retries) {
    switch (m_measure_with) {
        case measure::t_100US: return reduce_eviction_set<measure::t_100US>(target, retries);
        case measure::t_RDTSC: return reduce_eviction_set<measure::t_RDTSC>(target, retries);
    }
}

template<measure::measure_type measure_with>
EvictionSet *EvictionSetManager::reduce_eviction_set(uintptr_t target, int retries) {
    using ChosenProbeParameters = ProbeParameters<21, measure::AmplificationMeasure<measure_with>>;
    EvictionSet *result = nullptr;
    const int max_candidates = DEFAULT_ALLOCATION_SIZE / PAGE_SIZE_;

    int page_offset = get_page_offset(target);
    node _sentinel = { 0 };
    node *sentinel = &_sentinel;

    node_array candidates = { .arr = nullptr, .length = max_candidates };
    candidates.arr = new node *[max_candidates];
    for (int i = 0; i < candidates.length; i++) {
        candidates.arr[i] = (node *)(eviction_set_memory + i * PAGE_SIZE_ + page_offset);
    }

    for (int retry_index = 0; retry_index < retries; retry_index++) {
        candidates.length = max_candidates;
        node_array_shuffle(candidates);

        candidates.length = INITIAL_SAMPLE_SIZE;
        node_array_to_linked_list(candidates, sentinel);

        backtrack_count = 0;
        // typename ChosenProbeParameters::MeasureClass measurer;
        typename ChosenProbeParameters::MeasureClass measurer(m_amplification);
        if (reduce_eviction_set<ChosenProbeParameters>(sentinel, INITIAL_SAMPLE_SIZE, target, measurer)) {
            result = new EvictionSet;
            node_array result_node_array = { .arr = (node **)result->arr, .length = LLC_CACHE_ASSOCIATIVITY };
            linked_list_to_node_array(sentinel->next, result_node_array);
            break;
        }
    }
    delete candidates.arr;
    return result;
}

EvictionSet **EvictionSetManager::find_eviction_sets(int per_bucket, int amount) {
    // Not implemented yet...
    return nullptr;
}

template<typename probe_parameters>
uint64_t __always_inline probe_once(node *set, uintptr_t candidate, typename probe_parameters::MeasureClass m) {
    uint64_t trash = 0;

    trash = FORCE_READ(candidate, trash);
    node *temp = set;
    while (temp != NULL) {
        trash = FORCE_READ(temp, trash);
        temp = temp->next;
    }
    temp = (node *)((uintptr_t)set | (trash == 0xbaaaaad));
    while (temp != NULL) {
        trash = FORCE_READ(temp, trash);
        temp = temp->next;
    }
    return m.measure(candidate, trash);
}

template<typename probe_parameters>
bool __always_inline probe(node *set, uintptr_t candidate, typename probe_parameters::MeasureClass m) {
    uint32_t total = 0;
    for (int i = 0; i < probe_parameters::probe_trials; i++) {
        uint64_t result = probe_once<probe_parameters>(set, candidate, m);
        total += !m.in_cache(result);
    }
    return total > (probe_parameters::probe_trials / 2);
}

template<typename probe_parameters>
bool EvictionSetManager::reduce_eviction_set(node *sentinel, uint32_t length, uintptr_t evictee, typename probe_parameters::MeasureClass m) {
    if (length == LLC_CACHE_ASSOCIATIVITY)
        return true;

    const int N = (LLC_CACHE_ASSOCIATIVITY + 1);
    uint32_t advance_ceil = (length + N - 1) / N;
    uint32_t advance_floor = length / N;
    uint32_t advance = advance_ceil;

    node *chain_start;
    node *chain_end = sentinel;

    for (uint32_t i = 0; i < N; i++) {
        if (i == (length % N))
            advance = advance_floor;
        if (advance == 0)
            continue;
        chain_start = chain_end->next;
        chain_end = node_advance(chain_start, advance - 1);

        node *link_point = chain_start->prev;
        node_unlink_chain(chain_start, chain_end);

        if (probe<probe_parameters>(sentinel->next, evictee, m)) {
#ifdef REDUCE_DBG
            printf("Going in with %d at idx %d\n", length - advance, i);
#endif
            if (reduce_eviction_set<probe_parameters>(sentinel, length - advance, evictee, m))
                return true;
            if (backtrack_count >= BACKTRACKING_MAXIMUM) {
                return false;
            }
        }
#ifdef REDUCE_DBG
        else {
            printf("Not going in..\n");
        }
#endif
        node_link_chain(link_point, chain_start, chain_end);
    }
    backtrack_count++;
#ifdef REDUCE_DBG
    printf("backtracking... %d\n", backtrack_count);
    if (backtrack_count == BACKTRACKING_MAXIMUM) {
        printf("Reached max with size %d\n", length);
    }
#endif
    return false;
}

}