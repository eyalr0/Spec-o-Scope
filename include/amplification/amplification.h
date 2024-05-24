#pragma once
#include <stdbool.h>
#include <stdint.h>

#include "consts.h"
#include "util.h"

namespace amplification {

class Amplification {
public:
    virtual void initialize(uint64_t &trash) = 0;
    virtual void amplify(uintptr_t target, uint64_t &trash) = 0;
    virtual bool is_in_cache(uint64_t time_difference, measure::measure_type type) = 0;
};

class TrivialNoAmplification : public Amplification {
public:
    void initialize(uint64_t &trash) final { }
    void amplify(uintptr_t target, uint64_t &trash) final { trash = FORCE_READ(target, trash); }
    bool is_in_cache(uint64_t time_difference, measure::measure_type type) final {
        if (type == measure::t_RDTSC)
            return time_difference < RDTSC_THRESHOLD;

        // This "amplification" cannot distinguish with t_100US.
        return false;
    }
};

}