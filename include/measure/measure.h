#pragma once
#include "amplification/amplification.h"
#include "util.h"
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>

namespace measure {

template<measure_type type>
class Measure {
public:
    constexpr Measure() {};

    static uint64_t __attribute__((noinline)) measure(uintptr_t target, uint64_t &trash) {
        // Not strictly necessary, but prevents deref of trash at critical timing section.
        uint64_t trash_ = trash;

        uint64_t start_ = start(trash_);
        trash_ = FORCE_READ(target, trash_);
        uint64_t end_ = end(trash_);
        uint64_t result = val(start_, end_, trash_);

        trash = trash_;
        return result;
    }

    template<typename F>
    static uint64_t __attribute__((noinline)) measure(F &&f, uint64_t &trash) {
        // Not strictly necessary, but prevents deref of trash at critical timing section.
        uint64_t trash_ = trash;

        uint64_t start_ = start(trash_);
        f(trash_);
        uint64_t end_ = end(trash_);
        uint64_t result = val(start_, end_, trash_);

        trash = trash_;
        return result;
    }

    static bool in_cache(uint64_t time_delta) {
        amplification::TrivialNoAmplification trivial;
        return trivial.is_in_cache(time_delta, type);
    }

    static uint64_t start(uint64_t &trash) {
        uint64_t start = start_timestamp(trash);
        trash += start;
        return start;
    }

    static uint64_t end(uint64_t &trash) {
        uint64_t end = end_timestamp(trash);
        trash += end;
        return end;
    }

    static uint64_t val(uint64_t start, uint64_t end, uint64_t &trash) {
        uint64_t result = end - start + (trash == 0xbaaaaad);
        trash += result;
        return result;
    }
protected:

private:
    static uint64_t start_timestamp(uint64_t trash);
    static uint64_t end_timestamp(uint64_t trash);
};

template<measure_type type>
class AmplificationMeasure : public Measure<type> {
public:
    AmplificationMeasure(amplification::Amplification &a)
        : m_amplification(a) { }

    uint64_t measure(uintptr_t target, uint64_t &trash) {
        uint64_t start = Measure<type>::start(trash);
        m_amplification.amplify(target, trash);
        uint64_t end = Measure<type>::end(trash);
        return Measure<type>::val(start, end, trash);
    }

    bool in_cache(uint64_t time_delta) {
        return m_amplification.is_in_cache(time_delta, type);
    }

private:
    amplification::Amplification &m_amplification;
};

#ifndef WASM
uint64_t __always_inline rdtsc() {
    uint64_t result;
    asm volatile("rdtsc\n\t"          // Returns the time in EDX:EAX.
                 "shl rdx, 32\n\t" // Shift the upper bits left.
                 "or %0, rdx"       // 'Or' in the lower bits.
                 : "=a"(result)
                 :
                 : "rdx");
    return result;
}

uint64_t __always_inline rdtscp() {
    uint64_t result;
    asm volatile("rdtscp\n\t"          // Returns the time in EDX:EAX.
                 "shl rdx, 32\n\t" // Shift the upper bits left.
                 "or %0, rdx"       // 'Or' in the lower bits.
                 : "=a"(result)
                 :
                 : "rdx", "rcx");
    return result;
}

uint64_t __always_inline rdtsc_strong() {
    uint64_t result;
    asm volatile("mfence\nlfence\nrdtsc\nlfence\n\t"          // Returns the time in EDX:EAX.
                 "shl rdx, 32\n\t" // Shift the upper bits left.
                 "or %0, rdx"       // 'Or' in the lower bits.
                 : "=a"(result)
                 :
                 : "rdx");
    return result;
}

uint64_t __always_inline rdtscp_strong() {
    uint64_t result;
    asm volatile("rdtscp\nlfence\n\t"          // Returns the time in EDX:EAX.
                 "shl rdx, 32\n\t" // Shift the upper bits left.
                 "or %0, rdx"       // 'Or' in the lower bits.
                 : "=a"(result)
                 :
                 : "rdx", "rcx");
    return result;
}

template<>
uint64_t __always_inline Measure<t_RDTSC>::start_timestamp(uint64_t trash) {
    // TODO: write a test to verify these are indeed needed.
    return rdtsc_strong();
}

template<>
uint64_t __always_inline Measure<t_RDTSC>::end_timestamp(uint64_t trash) {
    return rdtscp_strong();
}
#else
#define RDTSC_START_MAGIC 0xddaa00ccbb00
#define RDTSC_END_MAGIC 0xddaa00ccbb80

template<>
uint64_t __always_inline Measure<t_RDTSC>::start_timestamp(uint64_t trash) {
    return RDTSC_START_MAGIC + (trash == 0xbaaaad);
}

template<>
uint64_t __always_inline Measure<t_RDTSC>::end_timestamp(uint64_t trash) {
    return RDTSC_END_MAGIC + (trash == 0xbaaaad);
}
#endif


#ifndef WASM
template<>
uint64_t __always_inline Measure<t_100US>::start_timestamp(uint64_t trash) {
    struct timeval te;
    gettimeofday(&te, NULL);
    return te.tv_sec * 10000LL + te.tv_usec / 100LL;
}
#else
#include <emscripten.h>

template<>
uint64_t __always_inline Measure<t_100US>::start_timestamp(uint64_t trash) {
    return (uint64_t)(emscripten_get_now() * 10);
}

#endif

template<>
uint64_t __always_inline Measure<t_100US>::end_timestamp(uint64_t trash) {
    return start_timestamp(trash);
}


}