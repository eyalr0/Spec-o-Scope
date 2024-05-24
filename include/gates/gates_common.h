#pragma once
#include <math.h>
#include "gates/gates.h"

namespace gates {

void __always_inline ensure_bank_loaded(GateBank *&bank, uint64_t trash) {
    // Make sure future bank dereferences depend on `trash`
    bank = (GateBank *)((uintptr_t)bank | (trash == 0xbaaaaad) | (bank->inputs[0] == 0xbaaaaad) | (bank->outputs[0] == 0xbaaaaad));
}

// A good value - 100.
#define DEFAULT_OVERWRITE_BRANCH_HISTORY 100
void __always_inline overwrite_branch_history() {
    #pragma nounroll
    for (uint64_t i = 0; i < DEFAULT_OVERWRITE_BRANCH_HISTORY; i++) {asm volatile("");}
}

// This function always returns 1 (unless the value is 0xbaaaaad).
bool __always_inline read_input(GateBank *bank, int index) {
    return (READ(bank->inputs[index])) != 0xbaaaaad;
}

// This function always returns 1 (unless one the values is 0xbaaaaad).
bool __always_inline read_inputs_and_base(GateBank *bank, int fan_in, uint64_t &trash) {
    bool and_result = 1;
    #pragma clang loop unroll(full)
    for (int i = 0; i < fan_in; i++) {
        and_result &= read_input(bank, i);
    }
    trash ^= and_result;
    return and_result;
}

void __always_inline prevent_reorder() { asm volatile (""); }

template<class T>
void __always_inline create_fake_dependency(T z) { asm volatile ("" :: "r"(z) :); }
template<class T>
T __always_inline create_fake_source() {
    T res;
    asm volatile ("xor %0, %0" : "=r"(res) ::);
    return res;
}
template <class T>
T blackbox(T x) {
    asm volatile("":"+r"(x));
    return x;
}

// NOTE: `slowdown_parmater` is an important paramater, be careful when playing with it!
// It balances between ensuring speculative windows induced by LLC reads don't reach the reading outputs part,
// and between having the last output read and the first input read within the same ROB (i.e, not too far from eachother).
// NOTE: It may be the case that this paramater should be tuned with respect to the amount on inputs in the gate.
double __always_inline slowdown_chain(double non_temporal_zero, const int slowdown_parmater = 14) {
    #pragma clang loop unroll(full)
    for (int i = 0; i < slowdown_parmater; i++) {non_temporal_zero = sqrt(non_temporal_zero);}

    return non_temporal_zero;
}

int __always_inline slowdown_chain_finegrained(int non_temporal_zero, const int slowdown_param) {
    int result = 0;

    #pragma clang loop unroll(full)
    for(int i = 0; i < slowdown_param; i++) {
        asm ("add %0, %1" : "+r"(result), "+r"(non_temporal_zero) :: );
    }

    return result;
}

// Force the compiler to convert the input to a double directly, without branching.
// For WASM, using `(trash == 1) ^ (trash == 2)` instead of `(trash == 1)` also works, but slower
double __always_inline force_convert_double(uint64_t input) {
    double result;
    asm ("cvtsi2sd %0, %1" : "=x"(result) : "r"(input) :);
    return result;
}

uintptr_t __always_inline force_div(uintptr_t a, uintptr_t b) {
    uintptr_t result;
    asm ("mov rax, %1 \n xor rdx, rdx \n div %2 \n mov %0, rax" : "=r"(result) : "r"(a), "r"(b) : "rdx", "rax");
    return result;
}



uint64_t __always_inline read_outputs_base(GateBank *bank, int fan_out, uintptr_t temporal_zero) {
    // Make sure future bank dereferences depend on `non_temporal_zero`
    bank = (GateBank *)((uintptr_t)bank | (temporal_zero));

    uint64_t sum = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < fan_out; i++) {
        sum += *(uint64_t *)(bank->outputs[i]);
    }
    return sum;
}

static uint64_t branch_counter = 0;

extern "C" {
// This function returns 1 iff the execution is within a speculative window.
static uintptr_t __attribute__ ((noinline)) temporal_branch_misprediction(uint64_t temporal_zero) {
    uint64_t index = (branch_counter++) & 0x7;
    switch (index ^ temporal_zero) {
        case 0x0: asm volatile(""); if (index == 0x0) return 0; break;
        case 0x1: asm volatile(""); if (index == 0x1) return 0; break;
        case 0x2: asm volatile(""); if (index == 0x2) return 0; break;
        case 0x3: asm volatile(""); if (index == 0x3) return 0; break;
        case 0x4: asm volatile(""); if (index == 0x4) return 0; break;
        case 0x5: asm volatile(""); if (index == 0x5) return 0; break;
        case 0x6: asm volatile(""); if (index == 0x6) return 0; break;
        case 0x7: asm volatile(""); if (index == 0x7) return 0; break;
    }
    return 1;
}
}

}