#pragma once
#include "util.h"
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <vector>

namespace gates {

#define MAX_INPUTS (16)
#define MAX_OUTPUTS (16)

enum GateType {
    NAND,
    NOR,
    AND,
    OR,
    OTHER,
};

struct GateBank {
    uintptr_t inputs[MAX_INPUTS];
    uintptr_t outputs[MAX_OUTPUTS];
};

struct GateResults {
    address_state inputs[MAX_INPUTS];
    address_state outputs[MAX_OUTPUTS];
};

/* The goal of these functions is to sample inputs such that the output distribution is uniform */
void and_sample_inputs(GateResults &results, int fan_in, int fan_out);
void or_sample_inputs(GateResults &results, int fan_in, int fan_out);

void nand_sample_inputs(GateResults &results, int fan_in, int fan_out);
void nor_sample_inputs(GateResults &results, int fan_in, int fan_out);

/* These functions simulate their gates operation */
void and_simulation(GateResults &results, int fan_in, int fan_out);
void or_simulation(GateResults &results, int fan_in, int fan_out);

void nand_simulation(GateResults &results, int fan_in, int fan_out);
void nor_simulation(GateResults &results, int fan_in, int fan_out);

class Gate {
public:
    virtual uint64_t gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const = 0;
    virtual const char *gate_type() const = 0;
    virtual void print_gate_name() const = 0;

    virtual uint64_t apply(GateBank *bank, uint64_t trash) const = 0;

    virtual void sample_input_states(GateResults &results) const = 0;
    virtual void simulate(GateResults &results) const = 0;

    virtual bool is_negating() const = 0;

    const int m_fan_in;
    const int m_fan_out;

protected:
    constexpr Gate(int fan_in, int fan_out)
        : m_fan_in(fan_in)
        , m_fan_out(fan_out) { }
};

template<GateType type, bool requires_dry_runs>
class GateBase : public Gate {
public:
    virtual uint64_t gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const = 0;

    virtual const char *gate_type() const = 0;

    virtual void print_gate_name() const final {
        printf("%s %dto%d", gate_type(), m_fan_in, m_fan_out);
    }

    uint64_t apply(GateBank *bank, uint64_t trash) const final {
        static uintptr_t __attribute__((aligned(128))) fake_zero = 0;
        static GateBank __attribute__((aligned(128))) fake = {
            .inputs = { (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero },
            .outputs = { (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero, (uintptr_t)&fake_zero }
        };
        if (requires_dry_runs) {
            trash = gate_implementation(0, &fake, trash);
            trash = gate_implementation(0, &fake, trash);
        }
        trash = gate_implementation(1, bank, trash);
        return trash;
    }

    void sample_input_states(GateResults &results) const final {
        switch (type) {
        case NAND: nand_sample_inputs(results, m_fan_in, m_fan_out); break;
        case NOR: nor_sample_inputs(results, m_fan_in, m_fan_out); break;
        case AND: and_sample_inputs(results, m_fan_in, m_fan_out); break;
        case OR: or_sample_inputs(results, m_fan_in, m_fan_out); break;
        case OTHER: assert(!"Not implemented"); break;
        }
    }

    void simulate(GateResults &results) const final {
        switch (type) {
        case NAND: nand_simulation(results, m_fan_in, m_fan_out); break;
        case NOR: nor_simulation(results, m_fan_in, m_fan_out); break;
        case AND: and_simulation(results, m_fan_in, m_fan_out); break;
        case OR: or_simulation(results, m_fan_in, m_fan_out); break;
        case OTHER: assert(!"Not implemented"); break;
        }
    }

    bool is_negating() const final {
        return type == NAND || type == NOR;
    }

protected:
    constexpr GateBase(int fan_in, int fan_out)
        : Gate(fan_in, fan_out) { }
};

}