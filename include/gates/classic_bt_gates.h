#pragma once
#include "gates/gates.h"

namespace gates {

class RetFastSampleInv2 : public GateBase<GateType::OTHER, false> {
public:
    constexpr RetFastSampleInv2() : GateBase(1, 10) {};

    uint64_t gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const final;

    const char *gate_type() const { return "ret fast sample inverted2"; }
};

#define RFSI2_SAMPLE_DEF(x) \
class RetFastSampleInv2_##x : public GateBase<GateType::OTHER, false> {   \
public: \
    constexpr RetFastSampleInv2_##x() : GateBase(1, x) {};    \
    \
    uint64_t gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const final;  \
    \
    const char *gate_type() const { return "ret fast sample inverted2 [" #x "]"; }   \
};
RFSI2_SAMPLE_DEF(1);
RFSI2_SAMPLE_DEF(2);
RFSI2_SAMPLE_DEF(3);
RFSI2_SAMPLE_DEF(4);
RFSI2_SAMPLE_DEF(5);
RFSI2_SAMPLE_DEF(6);
RFSI2_SAMPLE_DEF(7);
RFSI2_SAMPLE_DEF(8);
RFSI2_SAMPLE_DEF(9);
RFSI2_SAMPLE_DEF(10);


class FSI_BT : public GateBase<GateType::OTHER, false> {
public:
    constexpr FSI_BT() : GateBase(1, 1) {};

    uint64_t gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const final;

    const char *gate_type() const { return "FSI branch training"; }
};
class FSI_CBT : public GateBase<GateType::OTHER, false> {
public:
    constexpr FSI_CBT() : GateBase(1, 1) {};

    uint64_t gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const final;

    const char *gate_type() const { return "FSI counter branch training"; }
};
class FSI_RET : public GateBase<GateType::OTHER, false> {
public:
    constexpr FSI_RET() : GateBase(1, 1) {};

    uint64_t gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const final;

    const char *gate_type() const { return "FSI ret"; }
};



extern Gate* fsi_bt;
extern Gate* fsi_cbt;
extern Gate* fsi_ret;

extern Gate* ret_inv_window_gate;
extern Gate* ret_inv_window_gate_single;
extern Gate* ret_inv_window_gate_single_samples[10];

}