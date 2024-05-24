#include "gates/classic_bt_gates.h"
#include "gates/gates_common.h"
#include <math.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>

namespace gates {

// NOTE: The input must resolve to 0!
uint64_t RetFastSampleInv2::gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const {
    asm volatile (
        "jmp start%=\n"

        "ret_misprediction%=:\n"
        "lea rax, [rip+end%=]\n"
        "add rax, %[trash]\n"
        "mov [rsp], rax\n"
        "ret\n"

        "start%=:\n"

        "xorpd xmm0, xmm0\n"

        "mov rax, qword ptr [%[bank]]\n"        // input = bank->inputs[0]
        "xor %[trash], rax\n"                   // trash ^= input

        "xor rcx, rcx\n"
        "cmp %[trash], 0xBADF00D\n"
        "sete cl\n"
        "mov r8, qword ptr [rax + rcx]\n"       // r8 = *(input + (trash == 0xBADF00D))
        "mov r9, qword ptr [rax + r8]\n"        // r9 = *(input + r8)
        "mov r10, qword ptr [rax + r9]\n"       // r10 = *(input + r9)
        "mov r11, qword ptr [rax + r10]\n"      // r11 = *(input + r10)
        "mov r12, qword ptr [rax + r11]\n"      // r12 = *(input + r11)
        "mov r13, qword ptr [rax + r12]\n"      // r13 = *(input + r12)
        "mov r14, qword ptr [rax + r13]\n"      // r14 = *(input + r13)
        "mov r15, qword ptr [rax + r14]\n"      // r15 = *(input + r14)
        "mov rbp, qword ptr [rax + r15]\n"      // rbp = *(input + r15)
        "mov rbx, qword ptr [rax + rbp]\n"      // rbx = *(input + rbp)
        "mov %[trash], rbx\n"

        "call ret_misprediction%=\n"

        "cvtsi2sd xmm1, rdx\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "xor edx, edx\n"
        "ucomisd xmm0, xmm1\n"
        "sete dl\n"

        "mov rcx, qword ptr [%[bank] + 128]\n"  // marker = bank->outputs[0]
        "mov rcx, qword ptr [rcx + rdx]\n"      // READ(marker + rdx)

        "mov rcx, qword ptr [%[bank] + 136]\n"  // output1 = bank->outputs[1]
        "cvtsi2sd xmm1, r8\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "xor edx, edx\n"
        "ucomisd xmm0, xmm1\n"
        "sete dl\n"
        "mov rcx, qword ptr [rcx + rdx]\n"       // READ(output1 + r8)

        "mov rcx, qword ptr [%[bank] + 144]\n"  // output2 = bank->outputs[2]
        "cvtsi2sd xmm1, r9\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "xor edx, edx\n"
        "ucomisd xmm0, xmm1\n"
        "sete dl\n"
        "mov rcx, qword ptr [rcx + rdx]\n"       // READ(output2 + r9)

        "mov rcx, qword ptr [%[bank] + 152]\n"  // output3 = bank->outputs[3]
        "cvtsi2sd xmm1, r10\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "xor edx, edx\n"
        "ucomisd xmm0, xmm1\n"
        "sete dl\n"
        "mov rcx, qword ptr [rcx + rdx]\n"      // READ(output3 + r10)

        "mov rcx, qword ptr [%[bank] + 160]\n"  // output4 = bank->outputs[4]
        "popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n"
        "mov rcx, qword ptr [rcx + r11]\n"      // READ(output4 + r11)

        "mov rcx, qword ptr [%[bank] + 168]\n"  // output5 = bank->outputs[5]
        "popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n"
        "mov rcx, qword ptr [rcx + r12]\n"      // READ(output5 + r12)

        "mov rcx, qword ptr [%[bank] + 176]\n"  // output6 = bank->outputs[6]
        "popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n"
        "mov rcx, qword ptr [rcx + r13]\n"      // READ(output6 + r13)

        "mov rcx, qword ptr [%[bank] + 184]\n"  // output7 = bank->outputs[7]
        "popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n"
        "mov rcx, qword ptr [rcx + r14]\n"      // READ(output7 + r14)

        "mov rcx, qword ptr [%[bank] + 192]\n"  // output8 = bank->outputs[8]
        "popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n"
        "mov rcx, qword ptr [rcx + r15]\n"      // READ(output8 + r15)

        "mov rcx, qword ptr [%[bank] + 200]\n"  // output9 = bank->outputs[9]
        "add rcx, rdx\n"                        // output9 += rdx
        "popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n"
        "mov rcx, qword ptr [rcx + rbp]\n"      // READ(output9 + rbp)

        
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"


        "end%=:\n"

        : [trash] "+D"(trash), [wet_run] "+d"(wet_run) // D: RDI, d: RDX
        : "i"(temporal_branch_misprediction), [bank] "S"(bank)  // S: RSI
        : "rax", "rbx", "rcx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "xmm0", "xmm1", "memory");

    return trash;
}

uint64_t FSI_BT::gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const {
    asm volatile (
        "xorpd xmm0, xmm0\n"

        "mov rax, qword ptr [%[bank]]\n"        // input = bank->inputs[0]
        "xor %[trash], rax\n"                   // trash ^= input

        "mov rcx, 100\n"
        "obh_loop%=:\n"                         // overwrite_branch_history();
        "dec rcx\n"
        "jnz obh_loop%=\n"                  
 
 
        "xor ecx, ecx\n"                         
        "cmp %[trash], 0xBADF00D\n" 
        "sete cl\n" 
        "mov r8, qword ptr [rax + rcx]\n"       // r8 = *(input + (trash == 0xBADF00D))
        "mov %[trash], r8\n"

        "cmp %[trash], %q[wet_run]\n"
        "jne end%=\n"
        "test %[wet_run], %[wet_run]\n"
        "jz end%=\n"
        
        "cvtsi2sd xmm1, rdx\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "xor edx, edx\n" 
        "ucomisd xmm0, xmm1\n"
        "sete dl\n"

        "mov rcx, qword ptr [%[bank] + 128]\n"  // marker = bank->outputs[0]
        "mov rcx, qword ptr [rcx + rdx]\n"      // READ(marker + rdx)
    

        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"   \

        "end%=:\n"
    
        : [trash] "+D"(trash), [wet_run] "+d"(wet_run)
        : "i"(temporal_branch_misprediction), [bank] "S"(bank)
        : "rax", "rbx", "rcx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "xmm0", "xmm1", "memory");

    return trash;
}

uint64_t FSI_CBT::gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const {
    asm volatile (
        "xorpd xmm0, xmm0\n"

        "mov rax, qword ptr [%[bank]]\n"        // input = bank->inputs[0]
        "xor %[trash], rax\n"                   // trash ^= input

        "mov rcx, 30\n"
        "obh_loop%=:\n"                         // overwrite_branch_history();
        "dec rcx\n"
        "jnz obh_loop%=\n"                  
 
 
        "xor ecx, ecx\n"                         
        "cmp %[trash], 0xBADF00D\n" 
        "sete cl\n" 
        "mov r8, qword ptr [rax + rcx]\n"       // r8 = *(input + (trash == 0xBADF00D))
        
        "mov rdi, r8\n"
        "call %P2\n"        // temporal_branch_misprediction()
        "test rax, rax\n"   // NOTE: temporal_branch_misprediction uses rax, rcx, rdi, rdx
        "jz end%=\n"
        
        "xor edx, edx\n"
        "cmp %[bank], 0xBADF00D\n"
        "sete dl\n"
        "cvtsi2sd xmm1, rdx\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "xor edx, edx\n"
        "ucomisd xmm0, xmm1\n"
        "sete dl\n"

        "mov rcx, qword ptr [%[bank] + 128]\n"  // marker = bank->outputs[0]
        "mov rcx, qword ptr [rcx + rdx]\n"      // READ(marker + rdx)
    

        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"   \

        "end%=:\n"
    
        : [trash] "+D"(trash), [wet_run] "+d"(wet_run)
        : "i"(temporal_branch_misprediction), [bank] "S"(bank)
        : "rax", "rbx", "rcx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "xmm0", "xmm1", "memory");

    return trash;
}

uint64_t FSI_RET::gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const {
    asm volatile (
        "jmp start%=\n"

        "ret_misprediction%=:\n"
        "lea rax, [rip+end%=]\n"
        "add rax, %[trash]\n"
        "mov [rsp], rax\n"
        "ret\n"

        "start%=:\n"

        "xorpd xmm0, xmm0\n"

        "mov rax, qword ptr [%[bank]]\n"        // input = bank->inputs[0]
        "xor %[trash], rax\n"                   // trash ^= input
 
        "xor ecx, ecx\n"                         
        "cmp %[trash], 0xBADF00D\n" 
        "sete cl\n" 
        "mov r8, qword ptr [rax + rcx]\n"       // r8 = *(input + (trash == 0xBADF00D))
        
        "mov %[trash], r8\n"

        "call ret_misprediction%=\n"
        
        "cvtsi2sd xmm1, rdx\n"
        "sqrtsd xmm1, xmm1\n"
        "sqrtsd xmm1, xmm1\n"
        "xor edx, edx\n"
        "ucomisd xmm0, xmm1\n"
        "sete dl\n"

        "mov rcx, qword ptr [%[bank] + 128]\n"  // marker = bank->outputs[0]
        "mov rcx, qword ptr [rcx + rdx]\n"      // READ(marker + rdx)
    

        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"   \

        "end%=:\n"
    
        : [trash] "+D"(trash), [wet_run] "+d"(wet_run)
        : "i"(temporal_branch_misprediction), [bank] "S"(bank)
        : "rax", "rbx", "rcx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "xmm0", "xmm1", "memory");

    return trash;
}



#define RFSI2_SAMPLE_IMPL_PRELDUE(x) \
uint64_t RetFastSampleInv2_##x::gate_implementation(int wet_run, GateBank *bank, uint64_t trash) const {  \
    asm volatile (  \
        "jmp start%=\n" \
    \
        "ret_misprediction%=:\n"    \
        "lea rax, [rip+end%=]\n"    \
        "add rax, %[trash]\n"   \
        "mov [rsp], rax\n"  \
        "ret\n" \
    \
        "start%=:\n"    \
    \
        "xorpd xmm0, xmm0\n"    \
    \
        "mov rax, qword ptr [%[bank]]\n"            \
        "xor %[trash], rax\n"                       \
    \
    \
        "xor rcx, rcx\n"                            \
        "cmp %[trash], 0xBADF00D\n" \
        "sete cl\n" \
        "mov r8, qword ptr [rax + rcx]\n"

#define RFSI2_SAMPLE_IMPL_POSTLUDE \
        "call ret_misprediction%=\n"    \
    \
            \
        "cvtsi2sd xmm1, rdx\n"  \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "xor edx, edx\n"    \
        "ucomisd xmm0, xmm1\n"  \
        "sete dl\n" \
    \
        "mov rcx, qword ptr [%[bank] + 128]\n"      \
        "mov rcx, qword ptr [rcx + rdx]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 136]\n"      \
            \
        "cvtsi2sd xmm1, r8\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "xor edx, edx\n"    \
        "ucomisd xmm0, xmm1\n"  \
        "sete dl\n" \
            \
        "mov rcx, qword ptr [rcx + rdx]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 144]\n"      \
            \
        "cvtsi2sd xmm1, r9\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "xor edx, edx\n"    \
        "ucomisd xmm0, xmm1\n"  \
        "sete dl\n" \
            \
        "mov rcx, qword ptr [rcx + rdx]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 152]\n"      \
            \
        "cvtsi2sd xmm1, r10\n"  \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "sqrtsd xmm1, xmm1\n"   \
        "xor edx, edx\n"    \
        "ucomisd xmm0, xmm1\n"  \
        "sete dl\n" \
        "mov rcx, qword ptr [rcx + rdx]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 160]\n"      \
            \
            \
        "popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n"   \
        "mov rcx, qword ptr [rcx + r11]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 168]\n"      \
    \
            \
        "popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n" \
        "mov rcx, qword ptr [rcx + r12]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 176]\n"      \
    \
            \
        "popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n" \
        "mov rcx, qword ptr [rcx + r13]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 184]\n"      \
            \
        "popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n" \
        "mov rcx, qword ptr [rcx + r14]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 192]\n"      \
            \
        "popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n" \
        "mov rcx, qword ptr [rcx + r15]\n"          \
    \
        "mov rcx, qword ptr [%[bank] + 200]\n"      \
        "add rcx, rdx\n"                            \
        "popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n popcnt rbp, rbp\n"   \
        "mov rcx, qword ptr [rcx + rbp]\n"          \
    \
    \
            \
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"   \
    \
    \
        "end%=:\n"  \
    \
        : [trash] "+D"(trash), [wet_run] "+d"(wet_run)  \
        : "i"(temporal_branch_misprediction), [bank] "S"(bank)      \
        : "rax", "rbx", "rcx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "xmm0", "xmm1", "memory");  \
    \
    return trash;   \
}

#define RFSI2_SAMPLE_IMPL_POSTLUDE2 \
    \
    \
            \
        "nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n nop\n"   \
    \
    \
        "end%=:\n"  \
    \
        : [trash] "+D"(trash), [wet_run] "+d"(wet_run)  \
        : "i"(temporal_branch_misprediction), [bank] "S"(bank)      \
        : "rax", "rbx", "rcx", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "xmm0", "xmm1", "memory");  \
    \
    return trash;   \
}




RFSI2_SAMPLE_IMPL_PRELDUE(1)
    "mov %[trash], r8\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(2)
    "mov r9, qword ptr [rax + r8]\n"
    "mov %[trash], r9\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(3)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov %[trash], r10\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 144]\n"      \
        \
    "cvtsi2sd xmm1, r9\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(4)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov r11, qword ptr [rax + r10]\n"
    "mov %[trash], r11\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 144]\n"      \
        \
    "cvtsi2sd xmm1, r9\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 152]\n"      \
        \
    "cvtsi2sd xmm1, r10\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(5)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov r11, qword ptr [rax + r10]\n"
    "mov r12, qword ptr [rax + r11]\n"
    "mov %[trash], r12\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 144]\n"      \
        \
    "cvtsi2sd xmm1, r9\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 152]\n"      \
        \
    "cvtsi2sd xmm1, r10\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 160]\n"      \
        \
        \
    "popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n"   \
    "mov rcx, qword ptr [rcx + r11]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(6)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov r11, qword ptr [rax + r10]\n"
    "mov r12, qword ptr [rax + r11]\n"
    "mov r13, qword ptr [rax + r12]\n"
    "mov %[trash], r13\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 144]\n"      \
        \
    "cvtsi2sd xmm1, r9\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 152]\n"      \
        \
    "cvtsi2sd xmm1, r10\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 160]\n"      \
        \
        \
    "popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n"   \
    "mov rcx, qword ptr [rcx + r11]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 168]\n"      \
\
        \
    "popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n" \
    "mov rcx, qword ptr [rcx + r12]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(7)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov r11, qword ptr [rax + r10]\n"
    "mov r12, qword ptr [rax + r11]\n"
    "mov r13, qword ptr [rax + r12]\n"
    "mov r14, qword ptr [rax + r13]\n"
    "mov %[trash], r14\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 144]\n"      \
        \
    "cvtsi2sd xmm1, r9\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 152]\n"      \
        \
    "cvtsi2sd xmm1, r10\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 160]\n"      \
        \
        \
    "popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n"   \
    "mov rcx, qword ptr [rcx + r11]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 168]\n"      \
\
        \
    "popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n" \
    "mov rcx, qword ptr [rcx + r12]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 176]\n"      \
\
        \
    "popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n" \
    "mov rcx, qword ptr [rcx + r13]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(8)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov r11, qword ptr [rax + r10]\n"
    "mov r12, qword ptr [rax + r11]\n"
    "mov r13, qword ptr [rax + r12]\n"
    "mov r14, qword ptr [rax + r13]\n"
    "mov r15, qword ptr [rax + r14]\n"
    "mov %[trash], r15\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 144]\n"      \
        \
    "cvtsi2sd xmm1, r9\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 152]\n"      \
        \
    "cvtsi2sd xmm1, r10\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 160]\n"      \
        \
        \
    "popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n"   \
    "mov rcx, qword ptr [rcx + r11]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 168]\n"      \
\
        \
    "popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n" \
    "mov rcx, qword ptr [rcx + r12]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 176]\n"      \
\
        \
    "popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n" \
    "mov rcx, qword ptr [rcx + r13]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 184]\n"      \
        \
    "popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n" \
    "mov rcx, qword ptr [rcx + r14]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(9)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov r11, qword ptr [rax + r10]\n"
    "mov r12, qword ptr [rax + r11]\n"
    "mov r13, qword ptr [rax + r12]\n"
    "mov r14, qword ptr [rax + r13]\n"
    "mov r15, qword ptr [rax + r14]\n"
    "mov rbp, qword ptr [rax + r15]\n"
    "mov %[trash], rbp\n"
    "call ret_misprediction%=\n"    \
\
        \
    "cvtsi2sd xmm1, rdx\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
\
    "mov rcx, qword ptr [%[bank] + 128]\n"      \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 136]\n"      \
        \
    "cvtsi2sd xmm1, r8\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 144]\n"      \
        \
    "cvtsi2sd xmm1, r9\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
        \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 152]\n"      \
        \
    "cvtsi2sd xmm1, r10\n"  \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "sqrtsd xmm1, xmm1\n"   \
    "xor edx, edx\n"    \
    "ucomisd xmm0, xmm1\n"  \
    "sete dl\n" \
    "mov rcx, qword ptr [rcx + rdx]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 160]\n"      \
        \
        \
    "popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n popcnt r11, r11\n"   \
    "mov rcx, qword ptr [rcx + r11]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 168]\n"      \
\
        \
    "popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n popcnt r12, r12\n" \
    "mov rcx, qword ptr [rcx + r12]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 176]\n"      \
\
        \
    "popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n popcnt r13, r13\n" \
    "mov rcx, qword ptr [rcx + r13]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 184]\n"      \
        \
    "popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n popcnt r14, r14\n" \
    "mov rcx, qword ptr [rcx + r14]\n"          \
\
    "mov rcx, qword ptr [%[bank] + 192]\n"      \
        \
    "popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n popcnt r15, r15\n" \
    "mov rcx, qword ptr [rcx + r15]\n"          \
RFSI2_SAMPLE_IMPL_POSTLUDE2

RFSI2_SAMPLE_IMPL_PRELDUE(10)
    "mov r9, qword ptr [rax + r8]\n"
    "mov r10, qword ptr [rax + r9]\n"
    "mov r11, qword ptr [rax + r10]\n"
    "mov r12, qword ptr [rax + r11]\n"
    "mov r13, qword ptr [rax + r12]\n"
    "mov r14, qword ptr [rax + r13]\n"
    "mov r15, qword ptr [rax + r14]\n"
    "mov rbp, qword ptr [rax + r15]\n"
    "mov rbx, qword ptr [rax + rbp]\n"
    "mov %[trash], rbx\n"
RFSI2_SAMPLE_IMPL_POSTLUDE



Gate* fsi_bt = new FSI_BT();
Gate* fsi_cbt = new FSI_CBT();
Gate* fsi_ret = new FSI_RET();
Gate* ret_inv_window_gate = new RetFastSampleInv2();
Gate* ret_inv_window_gate_single = new RetFastSampleInv2_1();
Gate* ret_inv_window_gate_single_samples[10] = {
    new RetFastSampleInv2_1(),
    new RetFastSampleInv2_2(),
    new RetFastSampleInv2_3(),
    new RetFastSampleInv2_4(),
    new RetFastSampleInv2_5(),
    new RetFastSampleInv2_6(),
    new RetFastSampleInv2_7(),
    new RetFastSampleInv2_8(),
    new RetFastSampleInv2_9(),
    new RetFastSampleInv2_10(),
};

}