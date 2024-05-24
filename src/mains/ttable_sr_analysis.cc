#include <stddef.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <execution>
#include <atomic>
#include <cassert>
#include "aes.h"
using namespace std;


constexpr int KEY_COUNT = 1000;
constexpr int TEST_COUNT = 5000;

template<class T>
int sum(T* x, int count) {
    int sum = 0;
    for(int i = 0; i < count; i++) {
        sum += x[i];
    }
    return sum;
}

float pearson(bool* x, int8_t* y, int count){
    float x_ = ((float)sum(x, count))/count;
    float y_ = ((float)sum(y, count))/count;

    float cov = 0;
    float vx = 0;
    float vy = 0;
    for(int i = 0; i < count; i++) {
        float xi = ((float)x[i]) - x_;
        float yi = ((float)y[i]) - y_;
        cov += xi * yi;
        vx += xi * xi;
        vy += yi * yi;
    }
    if(vx == 0 || vy == 0)
        return 0;
    return cov/sqrtf(vx * vy);
}
float pearson_weird(bool* x, int8_t* y, int count, int8_t thresh=20){
    int sx = 0;
    int sy = 0;
    int wc = 0;
    for(int i = 0; i < count; i++) {
        int8_t v = y[i];
        if(v < thresh) continue;
        sx += x[i];
        sy += v;
        wc++;
    }
    float x_ = ((float)sx)/wc;
    float y_ = ((float)sy)/wc;

    float cov = 0;
    float vx = 0;
    float vy = 0;
    for(int i = 0; i < count; i++) {
        int8_t v = y[i];
        if(v < thresh) continue;
        float xi = ((float)x[i]) - x_;
        float yi = ((float)v) - y_;
        cov += xi * yi;
        vx += xi * xi;
        vy += yi * yi;
    }
    if(vx == 0 || vy == 0)
        return 0;
    return cov/sqrtf(vx * vy);
}

void fread_hex(uint8_t* target, FILE* f, int length) {
    unsigned int x;
    for(int i = 0; i < length; i++){
        fscanf(f, "%02x", &x);
        target[i] = x;
    }
}

void print_hex(uint8_t* target, int length) {
    for(int i = 0; i < length; i++){
        printf("%02x", target[i]);
    }
}

static int __always_inline compute_true_sample(int s) {
	return (s % 10) + ((s / 10) * 20);
}

static uint8_t get_acc_round_opt(uint8_t* rk, uint8_t* ct, uint8_t g0, uint8_t g7, uint8_t g10, uint8_t g13, uint8_t gf) {
    uint8_t k0 = (rk[0] & 0xF0) | g0;
    uint8_t k7 = (rk[7] & 0xF0) | g7;
    uint8_t k10 = (rk[10] & 0xF0) | g10;
    uint8_t k13 = (rk[13] & 0xF0) | g13;
    // printf("idx:[%x,%x,%x,%x]\n", k0^ct[0], k13^ct[13], k10^ct[10], k7^ct[7]);
    // printf("Tidx:[%x,%x,%x,%x]\n", Td0[k0^ct[0]], Td1[k13^ct[13]], Td2[k10^ct[10]], Td3[k7^ct[7]]);
    uint32_t t0 = Td0[k0 ^ ct[0]] ^ Td1[k13 ^ ct[13]] ^ Td2[k10 ^ ct[10]] ^ Td3[k7 ^ ct[7]];
    uint8_t acc = ((t0 >> 20) & 0xF) ^ gf;
    // printf("g:[%x,%x,%x,%x,%x] t0=%x acc=%x\n", g0, g7, g10, g13, gf, t0, acc);
    return acc;
}
static void truth_test(AES_KEY* key, uint8_t* ct) {
    uint8_t output[16];
    uint8_t T0_acc[40];
    uint8_t T1_acc[40];
    uint8_t T2_acc[40];
    uint8_t T3_acc[40];
    // printf("\n");
    // printf("\n");


    AES_decrypt_debug(ct, output, key, T0_acc, T1_acc, T2_acc, T3_acc);
    uint8_t tr = T1_acc[5] >> 4;
    uint8_t rk0[16];
    for(int i = 0; i < 4; i++) {
        rk0[4*i + 0] = (((uint32_t) key->rd_key[i]) >> 24) & 0xFF;
        rk0[4*i + 1] = (((uint32_t) key->rd_key[i]) >> 16) & 0xFF;
        rk0[4*i + 2] = (((uint32_t) key->rd_key[i]) >>  8) & 0xFF;
        rk0[4*i + 3] = (((uint32_t) key->rd_key[i]) >>  0) & 0xFF;
    }
    uint8_t rk1[16];
    for(int i = 0; i < 4; i++) {
        rk1[4*i + 0] = (((uint32_t) key->rd_key[4 + i]) >> 24) & 0xFF;
        rk1[4*i + 1] = (((uint32_t) key->rd_key[4 + i]) >> 16) & 0xFF;
        rk1[4*i + 2] = (((uint32_t) key->rd_key[4 + i]) >>  8) & 0xFF;
        rk1[4*i + 3] = (((uint32_t) key->rd_key[4 + i]) >>  0) & 0xFF;
    }
    uint8_t pred = get_acc_round_opt(rk0, ct, rk0[0]&0xF, rk0[7]&0xF, rk0[10]&0xF, rk0[13]&0xF, rk1[1]>>4);
    printf("%x == %x\n", tr, pred);
}

constexpr size_t BYTE_INDICES[] = {0, 7, 10, 13};
int main() {
    FILE* f = fopen("paper_expr/ttable_sr.txt", "r");

    auto key = new uint8_t[KEY_COUNT][16];
    auto ct = new uint8_t[KEY_COUNT][TEST_COUNT][16];
    auto measure = new int8_t[KEY_COUNT][TEST_COUNT];

    fprintf(stderr, "Loading file...\n");
    for(int k = 0; k < KEY_COUNT; k++) {
        if(k % 100 == 0)
            fprintf(stderr, "%d%%\n", k/10);
        fread_hex(key[k], f, 16);
        fseek(f, -32, SEEK_CUR);
        for(int t = 0; t < TEST_COUNT; t++) {
            fseek(f, 33, SEEK_CUR); // key,
            fread_hex(ct[k][t], f, 16);
            fseek(f, 1, SEEK_CUR); // ,
            int a1;
            fscanf(f, "%d", &a1);
            fseek(f, 1, SEEK_CUR); // ,
            int a2;
            fscanf(f, "%d", &a2);
            fseek(f, 1, SEEK_CUR); // \n

            int diff = (a2 - a1);
            assert(diff <= INT8_MAX && diff >= INT8_MIN);
            measure[k][t] = diff;
        }
    }
    fclose(f);

    fprintf(stderr, "Analyzing...\n");
    // atomic_size_t correct_tests = 0;
    // atomic_size_t correct_t_tests = 0;

    int needed[KEY_COUNT];
    int key_idx[KEY_COUNT];
    for(int i = 0; i < KEY_COUNT; i++) {
        key_idx[i] = i;
    }
    atomic_size_t keys_started = 0;
    for_each(execution::par, key_idx, key_idx + KEY_COUNT, [&](int k) {
        AES_KEY aeskey;

        int ks = (++keys_started);
        if(ks % 10 == 0)
            fprintf(stderr, "%d%%\n", ks/10);
        private_AES_set_decrypt_key(key[k], 128, &aeskey);
        uint8_t rk0[16];
        for(int i = 0; i < 4; i++) {
            rk0[4*i + 0] = (((uint32_t) aeskey.rd_key[i]) >> 24) & 0xFF;
            rk0[4*i + 1] = (((uint32_t) aeskey.rd_key[i]) >> 16) & 0xFF;
            rk0[4*i + 2] = (((uint32_t) aeskey.rd_key[i]) >>  8) & 0xFF;
            rk0[4*i + 3] = (((uint32_t) aeskey.rd_key[i]) >>  0) & 0xFF;
        }
        uint8_t rk1[16];
        for(int i = 0; i < 4; i++) {
            rk1[4*i + 0] = (((uint32_t) aeskey.rd_key[4 + i]) >> 24) & 0xFF;
            rk1[4*i + 1] = (((uint32_t) aeskey.rd_key[4 + i]) >> 16) & 0xFF;
            rk1[4*i + 2] = (((uint32_t) aeskey.rd_key[4 + i]) >>  8) & 0xFF;
            rk1[4*i + 3] = (((uint32_t) aeskey.rd_key[4 + i]) >>  0) & 0xFF;
        }

        uint32_t tg0 = rk0[0] & 0xF;
        uint32_t tg7 = rk0[7] & 0xF;
        uint32_t tg10 = rk0[10] & 0xF;
        uint32_t tg13 = rk0[13] & 0xF;
        uint32_t tgf = rk1[1] >> 4;

// #define BINARY_SEARCH
        bool access_vec[TEST_COUNT];
        float tpc = 0;
        int traces_needed = TEST_COUNT + 1;
#ifndef BINARY_SEARCH
        for(int traces = TEST_COUNT; traces >= 100; traces -= 100) {
#else
        int l = 1;
        int r = (TEST_COUNT/100)+1;
        while(l < r) {
            int m = (l + r)/2;
            int traces = m * 100;
#endif
            float max_pc = 0;
            uint32_t max_g0 = 0;
            uint32_t max_g7 = 0;
            uint32_t max_g10 = 0;
            uint32_t max_g13 = 0;
            for(uint32_t gs = 0; gs < (1 << 20); gs++) {
                uint8_t g0 = gs & 0xF;
                uint8_t g7 = (gs >> 4) & 0xF;
                uint8_t g10 = (gs >> 8) & 0xF;
                uint8_t g13 = (gs >> 12) & 0xF;
                uint8_t gf = (gs >> 16) & 0xF;
                
                for(int i = 0; i < traces; i++) {
                    access_vec[i] = get_acc_round_opt(rk0, ct[k][i], g0, g7, g10, g13, gf) == 0;
                }
                float pc = fabs(pearson_weird(access_vec, measure[k], traces));
                if(pc > max_pc) {
                    max_pc = pc;
                    max_g0 = g0;
                    max_g7 = g7;
                    max_g10 = g10;
                    max_g13 = g13;
                }
                if(g0 == tg0 && g7 == tg7 && g10 == tg10 && g13 == tg13 && gf == tgf) {
                    tpc = pc;
                }
            }
            // printf("%d\t[%x,%x,%x,%x](%.3f) [%x,%x,%x,%x](%.3f)\n", k, tg0, tg7, tg10, tg13, tpc, max_g0, max_g7, max_g10, max_g13, max_pc);
            if(tg0 == max_g0 && tg7 == max_g7 && tg10 == max_g10 && tg13 == max_g13) {
#ifndef BINARY_SEARCH
                traces_needed = traces;
            } else {
                break;
#else
                // A[m] >= t (~[A[m] < t])
                r = m;
            } else {
                l = m + 1;
#endif
            }
        }
#ifndef BINARY_SEARCH
        needed[k] = traces_needed;
#else
        needed[k] = l * 100;
#endif
    });

    {
        FILE* f = fopen("paper_expr/ttable_sr_traces.txt", "w");
        for(int i = 0; i < KEY_COUNT; i++) {
            fprintf(f, "%d\n", needed[i]);
        }
        fclose(f);
    }

    return 0;
}