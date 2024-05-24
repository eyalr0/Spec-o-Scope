#include <stddef.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <execution>
#include <atomic>
#include "aes_sbox_sr.h"
#include "aes.h"
using namespace std;


constexpr int KEY_COUNT = 1000;
constexpr int TEST_COUNT = 5;
constexpr int WITNESS_THRESHOLD = 70;

int sum(bool* x, int count) {
    int sum = 0;
    for(int i = 0; i < count; i++) {
        sum += x[i];
    }
    return sum;
}

float pearson(bool* x, bool* y, int count){
    float x_ = ((float)sum(x, count))/count;
    float y_ = ((float)sum(y, count))/count;

    float cov = 0;
    float vx = 0;
    float vy = 0;
    for(int i = 0; i < count; i++) {
        float xi = x[i] - x_;
        float yi = y[i] - y_;
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


int main() {
    FILE* f = fopen("paper_expr/sbox_sr.txt", "r");

    auto key = new uint8_t[KEY_COUNT][16];
    auto ct = new uint8_t[KEY_COUNT][TEST_COUNT][16][64][16];
    auto measure = new bool[KEY_COUNT][TEST_COUNT][16][64];

    fprintf(stderr, "Loading file...\n");
    for(int k = 0; k < KEY_COUNT; k++) {
        if(k % 100 == 0)
            fprintf(stderr, "%d%%\n", k/10);
        fread_hex(key[k], f, 16);
        fseek(f, -32, SEEK_CUR);
        for(int t = 0; t < TEST_COUNT; t++) {
            for(int bi = 0; bi < 16; bi++) {
                for(int lsb = 0; lsb < 64; lsb++) {
                    fseek(f, 33, SEEK_CUR); // key,
                    fread_hex(ct[k][t][bi][lsb], f, 16);
                    fseek(f, 1, SEEK_CUR); // ,
                    int a1;
                    fscanf(f, "%d", &a1);
                    fseek(f, 1, SEEK_CUR); // ,
                    int a2;
                    fscanf(f, "%d", &a2);
                    fseek(f, 1, SEEK_CUR); // \n

                    int diff = (compute_true_sample(a2) - compute_true_sample(a1));
                    measure[k][t][bi][lsb] = diff >= WITNESS_THRESHOLD;
                }
            }
        }
    }
    fclose(f);

    fprintf(stderr, "Analyzing...\n");
    atomic_size_t correct_tests = 0;
    atomic_size_t correct_t_tests = 0;
    atomic_size_t fail_t_tests_thresh = 0;
    atomic_size_t fail_t_tests_many = 0;
    atomic_size_t correct_bytes = 0;
    atomic_size_t correct_tests3 = 0;
    atomic_size_t correct_tests5 = 0;
    atomic_size_t initial_witness = 0;
    constexpr float PEARSON_MULT = 1000;

    constexpr float PEARSON_THRESHOLD = 0.6;
    auto correct_pearson = new float[KEY_COUNT * TEST_COUNT * 16];
    atomic_size_t correct_pearson_idx = 0;
    auto incorrect_pearson = new float[KEY_COUNT * TEST_COUNT * 16];
    atomic_size_t incorrect_pearson_idx = 0;

    int key_idx[KEY_COUNT];
    for(int i = 0; i < KEY_COUNT; i++) {
        key_idx[i] = i;
    }
    atomic_size_t keys_started = 0;
    for_each(execution::par, key_idx, key_idx + KEY_COUNT, [&](int k) {
        bool pred[64];
        AES_KEY aeskey;


        int ks = (++keys_started);
        if(ks % 10 == 0)
            fprintf(stderr, "%d%%\n", ks/10);
        AES_set_decrypt_key_sbox(key[k], 128, &aeskey);
        uint8_t* key0 = (uint8_t*) aeskey.rd_key;

        int correct_byte3[16] = {};
        int correct_byte5[16] = {};
        for(int t = 0; t < TEST_COUNT; t++) {
            bool witness = first_access_round_sbox(&aeskey, ct[k][t][0][0], 0) >= 2;
            if(witness) initial_witness++;

            bool correct = true;
            int num_correct = 0;
            int num_t_correct = 0;
            bool t_class_correct = true;
            for(int bi = 0; bi < 16; bi++) {
                uint8_t key_msb = key0[bi]&0xC0;
				uint8_t true_lsb = key0[bi]&0x3F;

                float max_pc = 0;
                uint8_t max_lsb = 0;
                for(int st = 0; st < 256; st++) {
                    uint8_t st0 = (st >> 0) & 0x3;
                    uint8_t st1 = (st >> 2) & 0x3;
                    uint8_t st2 = (st >> 4) & 0x3;
                    uint8_t st3 = (st >> 6) & 0x3;
                    for(int lsb = 0; lsb < 64; lsb++) {
                        uint8_t key_guess = key_msb | lsb;
                        for(int j = 0; j < 64; j++) {
                            uint8_t p0 = key_guess ^ ct[k][t][bi][j][bi];
                            // printf("lsb=%02x st=%02x j=%d %02x\n", lsb, st, j, p0);
                            uint8_t a0 = PRECOMPUTED_TABLE[st0][0][p0];
                            uint8_t a1 = PRECOMPUTED_TABLE[st1][1][p0];
                            uint8_t a2 = PRECOMPUTED_TABLE[st2][2][p0];
                            uint8_t a3 = PRECOMPUTED_TABLE[st3][3][p0];
                            pred[j] = (a0 == 0) || (a1 == 0) || (a2 == 0) || (a3 == 0);
                        }

                        float pc = fabs(pearson(measure[k][t][bi], pred, 64));
                        if(pc > max_pc) {
                            max_pc = pc;
                            max_lsb = lsb;
                        }
                    }
                }

                if(true_lsb != max_lsb) {
                    correct = false;
                    incorrect_pearson[incorrect_pearson_idx++] = max_pc;

                    if(max_pc >= PEARSON_THRESHOLD) {
                        t_class_correct = false;
                    }
                } else {
                    correct_pearson[correct_pearson_idx++] = max_pc;
                    if(max_pc >= PEARSON_THRESHOLD) {
                        num_t_correct += 1;
                    }

                    num_correct += 1;
                    if(t < 3)
                        correct_byte3[bi] += 1;
                    correct_byte5[bi] += 1;
                }
            }

            if(correct) correct_tests += 1;
            if(t_class_correct && num_t_correct >= 12) correct_t_tests += 1;
            if(!t_class_correct) fail_t_tests_thresh += 1;
            if(num_t_correct < 12) fail_t_tests_many += 1;
            correct_bytes += num_correct;
        }
        bool correct3 = true;
        bool correct5 = true;
        for(int i = 0; i < 16; i++) {
            if(correct_byte3[i] <= 1) correct3 = false;
            if(correct_byte5[i] <= 2) correct5 = false;
        }
        if(correct3) correct_tests3 += 1;
        if(correct5) correct_tests5 += 1;
    });

    printf("Correct: %.2f%% [%d/%d]\n", (100.0*correct_tests)/(KEY_COUNT * TEST_COUNT),
        (int)correct_tests, KEY_COUNT * TEST_COUNT);
    printf("Correct Thresh: %.2f%% [%d/%d]\n", (100.0*correct_t_tests)/(KEY_COUNT * TEST_COUNT),
        (int)correct_t_tests, KEY_COUNT * TEST_COUNT);
    printf("\tFail Above Thresh: %.2f%% [%d/%d]\n", (100.0*fail_t_tests_thresh)/(KEY_COUNT * TEST_COUNT),
        (int)fail_t_tests_thresh, KEY_COUNT * TEST_COUNT);
    printf("\tFail Many Incorrect: %.2f%% [%d/%d]\n", (100.0*fail_t_tests_many)/(KEY_COUNT * TEST_COUNT),
        (int)fail_t_tests_many, KEY_COUNT * TEST_COUNT);
    size_t not_witness = KEY_COUNT * TEST_COUNT - initial_witness;
    printf("\tFail Not Witness: %.2f%% [%d/%d]\n", (100.0*not_witness)/(KEY_COUNT * TEST_COUNT),
        (int)not_witness, KEY_COUNT * TEST_COUNT);
    printf("Correct Bytes: %.2f%% [%d/%d]\n", (100.0*correct_bytes)/(KEY_COUNT * TEST_COUNT * 16),
        (int)correct_bytes, KEY_COUNT * TEST_COUNT * 16);
    // printf("Pearson correct: %.3f Pearson incorrect: %.3f\n",
    //     pearson_correct_mean/(correct_bytes * PEARSON_MULT),
    //     pearson_incorrect_mean/((KEY_COUNT * TEST_COUNT * 16 - correct_bytes) * PEARSON_MULT));
    // printf("Correct3: %.2f%% [%d/%d]\n", (100.0*correct_tests3)/KEY_COUNT, (int)correct_tests3, KEY_COUNT);
    // printf("Correct5: %.2f%% [%d/%d]\n", (100.0*correct_tests5)/KEY_COUNT, (int)correct_tests5, KEY_COUNT);

    {
        FILE* f = fopen("paper_expr/pearson_correct.txt", "w");
        for(int i = 0; i < correct_pearson_idx; i++) {
            fprintf(f, "%f\n", correct_pearson[i]);
        }
        fclose(f);
    }
    {
        FILE* f = fopen("paper_expr/pearson_incorrect.txt", "w");
        for(int i = 0; i < incorrect_pearson_idx; i++) {
            fprintf(f, "%f\n", incorrect_pearson[i]);
        }
        fclose(f);
    }

    return 0;
}