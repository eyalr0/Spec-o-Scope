#include "aes.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AESSIZE 16

typedef uint8_t aes_t[AESSIZE];

void tobinary(const char* data, aes_t aes) {
    assert(strlen(data) == AESSIZE * 2);
    unsigned int x;
    for (int i = 0; i < AESSIZE; i++) {
        sscanf(data + i * 2, "%2x", &x);
        aes[i] = x;
    }
}

char* aesToString(uint8_t* aes, int size) {
    char buf[32 * 2 + 1];
    for (int i = 0; i < size; i++)
        sprintf(buf + i * 2, "%02x", aes[i]);
    return strdup(buf);
}

void randaes(aes_t aes) {
    for (int i = 0; i < AESSIZE; i++)
        aes[i] = rand() & 0xff;
}

void generate_example_pt(AES_KEY* aeskey, aes_t input, int round, int table, int line) {
    aes_t output;

    uint8_t T0_acc[40];
    uint8_t T1_acc[40];
    uint8_t T2_acc[40];
    uint8_t T3_acc[40];
    uint8_t* Ts[4] = {T0_acc, T1_acc, T2_acc, T3_acc};
    uint8_t* T_acc = Ts[table];
    while (1) {
        randaes(input);

        AES_encrypt_debug(input, output, aeskey, T0_acc, T1_acc, T2_acc, T3_acc);

        int good = 1;
        for (int i = 0; i < round; i++) {
            for (int j = 0; j < 4; j++) {
                if ((T_acc[i * 4 + j] & 0xF0) == (line << 4)) {
                    good = 0;
                }
            }
        }
        if (!good)
            continue;

        good = 0;
        for (int j = 0; j < 4; j++) {
            if ((T_acc[round * 4 + j] & 0xF0) == (line << 4)) {
                good = 1;
            }
        }

        if (good)
            break;
    }
}

int first_access_round_ttable(AES_KEY* aeskey, aes_t input, int table, int line) {
    aes_t output;
    uint8_t T0_acc[40];
    uint8_t T1_acc[40];
    uint8_t T2_acc[40];
    uint8_t T3_acc[40];
    uint8_t* Ts[4] = {T0_acc, T1_acc, T2_acc, T3_acc};
    uint8_t* T_acc = Ts[table];
    AES_decrypt_debug(input, output, aeskey, T0_acc, T1_acc, T2_acc, T3_acc);

    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 4; j++) {
            if ((T_acc[i * 4 + j] & 0xF0) == (line << 4)) {
                return i;
            }
        }
    }
    return 10;
}


void generate_example_ct_ttable(AES_KEY* aeskey, aes_t input, int round, int table, int line) {
    while (1) {
        randaes(input);

        if(first_access_round_ttable(aeskey, input, table, line) == round)
            return;
    }
}

void generate_example_ct_ttable_ge(AES_KEY* aeskey, aes_t input, int round, int table, int line) {
    while (1) {
        randaes(input);

        if(first_access_round_ttable(aeskey, input, table, line) >= round)
            return;
    }
}

void generate_example_ct_sbox(AES_KEY* aeskey, aes_t input, int round, int line) {
    while (1) {
        randaes(input);

        if(first_access_round_sbox(aeskey, input, line) == round)
            return;
    }
}

int first_access_round_sbox(AES_KEY* aeskey, aes_t input, int line) {
    aes_t output;
    uint8_t acc[160];
    AES_decrypt_sbox_debug(input, output, aeskey, acc);

    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 16; j++) {
            if ((acc[i * 16 + j] >> 6) == line) {
                return i;
            }
        }
    }
    return 10;
}

void generate_example_ct_sbox_ge(AES_KEY* aeskey, aes_t input, int round, int line) {
    while (1) {
        randaes(input);

        if(first_access_round_sbox(aeskey, input, line) >= round)
            return;
    }
}