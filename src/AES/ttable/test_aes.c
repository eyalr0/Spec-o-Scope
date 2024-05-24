#include "aes.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../aes_addons.c"

int main(int ac, char **av) {
    aes_t key, input, output;
    tobinary("99696f874385da79659bf0294f365347", key);
    AES_KEY aeskey;
    private_AES_set_decrypt_key(key, 128, &aeskey);
    printf("First round key: ");
    for(int i = 0; i < 4; i++) {
        for(int j = 0; j < 4; j++) {
            printf("%02x", (aeskey.rd_key[i] >> (24 - 8*j))&0xFF);
        }
    }
    printf("\n");

    // assert(ac == 2);

    // srand(time(NULL));

    // aes_t key, input, output;
    // tobinary("99696f874385da79659bf0294f365347", key);
    // AES_KEY aeskey;
    // private_AES_set_encrypt_key(key, 128, &aeskey);

    // uint8_t T0_acc[40];
    // uint8_t T1_acc[40];
    // uint8_t T2_acc[40];
    // uint8_t T3_acc[40];
    // int wanted_round = atoi(av[1]);

    // for(int i = 0; i < 1000000; i++)
    //     generate_example_pt(&aeskey, input, wanted_round, 1, 0x1);

    // AES_encrypt_debug(input, output, &aeskey, T0_acc, T1_acc, T2_acc, T3_acc);

    // {
    //     char* x = toString(input);
    //     printf("Plaintext: %s\n", x);
    //     free(x);
    // }

    // uint8_t* T_acc[] = { T0_acc, T1_acc, T2_acc, T3_acc };
    // for (int i = 0; i < 10; i++) {
    //     printf("Round %d\n", i);
    //     for (int j = 0; j < 4; j++) {
    //         printf("T%d: %02x %02x %02x %02x\n", j, T_acc[j][i * 4 + 0], T_acc[j][i * 4 + 1], T_acc[j][i * 4 + 2], T_acc[j][i * 4 + 3]);
    //     }
    // }

    // {
    //     char* x = toString(output);
    //     printf("Ciphertext: %s\n", x);
    //     free(x);
    // }
}
