#include "aes.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

int main(int ac, char **av) {
    aes_t master_key;
    AES_KEY encrypt_key, decrypt_key;
    aes_t plaintext, ciphertext, message;
    srand(time(NULL));

    // Generate Master Key
    // toBinary("00112233445566778899aabbccddeeff", master_key);
    randaes(master_key);

    // Set encryption and decryption Key
    AES_set_encrypt_key_sbox(master_key, 128, &encrypt_key);
    AES_set_decrypt_key_sbox(master_key, 128, &decrypt_key);

    // Get a Plaintext
    // toBinary("00112233445566778899aabbccddeeff", plaintext);
    randaes(plaintext);
    printf("%s\n", aesToString(plaintext, 16));

    // Do Encryption
    AES_encrypt_sbox(plaintext, ciphertext, &encrypt_key);
    printf("%s\n", aesToString(ciphertext, 16));

    // Do Decryption
    AES_decrypt_sbox(ciphertext, message, &decrypt_key);
    printf("%s\n", aesToString(message, 16));

    // Check if code is correct
    for (int i = 0; i < 16; i++) {
        if (message[i] != plaintext[i]) {
            printf("Incorrect...\n");
            return 1;
        }
    }
    printf("Correct.\n");
}
