#include "../include/encryption.h"

// XOR encryption key - can be randomly generated
unsigned char xor_key[] = {0x41, 0x33, 0x55, 0x7A, 0x89, 0xAB, 0xCD, 0xEF};

// Function to get XOR key size
size_t get_xor_key_size(void) {
    return sizeof(xor_key);
}

// Function to XOR encrypt/decrypt data
void xor_data(unsigned char* data, unsigned int data_len, unsigned char* key, unsigned int key_len) {
    for (unsigned int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key[i % key_len];
    }
} 