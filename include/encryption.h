#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include <stddef.h>
// XOR encryption key - can be randomly generated
extern unsigned char xor_key[];

// Function to get XOR key size
size_t get_xor_key_size(void);

// Function to XOR encrypt/decrypt data
void xor_data(unsigned char* data, unsigned int data_len, unsigned char* key, unsigned int key_len);

#endif // ENCRYPTION_H 