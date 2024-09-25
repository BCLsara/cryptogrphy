//1.1 Define Block and Key Sizes
#include <stdio.h>

#define BLOCK_SIZE 8
#define KEY_SIZE 8

//1.2 Implement a Simple Substitution Box(S-box)
// S-Box for 4-bit input (4x4)
unsigned char s_box[16] = {
    0x9, 0x4, 0xA, 0xB, 
    0xD, 0x1, 0x8, 0x5, 
    0x6, 0x2, 0x0, 0x3, 
    0xC, 0xE, 0xF, 0x7  
};

// Function to substitute 4-bit input using S-Box
unsigned char substitute_4bit(unsigned char input) {
    return s_box[input & 0xF];  
}

//1.3 Implement a Simplified Permutation
// Permutation table: Bit positions after permutation
int perm_table[BLOCK_SIZE] = {1, 5, 2, 0, 3, 7, 4, 6};

// Function to permute 8-bit block
unsigned char permute(unsigned char block) {
    unsigned char permuted = 0;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        permuted |= ((block >> i) & 0x1) << perm_table[i];
    }
    return permuted;
}

//1.4 Implement a Basic Feistel Function 
// Feistel function: XOR with the key and substitute
unsigned char feistel(unsigned char half_block, unsigned char key) {
    return substitute_4bit(half_block ^ key);
}

//1.5 Combine Components for Encryption
// Single-round Feistel cipher encryption
unsigned char encrypt_block(unsigned char block, unsigned char key) {
    // Split block into left and right 4-bit halves
    unsigned char left = (block >> 4) & 0xF;
    unsigned char right = block & 0xF;

    // Apply Feistel function on right half with the key
    unsigned char new_left = right;
    unsigned char new_right = left ^ feistel(right, key);

    // Combine new left and right halves
    unsigned char combined = (new_left << 4) | new_right;

    // Permute the combined block
    return permute(combined);
}

int main() {
    unsigned char block = 0xAB;  
    unsigned char key = 0x3F;    

    unsigned char encrypted_block = encrypt_block(block, key);

    printf("Original block: 0x%02X\n", block);
    printf("Encrypted block: 0x%02X\n", encrypted_block);

    return 0;
}


//2.1 Electronic Codebook (ECB) Mode
#define BLOCK_SIZE 8

// Encryption using ECB mode
void ecb_encrypt(unsigned char* plaintext, unsigned char* ciphertext, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        ciphertext[i] = encrypt_block(plaintext[i], key);
    }
}

// Decryption using ECB mode
void ecb_decrypt(unsigned char* ciphertext, unsigned char* decryptedtext, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        decryptedtext[i] = encrypt_block(ciphertext[i], key);  
    }
}

//2.2 Cipher Block Chaining (CBC) Mode
// Encryption using CBC mode
void cbc_encrypt(unsigned char* plaintext, unsigned char* ciphertext, int len, unsigned char key, unsigned char iv) {
    unsigned char previous_block = iv;
    
    for (int i = 0; i < len; i++) {
        unsigned char input_block = plaintext[i] ^ previous_block; 
        ciphertext[i] = encrypt_block(input_block, key);
        previous_block = ciphertext[i]; 
    }
}

// Decryption using CBC mode
void cbc_decrypt(unsigned char* ciphertext, unsigned char* decryptedtext, int len, unsigned char key, unsigned char iv) {
    unsigned char previous_block = iv;
    
    for (int i = 0; i < len; i++) {
        unsigned char decrypted_block = encrypt_block(ciphertext[i], key);
        decryptedtext[i] = decrypted_block ^ previous_block; 
        previous_block = ciphertext[i]; 
    }
}

//2.3 Bonus: Output Feedback (OFB) Mode
// Encryption and Decryption using OFB mode
void ofb_encrypt_decrypt(unsigned char* input, unsigned char* output, int len, unsigned char key, unsigned char iv) {
    unsigned char feedback = iv;
    
    for (int i = 0; i < len; i++) {
        feedback = encrypt_block(feedback, key);  
        output[i] = input[i] ^ feedback;          
    }
}


//3.Prepare Sample Input & Encrypt and Decrypt Using ECB and CBC
#include <string.h>

#define BLOCK_SIZE 8

// Function prototypes
void ecb_encrypt(unsigned char* plaintext, unsigned char* ciphertext, int len, unsigned char key);
void ecb_decrypt(unsigned char* ciphertext, unsigned char* decryptedtext, int len, unsigned char key);
void cbc_encrypt(unsigned char* plaintext, unsigned char* ciphertext, int len, unsigned char key, unsigned char iv);
void cbc_decrypt(unsigned char* ciphertext, unsigned char* decryptedtext, int len, unsigned char key, unsigned char iv);

// Padding function (zero padding)
int pad_plaintext(unsigned char* plaintext, int len) {
    int pad_len = BLOCK_SIZE - (len % BLOCK_SIZE);
    for (int i = len; i < len + pad_len; i++) {
        plaintext[i] = 0x00;  
    }
    return len + pad_len;  
}

int main() {
    unsigned char plaintext[16] = "HELLO";  
    unsigned char key = 0x3F;              
    unsigned char iv = 0x55;                
    int padded_len = pad_plaintext(plaintext, strlen((char*)plaintext));

    unsigned char ciphertext[16], decryptedtext[16];

    // ECB Mode
    printf("ECB Mode:\n");
    ecb_encrypt(plaintext, ciphertext, padded_len, key);
    ecb_decrypt(ciphertext, decryptedtext, padded_len, key);
    printf("Decrypted: %s\n", decryptedtext);

    // CBC Mode
    printf("\nCBC Mode:\n");
    cbc_encrypt(plaintext, ciphertext, padded_len, key, iv);
    cbc_decrypt(ciphertext, decryptedtext, padded_len, key, iv);
    printf("Decrypted: %s\n", decryptedtext);

    return 0;
}

// Dummy ECB and CBC encryption and decryption functions
void ecb_encrypt(unsigned char* plaintext, unsigned char* ciphertext, int len, unsigned char key) {
    for (int i = 0; i < len; i++) ciphertext[i] = plaintext[i] ^ key;  
}

void ecb_decrypt(unsigned char* ciphertext, unsigned char* decryptedtext, int len, unsigned char key) {
    for (int i = 0; i < len; i++) decryptedtext[i] = ciphertext[i] ^ key;  
}

void cbc_encrypt(unsigned char* plaintext, unsigned char* ciphertext, int len, unsigned char key, unsigned char iv) {
    unsigned char prev = iv;
    for (int i = 0; i < len; i++) {
        ciphertext[i] = (plaintext[i] ^ prev) ^ key;  
        prev = ciphertext[i];
    }
}

void cbc_decrypt(unsigned char* ciphertext, unsigned char* decryptedtext, int len, unsigned char key, unsigned char iv) {
    unsigned char prev = iv;
    for (int i = 0; i < len; i++) {
        decryptedtext[i] = (ciphertext[i] ^ key) ^ prev;  
        prev = ciphertext[i];
    }
}




