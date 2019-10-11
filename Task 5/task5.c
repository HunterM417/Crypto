// Task4.c for M. Hunter Martin's CSCE465 Fall 2019 Submission.

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned char iv[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
unsigned char key[] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc};

unsigned char *plaintext = "This is a very secret message.";

int encrypt(unsigned char* plaintext, unsigned char* encrypted_text, int* e_len, unsigned char* key)
{
    if(strlen(key) < 16)
    {
        for(int i = strlen(key); i < 16; i++){
            key[i] = 0x20; // make sure all keys are 16 characters, filled with spaces.
        }
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_des_cbc(), NULL, NULL, NULL, 1);
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, 1);

    int encrypt_len;
    EVP_CipherUpdate(&ctx, encrypted_text, &encrypt_len, plaintext, strlen(plaintext));
    *e_len = encrypt_len;
    EVP_CipherFinal_ex(&ctx, encrypted_text + encrypt_len, &encrypt_len);
    *e_len += encrypt_len;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;
}

int main()
{
    unsigned char encrypted_text[EVP_MAX_BLOCK_LENGTH];
    int encrypt_len = 0;
    encrypt(plaintext, encrypted_text, &encrypt_len, key);

    printf("Plaintext: %s\n", plaintext);
    printf("Cipher: %s\n", encrypted_text);

    return 0;
}
