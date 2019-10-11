#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned char ciphertext[] = 
{
	0x8d,0x20,0xe5,0x05,0x6a,0x8d,0x24,0xd0,0x46,0x2c,
	0xe7,0x4e,0x49,0x04,0xc1,0xb5,0x13,0xe1,0x0d,0x1d,
	0xf4,0xa2,0xef,0x2a,0xd4,0x54,0x0f,0xae,0x1c,0xa0,
	0xaa,0xf9
};

unsigned char iv[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

unsigned char *plaintext = "This is a top secret.";

int encrypt(unsigned char* plaintext, unsigned char* encrypted_text, int* buf_out_len, unsigned char* key)
{
    if(strlen(key) < 16)
    {
        for(int i = strlen(key); i < 16; i++){
            key[i] = 0x20; // make sure all keys are 16 characters, filled with spaces.
        }
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, 1);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, 1);

    int encrypt_len;
    EVP_CipherUpdate(&ctx, encrypted_text, &encrypt_len, plaintext, strlen(plaintext));
    *buf_out_len = encrypt_len;
    EVP_CipherFinal_ex(&ctx, encrypted_text + encrypt_len, &encrypt_len);
    *buf_out_len += encrypt_len;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;
}

int check_key(char* key)
{
    unsigned char encrypted_text[EVP_MAX_BLOCK_LENGTH];
    int encrypt_len = 0;
    encrypt(plaintext, encrypted_text, &encrypt_len, key);
    for(int i = 0; i < sizeof(ciphertext); i++)
    {
        if(ciphertext[i] != encrypted_text[i])
        {
            return 1;
        }
    }
    return 0;
}

int main()
{
    char line[16];
    FILE *dictionary = fopen("words.txt", "r");
    int found = 0;
    if(dictionary != NULL)
    {
        while(fgets (line, 15, dictionary) != NULL) 
        {
            line[strcspn(line, "\r\n")] = 0;
            if (check_key(line) == 0)
            {
                printf("Key Found:: %s\n", line);
                found = 1;
                break;
            }
        }
        fclose(dictionary);
    }
    if (found != 1)
    	printf("Key was not found in words.txt\n");

    return 0;
}
