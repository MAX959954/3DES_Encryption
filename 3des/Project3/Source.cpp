#include <openssl/des.h>
#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

const int MAX_LENGTH = 100;


//Second  method of DES encryption 
//Triple DES key for Encryption and Decryption
DES_cblock Key1 = { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
DES_cblock Key2 = { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 };
DES_cblock Key3 = { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 };
DES_key_schedule SchKey1, SchKey2, SchKey3;

//Print Encrypted and Decrypted data packets
void print_data(const char* tittle, const void* data, int len);

int main()
{
    //Input data to encrypt
    DES_cblock input_data = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x6, 0x7, 0x8 };

    //Check for Weak key generation
    if (-2 == (DES_set_key_checked(&Key1, &SchKey1) | DES_set_key_checked(&Key2, &SchKey2) | DES_set_key_checked(&Key3, &SchKey3)))
    {
        printf(" Weak key ....\n");
        return 1;
    }

    //Buffers for Encryption and Decryption
    DES_cblock cipher;
    DES_cblock text;

    //Triple-DES ECB Encryption
    DES_ecb3_encrypt(&input_data, &cipher, &SchKey1, &SchKey2, &SchKey3, DES_ENCRYPT);

    //Triple-DES ECB Decryption
    DES_ecb3_encrypt(&cipher, &text, &SchKey1, &SchKey2, &SchKey3, DES_ENCRYPT);

    //Printing and Verifying
    print_data("\n Original ", (const void*)input_data, sizeof(input_data));
    print_data("\n Encrypted ", (const void*)cipher, sizeof(input_data));
    print_data("\n Decrypted ", (const void*)text, sizeof(input_data));

    return 0;
}


void print_data(const char* tittle, const void* data, int len)
{
    printf("%s : ", tittle);
    const unsigned char* p = (const unsigned char*)data;
    int i = 0;
    for (; i < len; i++)
    {
        printf("%02X ", *p++);
    }

    printf("\n");
}



//First method of 3DES Encryption
void des3_encrypt(const unsigned char* input, unsigned char* output, const unsigned char* key)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

     
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, NULL);

  
    EVP_EncryptUpdate(ctx, output, &len, input, strlen((const char*)input));
    ciphertext_len = len;

   
    EVP_EncryptFinal_ex(ctx, output + len, &len);
    ciphertext_len += len;

   
    EVP_CIPHER_CTX_free(ctx);
}

void des3_decrypt(const unsigned char* input, unsigned char* output, const unsigned char* key)
{
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;


    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, key, NULL);

    
    EVP_DecryptUpdate(ctx, output, &len, input, strlen((const char*)input));
    plaintext_len = len;

    
    EVP_DecryptFinal_ex(ctx, output + len, &len);
    plaintext_len += len;

   
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    const unsigned char input[] = "Hello World!";
    int input_length = strlen((char*)input);

    // 24-byte key for Triple DES
    const unsigned char key[26] = "0123456789abcdefghABCDEFG";

    unsigned char encrypted[MAX_LENGTH];
    unsigned char decrypted[MAX_LENGTH];

    des3_encrypt(input, encrypted, key);
    std::cout << "Encrypted: ";
    for (int i = 0; i < input_length; ++i)
        std::cout << std::hex << (int)encrypted[i];
    std::cout << std::endl;

    des3_decrypt(encrypted, decrypted, key);
    std::cout << "Decrypted: " << decrypted << std::endl;

    return 0;
};
