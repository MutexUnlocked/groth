/*
 * =====================================================================================
 *
 *       Filename:  test.cpp
 *
 *    Description: Check sodium salsa20 
 *
 *        Version:  1.0
 *        Created:  09/13/2020 09:15:14 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Friedrich Doku, 
 *   Organization:  Mutex Unlocked
 *
 * =====================================================================================
 */
#include <iostream>
#include <stdlib.h>
#include <sodium.h>

#define MESSAGE ((const unsigned char*) "MESSAGE")
#define MESSAGE_LEN 7
#define CIPHERTEXT_LEN (MESSAGE_LEN + crypto_secretbox_MACBYTES)

auto main() -> int{
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char ciphertext[CIPHERTEXT_LEN];

    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));
    crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, key);

    unsigned char decrypted[1000]; // BS LENGTH
    if(crypto_secretbox_open(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, key)){
        std::cout << "PASSED" << std::endl;  
    }
    return 0;
}


