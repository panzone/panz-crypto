#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pAES.h"


//Semplice macro per stampare i nostri testi
#define PRINT(buf)  {              \
                    for (unsigned int i = 0; i < sizeof(buf);i++)    \
                        printf("%02x ", buf[i]); \
                    printf("\n");}

int main(){
    unsigned int i = 0;
    unsigned char cypher[256][16];

    unsigned char key [16];
    for(i=0; i< 16; i++) key[i]= i;

    createPlainTexts(cypher,key);

    for(unsigned long k = 0; k < 256; k++){
        aes128_encrypt_5round(cypher[k],cypher[k],key);
    }

    for(unsigned int k = 0; k < 16; k++){
        for (unsigned int keyValue = 0; keyValue < 256; keyValue++){
            unsigned char par_sum = 0;
            for(unsigned int val = 0; val < 256; val++){
                unsigned char tmp = cypher [val][k] ^ (keyValue&0xFF);
                tmp = (unsigned char) INV_SBOX[tmp >> 4][tmp & 0x0F];
                par_sum ^= tmp;
            }
            if (par_sum == 0)
                printf("Byte %d of the key: %x\n",k,keyValue);
        }
        printf("\n");
    }

    /*Ovviamente solo per controllo*/
    newRoundKey(key,1);
    newRoundKey(key,2);
    newRoundKey(key,3);
    newRoundKey(key,4);
    newRoundKey(key,5);

    printf("Chiave quinto round: ");
    PRINT(key);

}
