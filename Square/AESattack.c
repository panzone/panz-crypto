#include "pAES.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//This functions execute the numRound round of AES. The last one remove the mixColumns
void aes_encrypt_fullRound(unsigned char output[], unsigned char key[], int numRound){
    SubBytes(output);
    ShiftRows(output);
    MixColumns(output);
    newRoundKey(key,numRound);
    AddRoundKey(output,key);
}

void aes128_encrypt_5round(unsigned char input[], unsigned char output[], unsigned char key[])
{
    BYTE bufferKey [16];
    memcpy(bufferKey, key, 16);
    memcpy(output, input, 16);

    AddRoundKey(output,bufferKey);
   aes_encrypt_fullRound(output,bufferKey,1);
     aes_encrypt_fullRound(output,bufferKey,2);
       aes_encrypt_fullRound(output,bufferKey,3);
         aes_encrypt_fullRound(output,bufferKey,4);

   /*The last round doesn' t use MixColums*/
   SubBytes(output);
   ShiftRows(output);
   newRoundKey(bufferKey,5);
   AddRoundKey(output,bufferKey);

}

void createPlainTexts(unsigned char plaintexts [256][16], unsigned char key[]){
    unsigned int numOutput = 0;
    unsigned int i = 0;
    unsigned char input[16];
    unsigned char output[16];
    unsigned char keyRound[16];

    memcpy(keyRound,key,16);
    newRoundKey(keyRound,1);

    for(unsigned long k = 0; k < 0xffffffff; k++){
        for(i=0; i< 16; i++) input[i]= 0x00;
        input[0]=k &0xff;
        input[5]=(k >> 8) &0xff;
        input[10]=(k>>16) &0xff;
        input[15]=(k>>24) &0xff;

        memcpy(output,input,16);

        AddRoundKey(output,key);
        SubBytes(output);
        ShiftRows(output);
        MixColumns(output);
        AddRoundKey(output,keyRound);

        if(output[1]+output[2] +output[3] ==0){
            for(i=0; i< 16; i++) plaintexts[numOutput][i] = input[i];
            numOutput++;
        }
    }
    if(numOutput!=256){
        printf("Not enough plaintext %x\n",numOutput);
        exit(2);
    }
}
