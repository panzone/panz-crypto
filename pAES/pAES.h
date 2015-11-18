#ifndef PAES_H
#define PAES_H

typedef unsigned char BYTE;
#define NUM_BYTE 128/8

extern BYTE SBOX[16][16];
extern BYTE INV_SBOX[16][16];

/*Cifra con AES128 input con la chiave key e mette il risultato in output*/

void p_aes128_encrypt(BYTE input[], BYTE output[], BYTE key[]);

/*Le funzioni delle singole operazioni*/
void AddRoundKey(BYTE text[], BYTE key[]);
void SubBytes(BYTE text[]);
void ShiftRows(BYTE text[]);
void MixColumns(BYTE text[]);

#endif
