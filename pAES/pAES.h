#ifndef PAES_H
#define PAES_H
#define WORD        32                            // 1 WORD = 32 bit
#define NK          4                             // number of 32-bit words
#define DIM_MATRIX  (NK * WORD)/8                 // 16
#define SIZE        DIM_MATRIX/4                  // 4
typedef unsigned char BYTE;

extern BYTE SBOX[DIM_MATRIX][DIM_MATRIX];
extern BYTE INV_SBOX[DIM_MATRIX][DIM_MATRIX];

/*  Encryption with AES128  ------------------------------------------------  *
 *  10 ROUND:                                                                 *
 *  (                                     AddRoundKey  +)                     *
 *  9 * (SubBytes, ShiftRows, MixColumns, AddRoundKey) +                      *
 *  1 * (SubBytes, ShiftRows, AddRoundKey)                                    *
 *                                                                            *
 *  INPUT:                                                                    *
 *  text        =   {b0,  b4,  b8,  b12,    -> 128 Bytes                      *
 *                   b1,  b5,  b9,  b13,                                      *
 *                   b2,  b6,  b10, b14,                                      *
 *                   b3,  b7,  b11, b15}                                      *
 *  key         =   {k0,  k4,  k8,  k12,    -> 128 Bytes                      *
 *                   k1,  k5,  k9,  k13,                                      *
 *                   k2,  k6,  k10, k14,                                      *
 *                   k3,  k7,  k11, k15}                                      *
 *                                                                            *
 *  OUTPUT:                                                                   *
 *  ciphertext  =   {c0,  c4,  c8,  c12,    -> 128 Bytes                      *
 *                   c1,  c5,  c9,  c13,                                      *
 *                   c2,  c6,  c10, c14,                                      *
 *                   c3,  c7,  c11, c15}                                      *
 *  ------------------------------------------------------------------------  */
 
/*  Individual transformations in AES128 */
void SubBytes(BYTE* text[]);
void ShiftRows(BYTE* text[]);
void MixColumns(BYTE* text[]);
void newRoundKey(BYTE* key[], int i);
void AddRoundKey(BYTE* text[], BYTE* key[]);

/* Summary function */
void p_aes128_encrypt(char* text, char* ciphertext, char* key);

/* Useful functions */
void print_ciphertext(char* ciphertext);

#endif
