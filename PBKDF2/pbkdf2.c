#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

typedef uint32_t uint160_t[5];

#define toBE(num)                                                              \
  ((num & 0x000000ff) << 24) | ((num & 0x0000ff00) << 8) |                     \
      ((num & 0x00ff0000) >> 8) | ((num & 0xff000000) >> 24)
#define ROTL(a, n) ((a << n) | (a >> (32 - n)))

#define SR0_R15(t, a, b, c, d, e)                                              \
  e = ROTL(a, 5) + (d ^ (b & (c ^ d))) + t + e + 0x5A827999;                   \
  b = ROTL(b, 30);
#define SR16_R19(t, a, b, c, d, e)                                             \
  e = ROTL(a, 5) + (d ^ (b & (c ^ d))) + t + e + 0x5A827999;                   \
  b = ROTL(b, 30);
#define SR20_R39(t, a, b, c, d, e)                                             \
  e = ROTL(a, 5) + (b ^ c ^ d) + t + e + 0x6ED9EBA1;                           \
  b = ROTL(b, 30);
#define SR40_R59(t, a, b, c, d, e)                                             \
  e = ROTL(a, 5) + ((b & c) | (b & d) | (c & d)) + t + e + 0x8F1BBCDC;         \
  b = ROTL(b, 30);
#define SR60_R79(t, a, b, c, d, e)                                             \
  e = ROTL(a, 5) + (b ^ c ^ d) + t + e + 0xCA62C1D6;                           \
  b = ROTL(b, 30);

#define bitselect(d, c, b) (d ^ (b & (c ^ d)))

/* SHA_PASSES implements the last 77 steps of SHA-1. */

#define SHA_PASSES                                                             \
  do {                                                                         \
    SR0_R15(W3, C, D, E, A, B);                                                \
    SR0_R15(W4, B, C, D, E, A);                                                \
    SR0_R15(W5, A, B, C, D, E);                                                \
    D = ROTL(E, 5) + bitselect(C, B, A) + D + 0x5A827999;                      \
    A = ROTL(A, 30);                                                           \
    C = ROTL(D, 5) + bitselect(B, A, E) + C + 0x5A827999;                      \
    E = ROTL(E, 30);                                                           \
    B = ROTL(C, 5) + bitselect(A, E, D) + B + 0x5A827999;                      \
    D = ROTL(D, 30);                                                           \
    A = ROTL(B, 5) + bitselect(E, D, C) + A + 0x5A827999;                      \
    C = ROTL(C, 30);                                                           \
    E = ROTL(A, 5) + bitselect(D, C, B) + E + 0x5A827999;                      \
    B = ROTL(B, 30);                                                           \
    D = ROTL(E, 5) + bitselect(C, B, A) + D + 0x5A827999;                      \
    A = ROTL(A, 30);                                                           \
    C = ROTL(D, 5) + bitselect(B, A, E) + C + 0x5A827999;                      \
    E = ROTL(E, 30);                                                           \
    B = ROTL(C, 5) + bitselect(A, E, D) + B + 0x5A827999;                      \
    D = ROTL(D, 30);                                                           \
    A = ROTL(B, 5) + bitselect(E, D, C) + A + 0x5A827999;                      \
    C = ROTL(C, 30);                                                           \
    SR0_R15(Wf, A, B, C, D, E);                                                \
    W0 = ROTL((W2 ^ W0), 1);                                                   \
    SR16_R19(W0, E, A, B, C, D);                                               \
    W1 = ROTL((W3 ^ W1), 1);                                                   \
    SR16_R19(W1, D, E, A, B, C);                                               \
    W2 = ROTL((Wf ^ W4 ^ W2), 1);                                              \
    SR16_R19(W2, C, D, E, A, B);                                               \
    W3 = ROTL((W0 ^ W5 ^ W3), 1);                                              \
    SR16_R19(W3, B, C, D, E, A);                                               \
    W4 = ROTL((W1 ^ W4), 1);                                                   \
    SR20_R39(W4, A, B, C, D, E);                                               \
    W5 = ROTL((W2 ^ W5), 1);                                                   \
    SR20_R39(W5, E, A, B, C, D);                                               \
    W6 = ROTL((W3), 1);                                                        \
    SR20_R39(W6, D, E, A, B, C);                                               \
    W7 = ROTL((W4 ^ Wf), 1);                                                   \
    SR20_R39(W7, C, D, E, A, B);                                               \
    W8 = ROTL((W5 ^ W0), 1);                                                   \
    SR20_R39(W8, B, C, D, E, A);                                               \
    W9 = ROTL((W6 ^ W1), 1);                                                   \
    SR20_R39(W9, A, B, C, D, E);                                               \
    Wa = ROTL((W7 ^ W2), 1);                                                   \
    SR20_R39(Wa, E, A, B, C, D);                                               \
    Wb = ROTL((W8 ^ W3), 1);                                                   \
    SR20_R39(Wb, D, E, A, B, C);                                               \
    Wc = ROTL((W9 ^ W4), 1);                                                   \
    SR20_R39(Wc, C, D, E, A, B);                                               \
    Wd = ROTL((Wa ^ W5 ^ Wf), 1);                                              \
    SR20_R39(Wd, B, C, D, E, A);                                               \
    We = ROTL((Wb ^ W6 ^ W0), 1);                                              \
    SR20_R39(We, A, B, C, D, E);                                               \
    Wf = ROTL((Wc ^ W7 ^ W1 ^ Wf), 1);                                         \
    SR20_R39(Wf, E, A, B, C, D);                                               \
    W0 = ROTL((Wd ^ W8 ^ W2 ^ W0), 1);                                         \
    SR20_R39(W0, D, E, A, B, C);                                               \
    W1 = ROTL((We ^ W9 ^ W3 ^ W1), 1);                                         \
    SR20_R39(W1, C, D, E, A, B);                                               \
    W2 = ROTL((Wf ^ Wa ^ W4 ^ W2), 1);                                         \
    SR20_R39(W2, B, C, D, E, A);                                               \
    W3 = ROTL((W0 ^ Wb ^ W5 ^ W3), 1);                                         \
    SR20_R39(W3, A, B, C, D, E);                                               \
    W4 = ROTL((W1 ^ Wc ^ W6 ^ W4), 1);                                         \
    SR20_R39(W4, E, A, B, C, D);                                               \
    W5 = ROTL((W2 ^ Wd ^ W7 ^ W5), 1);                                         \
    SR20_R39(W5, D, E, A, B, C);                                               \
    W6 = ROTL((W3 ^ We ^ W8 ^ W6), 1);                                         \
    SR20_R39(W6, C, D, E, A, B);                                               \
    W7 = ROTL((W4 ^ Wf ^ W9 ^ W7), 1);                                         \
    SR20_R39(W7, B, C, D, E, A);                                               \
    W8 = ROTL((W5 ^ W0 ^ Wa ^ W8), 1);                                         \
    SR40_R59(W8, A, B, C, D, E);                                               \
    W9 = ROTL((W6 ^ W1 ^ Wb ^ W9), 1);                                         \
    SR40_R59(W9, E, A, B, C, D);                                               \
    Wa = ROTL((W7 ^ W2 ^ Wc ^ Wa), 1);                                         \
    SR40_R59(Wa, D, E, A, B, C);                                               \
    Wb = ROTL((W8 ^ W3 ^ Wd ^ Wb), 1);                                         \
    SR40_R59(Wb, C, D, E, A, B);                                               \
    Wc = ROTL((W9 ^ W4 ^ We ^ Wc), 1);                                         \
    SR40_R59(Wc, B, C, D, E, A);                                               \
    Wd = ROTL((Wa ^ W5 ^ Wf ^ Wd), 1);                                         \
    SR40_R59(Wd, A, B, C, D, E);                                               \
    We = ROTL((Wb ^ W6 ^ W0 ^ We), 1);                                         \
    SR40_R59(We, E, A, B, C, D);                                               \
    Wf = ROTL((Wc ^ W7 ^ W1 ^ Wf), 1);                                         \
    SR40_R59(Wf, D, E, A, B, C);                                               \
    W0 = ROTL((Wd ^ W8 ^ W2 ^ W0), 1);                                         \
    SR40_R59(W0, C, D, E, A, B);                                               \
    W1 = ROTL((We ^ W9 ^ W3 ^ W1), 1);                                         \
    SR40_R59(W1, B, C, D, E, A);                                               \
    W2 = ROTL((Wf ^ Wa ^ W4 ^ W2), 1);                                         \
    SR40_R59(W2, A, B, C, D, E);                                               \
    W3 = ROTL((W0 ^ Wb ^ W5 ^ W3), 1);                                         \
    SR40_R59(W3, E, A, B, C, D);                                               \
    W4 = ROTL((W1 ^ Wc ^ W6 ^ W4), 1);                                         \
    SR40_R59(W4, D, E, A, B, C);                                               \
    W5 = ROTL((W2 ^ Wd ^ W7 ^ W5), 1);                                         \
    SR40_R59(W5, C, D, E, A, B);                                               \
    W6 = ROTL((W3 ^ We ^ W8 ^ W6), 1);                                         \
    SR40_R59(W6, B, C, D, E, A);                                               \
    W7 = ROTL((W4 ^ Wf ^ W9 ^ W7), 1);                                         \
    SR40_R59(W7, A, B, C, D, E);                                               \
    W8 = ROTL((W5 ^ W0 ^ Wa ^ W8), 1);                                         \
    SR40_R59(W8, E, A, B, C, D);                                               \
    W9 = ROTL((W6 ^ W1 ^ Wb ^ W9), 1);                                         \
    SR40_R59(W9, D, E, A, B, C);                                               \
    Wa = ROTL((W7 ^ W2 ^ Wc ^ Wa), 1);                                         \
    SR40_R59(Wa, C, D, E, A, B);                                               \
    Wb = ROTL((W8 ^ W3 ^ Wd ^ Wb), 1);                                         \
    SR40_R59(Wb, B, C, D, E, A);                                               \
    Wc = ROTL((W9 ^ W4 ^ We ^ Wc), 1);                                         \
    SR60_R79(Wc, A, B, C, D, E);                                               \
    Wd = ROTL((Wa ^ W5 ^ Wf ^ Wd), 1);                                         \
    SR60_R79(Wd, E, A, B, C, D);                                               \
    We = ROTL((Wb ^ W6 ^ W0 ^ We), 1);                                         \
    SR60_R79(We, D, E, A, B, C);                                               \
    Wf = ROTL((Wc ^ W7 ^ W1 ^ Wf), 1);                                         \
    SR60_R79(Wf, C, D, E, A, B);                                               \
    W0 = ROTL((Wd ^ W8 ^ W2 ^ W0), 1);                                         \
    SR60_R79(W0, B, C, D, E, A);                                               \
    W1 = ROTL((We ^ W9 ^ W3 ^ W1), 1);                                         \
    SR60_R79(W1, A, B, C, D, E);                                               \
    W2 = ROTL((Wf ^ Wa ^ W4 ^ W2), 1);                                         \
    SR60_R79(W2, E, A, B, C, D);                                               \
    W3 = ROTL((W0 ^ Wb ^ W5 ^ W3), 1);                                         \
    SR60_R79(W3, D, E, A, B, C);                                               \
    W4 = ROTL((W1 ^ Wc ^ W6 ^ W4), 1);                                         \
    SR60_R79(W4, C, D, E, A, B);                                               \
    W5 = ROTL((W2 ^ Wd ^ W7 ^ W5), 1);                                         \
    SR60_R79(W5, B, C, D, E, A);                                               \
    W6 = ROTL((W3 ^ We ^ W8 ^ W6), 1);                                         \
    SR60_R79(W6, A, B, C, D, E);                                               \
    W7 = ROTL((W4 ^ Wf ^ W9 ^ W7), 1);                                         \
    SR60_R79(W7, E, A, B, C, D);                                               \
    W8 = ROTL((W5 ^ W0 ^ Wa ^ W8), 1);                                         \
    SR60_R79(W8, D, E, A, B, C);                                               \
    W9 = ROTL((W6 ^ W1 ^ Wb ^ W9), 1);                                         \
    SR60_R79(W9, C, D, E, A, B);                                               \
    Wa = ROTL((W7 ^ W2 ^ Wc ^ Wa), 1);                                         \
    SR60_R79(Wa, B, C, D, E, A);                                               \
    Wb = ROTL((W8 ^ W3 ^ Wd ^ Wb), 1);                                         \
    SR60_R79(Wb, A, B, C, D, E);                                               \
    Wc = ROTL((W9 ^ W4 ^ We ^ Wc), 1);                                         \
    SR60_R79(Wc, E, A, B, C, D);                                               \
    Wd = ROTL((Wa ^ W5 ^ Wf ^ Wd), 1);                                         \
    SR60_R79(Wd, D, E, A, B, C);                                               \
    We = ROTL((Wb ^ W6 ^ W0 ^ We), 1);                                         \
    SR60_R79(We, C, D, E, A, B);                                               \
    Wf = ROTL((Wc ^ W7 ^ W1 ^ Wf), 1);                                         \
    SR60_R79(Wf, B, C, D, E, A);                                               \
  } while (0)

/* It's necessary to use a "special" SHA-1 function since we don't know the salt
 * size */

void sha_salt(SHA_CTX *ctx, SHA_CTX *input, uint32_t size) {
  uint32_t A, B, C, D, E;
  uint32_t W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, Wa, Wb, Wc, Wd, We, Wf;

  A = ctx->h0;
  B = ctx->h1;
  C = ctx->h2;
  D = ctx->h3;
  E = ctx->h4;

  W0 = input->h0;
  W1 = input->h1;
  W2 = input->h2;
  W3 = input->h3;
  W4 = input->h4;
  W5 = 0;
  Wf = size;

  E = ROTL(A, 5) + (D ^ (B & (C ^ D))) + W0 + E + 0x5A827999;
  B = ROTL(B, 30);
  D = ROTL(E, 5) + (C ^ (A & (B ^ C))) + W1 + D + 0x5A827999;
  A = ROTL(A, 30);
  C = ROTL(D, 5) + (B ^ (E & (A ^ B))) + W2 + C + 0x5A827999;
  E = ROTL(E, 30);
  SHA_PASSES;

  input->h0 = A + ctx->h0;
  input->h1 = B + ctx->h1;
  input->h2 = C + ctx->h2;
  input->h3 = D + ctx->h3;
  input->h4 = E + ctx->h4;
}

void xor(uint32_t * buffer, SHA_CTX *ctx) {
      buffer[0] ^= ctx->h0;
      buffer[1] ^= ctx->h1;
      buffer[2] ^= ctx->h2;
      buffer[3] ^= ctx->h3;
      buffer[4] ^= ctx->h4;
    }

    /* This function precomputes the constants used during the first three
       rounds */

void calculate_constants(SHA_CTX *ctx, SHA_CTX *constants) {
  constants->h4 = ROTL(ctx->h0, 5) +
                  (ctx->h3 ^ (ctx->h1 & (ctx->h2 ^ ctx->h3))) + ctx->h4 +
                  0x5A827999;
  constants->h1 = ROTL(ctx->h1, 30);
  constants->h3 =
      (ctx->h2 ^ (ctx->h0 & (constants->h1 ^ ctx->h2))) + ctx->h3 + 0x5A827999;
  constants->h0 = ROTL(ctx->h0, 30);
}

void pbkdf2(char *key, char *message, uint32_t iter, uint160_t password) {
  SHA_CTX ipad_ctx, opad_ctx;
  uint32_t buffer[16];
  SHA_CTX tmp_ctx, const_ipad, const_opad;

  memset(buffer, 0, 64);
  memcpy(buffer, key, strlen(key));

  SHA1_Init(&ipad_ctx);
  SHA1_Init(&opad_ctx);

  for (int i = 0; i < 16; i++) {
    buffer[i] = buffer[i] ^ 0x36363636;
  }
  SHA1_Transform(&ipad_ctx, (unsigned char *)buffer);

  for (int i = 0; i < 16; i++) {
    buffer[i] = buffer[i] ^ 0x6a6a6a6a;
  }
  SHA1_Transform(&opad_ctx, (unsigned char *)buffer);

  /* The salt should be remade as an argument */
  tmp_ctx.h0 = 0x00000001;
  tmp_ctx.h1 = 0x80000000;
  tmp_ctx.h2 = 0x00000000;
  tmp_ctx.h3 = 0x00000000;
  tmp_ctx.h4 = 0x00000000;

  /* U1 computation */

  sha_salt(&ipad_ctx, &tmp_ctx, 544);

  calculate_constants(&opad_ctx, &const_opad);
  calculate_constants(&ipad_ctx, &const_ipad);

  uint32_t A, B, C, D, E;
  uint32_t W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, Wa, Wb, Wc, Wd, We, Wf;

  A = const_opad.h0;
  B = const_opad.h1;
  C = opad_ctx.h2;

  W0 = tmp_ctx.h0;
  W1 = tmp_ctx.h1;
  W2 = tmp_ctx.h2;
  W3 = tmp_ctx.h3;
  W4 = tmp_ctx.h4;
  W5 = 0x80000000;
  Wf = 672;

  E = W0 + const_opad.h4;
  D = ROTL(E, 5) + W1 + const_opad.h3;
  C = ROTL(D, 5) + (B ^ (E & (A ^ B))) + W2 + C + 0x5A827999;
  E = ROTL(E, 30);
  SHA_PASSES;

  tmp_ctx.h0 = A + opad_ctx.h0;
  tmp_ctx.h1 = B + opad_ctx.h1;
  tmp_ctx.h2 = C + opad_ctx.h2;
  tmp_ctx.h3 = D + opad_ctx.h3;
  tmp_ctx.h4 = E + opad_ctx.h4;

  xor(password, &tmp_ctx);

  /* Ui computation */

  for (int i = 1; i < iter; i++) {
    /* HMAC ipad */

    A = const_ipad.h0;
    B = const_ipad.h1;
    C = ipad_ctx.h2;

    W0 = tmp_ctx.h0;
    W1 = tmp_ctx.h1;
    W2 = tmp_ctx.h2;
    W3 = tmp_ctx.h3;
    W4 = tmp_ctx.h4;
    W5 = 0x80000000;
    Wf = 672;

    E = W0 + const_ipad.h4;
    D = ROTL(E, 5) + W1 + const_ipad.h3;
    C = ROTL(D, 5) + (B ^ (E & (A ^ B))) + W2 + C + 0x5A827999;
    E = ROTL(E, 30);
    SHA_PASSES;

    tmp_ctx.h0 = A + ipad_ctx.h0;
    tmp_ctx.h1 = B + ipad_ctx.h1;
    tmp_ctx.h2 = C + ipad_ctx.h2;
    tmp_ctx.h3 = D + ipad_ctx.h3;
    tmp_ctx.h4 = E + ipad_ctx.h4;

    /* HMAC opad */

    A = const_opad.h0;
    B = const_opad.h1;
    C = opad_ctx.h2;

    W0 = tmp_ctx.h0;
    W1 = tmp_ctx.h1;
    W2 = tmp_ctx.h2;
    W3 = tmp_ctx.h3;
    W4 = tmp_ctx.h4;
    W5 = 0x80000000;
    Wf = 672;

    E = W0 + const_opad.h4;
    D = ROTL(E, 5) + W1 + const_opad.h3;
    C = ROTL(D, 5) + (B ^ (E & (A ^ B))) + W2 + C + 0x5A827999;
    E = ROTL(E, 30);
    SHA_PASSES;

    tmp_ctx.h0 = A + opad_ctx.h0;
    tmp_ctx.h1 = B + opad_ctx.h1;
    tmp_ctx.h2 = C + opad_ctx.h2;
    tmp_ctx.h3 = D + opad_ctx.h3;
    tmp_ctx.h4 = E + opad_ctx.h4;

    /* Iter sum */

    password[0] ^= tmp_ctx.h0;
    password[1] ^= tmp_ctx.h1;
    password[2] ^= tmp_ctx.h2;
    password[3] ^= tmp_ctx.h3;
    password[4] ^= tmp_ctx.h4;
  }
}
