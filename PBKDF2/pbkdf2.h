#ifndef SHA_H
#define SHA_H

#include <stdint.h>
#include <stdio.h>

typedef uint32_t uint160_t[5];
#define PRINT_HASH(hash)                                                       \
  for (int _i = 0; _i < 5; _i++)                                               \
    printf("%02x ", hash[_i]);                                                 \
  printf("\n");

void pbkdf2(char *key, char *message, uint32_t iter, uint160_t password);

#endif
