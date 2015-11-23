#ifndef PCSPRNG_H
#define PCSPRNG_H

/*Handle the generator*/
void initGenerator(unsigned long seed);
void destroyGenerator();

/*Return a random bit. Must first seed the generator*/
unsigned char nextRandomBit();

#endif
