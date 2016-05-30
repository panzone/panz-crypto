# panz-crypto

panz-crypto is a collection of cryptographic algorithms and attacks created during my Cryptography classes. The algorithms' implementation are simple and easy to modify so that they can be used for educational purposes.

**Please note that none of these implementations are cryptographically secure. They shouldn't be used in any context that require a cryptographically secure implementation.**

## pAES

pAES is a simple implementation of AES with 128-bit keys, created for my Advanced Cryptography class. It's very basic and provides only encryption at the moment, but it presents a simple interface for call the AES internal operations.

## fermatRSA

This is a simple implementation of an attack to RSA using the Fermat factorization written during a challenge in my class. It requires gmp and openssl.

## Square

Square implements a Square attack on a reduced 5-round AES 128 bit. It uses pAES for the generation of the ciphertexts.

## CSPRNG

This is an implementation of Blum Micali pseudorandom number generator. It requires gmp.