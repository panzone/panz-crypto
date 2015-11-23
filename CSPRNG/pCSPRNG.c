#include<gmp.h>

static mpz_t _seed;

/*1536-bit MODP Group, it have 2 as primitive root*/
static char* _prime_str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

/*Handle the generator*/
void initGenerator(unsigned long seed){
    mpz_init_set_ui(_seed,seed);
    mpz_t p;
    mpz_init_set_str(p,_prime_str,16);

    mpz_mod(_seed,_seed, p);
    mpz_clears (p,NULL);
}

void destroyGenerator(){
    mpz_clear(_seed);
}

/*Xt = g^X(t-1) mod p*/
unsigned char nextRandomBit(){
    mpz_t p;
    mpz_t r;
    mpz_t h;

    mpz_init_set_str(p,_prime_str,16);
    mpz_init_set_ui(r,2);
    mpz_init_set(h,p);
    mpz_sub_ui(h,h,1);
    mpz_cdiv_q_ui(h,h,2);

    mpz_powm(_seed,r,_seed,p);

    if(mpz_cmp(_seed,h) > 0)
        return 1;
    else
        return 0;
     mpz_clears (p,r,h,NULL);
}
