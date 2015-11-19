#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>

/*Read the public key and put it in memory*/

RSA *readPublicKey(char * path){
    char *buffer;
    FILE *f = fopen(path,"rb");
    if(!f)
        return NULL;

    fseek(f, 0L, SEEK_END);
    int sz = ftell(f);
    fseek(f, 0L, SEEK_SET);

    buffer = malloc(sz+1);
    if(!buffer)
        return NULL;

    fread(buffer,1,sz,f);
    buffer[sz] ='\0';
    fclose(f);
    BIO *provaB = BIO_new(BIO_s_mem());
    BIO_puts(provaB,buffer);
    RSA *publicKey = PEM_read_bio_RSAPublicKey(provaB,NULL,NULL,NULL);
    free(buffer);
    return publicKey;
}

/* Naive implementation of the Fermat factorization. 
 * For the return we use two strings, not the best way but easy to implement
 */
void fermat(mpz_t n,char ** retVal){
    mpz_t a,b,temp,temp2;

    mpz_inits(a,b,temp,temp2,NULL);

    mpz_sqrt(a,n);
    mpz_set_ui(temp,2);

    while(mpz_cmp(temp,temp2)!=0){
        mpz_add_ui(a,a,1);
        mpz_mul(temp,a,a);
        mpz_sub(temp,temp,n);
        mpz_sqrt(b,temp);
        mpz_mul(temp2,b,b);
    }
    mpz_add(temp,a,b);
    retVal[0] = mpz_get_str(NULL,10,temp);

    mpz_sub(temp,a,b);
    retVal[1] = mpz_get_str(NULL,10,temp);
}

/* Starting from the public key, try to deduct p and q using fermat
 * Then it change the key putting all the data into it, effectively create the
 * keypair public-private
 */

void generatePrivateKey(RSA *publicKey){
    mpz_t n,p,q,phi,d,e;
    char* retF[2];

    mpz_inits(n,p,q,phi,d,e,NULL);

    
    /* Recover n and e from the key */  
    mpz_set_str(n,BN_bn2dec(publicKey->n),10);
    mpz_set_str(e,BN_bn2dec(publicKey->e),10);

    /* Calculate p and q using fermat */
    fermat(n,retF);

    mpz_set_str(p,retF[0],10);
    mpz_set_str(q,retF[1],10);
    BN_dec2bn(&(publicKey->p),retF[0]);
    BN_dec2bn(&(publicKey->q),retF[1]);

    /* iqmp */
    mpz_invert(phi,q,p);
    BN_dec2bn(&(publicKey->iqmp),mpz_get_str(NULL,10,phi));

    /* phi(N) */
    mpz_sub_ui(p,p,1);
    mpz_sub_ui(q,q,1);
    mpz_mul(phi,p,q);

    /* d */
    mpz_invert(d,e,phi);
    BN_dec2bn(&(publicKey->d),mpz_get_str(NULL,10,d));

    /* d mod (p-1) */
    mpz_mod(phi,d,p);
    BN_dec2bn(&(publicKey->dmp1),mpz_get_str(NULL,10,phi));

    /* d mod (q-1) */
    mpz_mod(phi,d,q);
    BN_dec2bn(&(publicKey->dmq1),mpz_get_str(NULL,10,phi));

    /* Now the key is complete */
}

int main(int argc, char** argv) {
    char err[256];
    char encrypt[256];
    char decrypt[256];

    RSA *key = readPublicKey(argv[1]);
    if(!key){
        fprintf(stderr,"Error reading the key\n");
        exit(2);
    }
    generatePrivateKey(key);

    FILE *fd = fopen(argv[2],"rb");
    fread(encrypt,1,256,fd);
    fclose(fd);

    if(RSA_private_decrypt(256, (unsigned char*)encrypt, (unsigned char*)decrypt,
                           key, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }
    printf("%s\n", decrypt);

    return 1;
}