#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stddef.h>



typedef struct {
    unsigned char IV[12];
    unsigned char tag[16];
    unsigned char *ciphertext;
    int ciphertext_len;
    unsigned char *signature;
    int signature_len;
    unsigned char *aad;
    int aad_len;
    unsigned char *sender_pub_key;
    int pub_key_len;
} Pack;


EVP_PKEY* generate_key();


unsigned char* secret_generation(EVP_PKEY *private_key, EVP_PKEY *public_key, size_t *out_len);

void key_derive(unsigned char *secret, size_t secret_len, unsigned char *enc_key, unsigned char *sig_key);


void encrypt_message(unsigned char *enc_key, unsigned char *plaintext, int pt_len, unsigned char *aad, int aad_len, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);


unsigned char* sign_message(EVP_PKEY *private_key, unsigned char *data, int data_len, size_t *sig_len_out);


int decrypt(Pack message, unsigned char *enc_key);