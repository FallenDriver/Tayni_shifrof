#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hmac.h>


EVP_PKEY* generate_key() {

    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Ошибка генерации ключа\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_group_name(ctx, "secp256k1") == 0) {
        printf("Ошибка генерации\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("Ошибка генерации\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

unsigned char *secret_generation(EVP_PKEY *private_key, EVP_PKEY *public_key, int *len_result) {
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);

    size_t len = 0;

    EVP_PKEY_derive_init(ctx);

    EVP_PKEY_derive_set_peer(ctx, public_key);

    EVP_PKEY_derive(ctx, NULL, &len);

    unsigned char *secret = malloc(len);

    EVP_PKEY_derive(ctx, secret, &len);

    *len_result = len;
    EVP_PKEY_CTX_free(ctx);

    return secret;
}



void key_derive(unsigned char *secret, size_t secret_len, unsigned char *enc_key, unsigned char *sig_key) {

    char *salt_str = "protocol-salt";
    unsigned char *salt = (unsigned char *)salt_str;
    size_t salt_len = strlen(salt_str);

    unsigned char prk[32];
    unsigned int prk_len = 32;

    HMAC(EVP_sha256(), salt, salt_len, secret, secret_len, prk, &prk_len);

    char *info_enc = "enc";
    size_t info_enc_len = strlen(info_enc);

    char *info_sig = "sig";
    size_t info_sig_len = strlen(info_sig);

    char input_enc[33];
    memcpy(input_enc, info_enc, info_enc_len);
    input_enc[info_enc_len] = 0x01;

    unsigned int len_out = 32;
    HMAC(EVP_sha256(), prk, prk_len, input_enc, info_enc_len + 1, enc_key, &len_out);



    char input_sig[33];
    memcpy(input_sig, info_sig, info_sig_len);
    input_sig[info_sig_len] = 0x01;

    HMAC(EVP_sha256(), prk, prk_len, input_sig, info_sig_len + 1, sig_key, &len_out);
}
    


int main() {
    
    if (OPENSSL_init_crypto(0, NULL) != 1) {
        printf("Ошибка инициализации OpenSSl\n");
        return 1;
    }

    printf("Версия OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));

    
    EVP_PKEY *mikhail_key = generate_key();
    EVP_PKEY *alexandra_key = generate_key();

    if (mikhail_key != NULL && alexandra_key != NULL) {
        printf("Ключи сгенерированы успешно!\n");
    }

    int m_len, a_len;

    unsigned char *mikhail_secret = secret_generation(mikhail_key, alexandra_key, &m_len);
    unsigned char *alexandra_secret = secret_generation(alexandra_key, mikhail_key, &a_len);


    if (m_len == a_len && memcmp(mikhail_secret, alexandra_secret, m_len) == 0) {
        printf("Секреты совпадают!\n");
    } else {
        printf("Ошибка: секреты не совпадают!\n");
    }


    unsigned char enc_key[32];
    unsigned char sig_key[32];

    key_derive(mikhail_secret, m_len, enc_key, sig_key);

    printf("Enc-ключ: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", enc_key[i]);
    }

    printf("\nSig-ключ: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", sig_key[i]);
    }
    printf("\n");
    
    EVP_PKEY_free(mikhail_key);
    EVP_PKEY_free(alexandra_key);
    free(mikhail_secret);
    free(alexandra_secret);

    OPENSSL_cleanup();
    return 0;
}