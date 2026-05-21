#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>


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


    
    EVP_PKEY_free(mikhail_key);
    EVP_PKEY_free(alexandra_key);
    free(mikhail_secret);
    free(alexandra_secret);

    OPENSSL_cleanup();
    return 0;
}