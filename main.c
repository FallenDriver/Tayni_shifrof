#include <stdio.h>
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
        printf("Ошибка генерации");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
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
    
    EVP_PKEY_free(mikhail_key);
    EVP_PKEY_free(alexandra_key);

    OPENSSL_cleanup();
    return 0;
}