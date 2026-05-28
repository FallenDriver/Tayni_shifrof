#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cipher.h"
#include <stddef.h>



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

    size_t m_len, a_len;

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

    unsigned char IV[12];
    unsigned char tag[16];
    unsigned char *text = (unsigned char *)"Здарова!";
    int text_len = strlen((char *)text);

    unsigned char *aad = (unsigned char *)"Михаил->Александра";
    int aad_len = strlen((char *)aad);

    unsigned char ciphertext[text_len];

    encrypt_message(enc_key, text, text_len, aad, aad_len, IV, ciphertext, tag);

    printf("IV: ");
    for (int i = 0; i < 12; i++) {
        printf("%02x", IV[i]);
    }
    printf("\nCiphertext: ");
    for (int i = 0; i < text_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\nTag: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    int data_len = 12 + text_len + 16;

    unsigned char *data = malloc(data_len);

    memcpy(data, IV, 12);
    memcpy(data + 12, ciphertext, text_len);
    memcpy(data + 12 + text_len, tag, 16);

    size_t sig_len = 0;
    unsigned char *signature = sign_message(mikhail_key, data, data_len, &sig_len);

    printf("Длинна подписи: %zu\n", sig_len);

    size_t pub_key_len;
    EVP_PKEY_get_octet_string_param(mikhail_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &pub_key_len);
    unsigned char *sender_pub_key = malloc(pub_key_len);
    EVP_PKEY_get_octet_string_param(mikhail_key, OSSL_PKEY_PARAM_PUB_KEY, sender_pub_key, pub_key_len, &pub_key_len);
    
    Pack packet;

    memcpy(packet.IV, IV, 12);
    memcpy(packet.tag, tag, 16);
    packet.ciphertext_len = text_len;
    packet.ciphertext = malloc(text_len);
    memcpy(packet.ciphertext, ciphertext, text_len);

    packet.signature_len = sig_len;
    packet.signature = malloc(sig_len);
    memcpy(packet.signature, signature, sig_len);

    packet.aad_len = aad_len;
    packet.aad = malloc(aad_len);
    memcpy(packet.aad, aad, aad_len);

    packet.pub_key_len = pub_key_len;
    packet.sender_pub_key = malloc(pub_key_len);
    memcpy(packet.sender_pub_key, sender_pub_key, pub_key_len);

    printf("%d\n", packet.pub_key_len);

    if (decrypt(packet, enc_key) == 1) {
        printf("Успешный результат!\n");
    } else {
        printf("Где то прячется ошибка..\n");
    }




    free(data);
    free(signature);
    EVP_PKEY_free(mikhail_key);
    EVP_PKEY_free(alexandra_key);
    free(mikhail_secret);
    free(alexandra_secret);
    free(packet.ciphertext);
    free(packet.signature);
    free(packet.aad);
    free(packet.sender_pub_key);

    OPENSSL_cleanup();
    return 0;
}