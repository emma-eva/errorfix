#ifndef PKCS7_H
#define PKCS7_H

#include <openssl/pkcs7.h>

typedef struct {
    unsigned char *signature_data;
    size_t signature_length;
} PKCS7Signature;

int pkcs7_sign(PKCS7Signature *pkcs7, const unsigned char *keystore_data, size_t keystore_size, const char *key_alias, const char *key_password, const char *store_password, const unsigned char *data, size_t data_len);
void pkcs7_free(PKCS7Signature *pkcs7);

#endif
