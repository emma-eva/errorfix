#include "pkcs7.h"
#include <openssl/pem.h>

int pkcs7_sign(PKCS7Signature *pkcs7, const unsigned char *keystore_data, size_t keystore_size, const char *key_alias, const char *key_password, const char *store_password, const unsigned char *data, size_t data_len) {
    /* Load keystore */
    BIO *in = BIO_new_mem_buf((void *)keystore_data, keystore_size);
    PKCS12 *p12 = d2i_PKCS12_bio(in, NULL);
    if (!p12) {
        return 0;
    }
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    if (!PKCS12_parse(p12, key_password, &pkey, &cert, &ca)) {
        PKCS12_free(p12);
        return 0;
    }
    PKCS12_free(p12);
    /* Sign data */
    BIO *data_in = BIO_new_mem_buf((void *)data, data_len);
    PKCS7 *pkcs7_raw = PKCS7_sign(cert, pkey, ca, data_in, PKCS7_BINARY);
    if (!pkcs7_raw) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 0;
    }
    /* Attach the original data to the PKCS7 container */
    PKCS7_add_attribute(pkcs7_raw, OBJ_nid2obj(NID_pkcs9_contentType), V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data));
    PKCS7_add_signed_attribute(pkcs7_raw, OBJ_nid2obj(NID_pkcs9_messageDigest), 0x02, (void *)hash, SHA256_DIGEST_LENGTH);
    BIO *out = BIO_new(BIO_s_mem());
    if (!i2d_PKCS7_bio(out, pkcs7_raw)) {
        PKCS7_free(pkcs7_raw);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 0;
    }
    PKCS7_free(pkcs7_raw);
    /* Get the PKCS7 signature bytes */
    long len = BIO_get_mem_data(out, NULL);
    pkcs7->signature_data = malloc(len);
    BIO_read(out, pkcs7->signature_data, len);
    pkcs7->signature_length = len;
    /* Clean up */
    BIO_free_all(in);
    BIO_free_all(data_in);
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    return 1;
}

void pkcs7_free(PKCS7Signature *pkcs7) {
    free(pkcs7->signature_data);
    pkcs7->signature_data = NULL;
    pkcs7->signature_length = 0;
}
