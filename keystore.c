#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>

#define MAX_KEYSTORE_PASSWORD_LENGTH 1024

int sign_apk(const char *keystore_file, const char *key_alias, const char *key_password, const char *apk_file) {

    // Read keystore password
    char keystore_password[MAX_KEYSTORE_PASSWORD_LENGTH];
    printf("Enter keystore password: ");
    fgets(keystore_password, MAX_KEYSTORE_PASSWORD_LENGTH, stdin);
    size_t password_length = strlen(keystore_password);
    if (password_length > 0 && keystore_password[password_length - 1] == '\n') {
        keystore_password[password_length - 1] = '\0';
    }

    // Read Java Keystore file
    FILE *fp = fopen(keystore_file, "rb");
    if (!fp) {
        printf("Error: failed to open keystore file for reading.\n");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    size_t keystore_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *keystore_data = malloc(keystore_size);
    if (!keystore_data) {
        printf("Error: failed to allocate memory for keystore data.\n");
        fclose(fp);
        return 1;
    }
    fread(keystore_data, keystore_size, 1, fp);
    fclose(fp);

    // Load private key and certificate chain from Java Keystore
    PKCS12 *p12 = d2i_PKCS12(NULL, (const unsigned char **)&keystore_data, keystore_size);
    free(keystore_data);
    if (!p12) {
        printf("Error: failed to load PKCS#12 data from keystore file.\n");
        return 1;
    }
    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca = NULL;
    if (!PKCS12_parse(p12, key_password, &pkey, &cert, &ca)) {
        printf("Error: failed to parse PKCS#12 data from keystore file.\n");
        PKCS12_free(p12);
        return 1;
    }
    PKCS12_free(p12);

    // Load APK file
    FILE *apk_fp = fopen(apk_file, "rb");
    if (!apk_fp) {
        printf("Error: failed to open APK file for reading.\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 1;
    }
    fseek(apk_fp, 0, SEEK_END);
    size_t apk_size = ftell(apk_fp);
    fseek(apk_fp, 0, SEEK_SET);
    unsigned char *apk_data = malloc(apk_size);
    if (!apk_data) {
        printf("Error: failed to allocate memory for APK data.\n");
        fclose(apk_fp);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 1;
    }
    fread(apk_data, apk_size, 1, apk_fp);
    fclose(apk_fp);

        // Create PKCS#7 signed data
    PKCS7 *p7 = PKCS7_new();
    if (!p7) {
        printf("Error: failed to create PKCS#7 object.\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 1;
    }
    PKCS7_set_type(p7, NID_pkcs7_signed);

    // Create PKCS#7 signer info
    PKCS7_SIGNER_INFO *si = PKCS7_SIGNER_INFO_new();
    if (!si) {
        printf("Error: failed to create PKCS#7 signer info object.\n");
        PKCS7_free(p7);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 1;
    }
    PKCS7_SIGNER_INFO_set_version(si, 1);
    PKCS7_SIGNER_INFO_set0_signer_id(si, cert->cert_info->issuer, cert->cert_info->serialNumber);
    PKCS7_SIGNER_INFO_set0_signature(si, NULL, EVP_sha256());
    PKCS7_add_signer(p7, si);

    // Create PKCS#7 certificate chain
    STACK_OF(X509) *certs = sk_X509_new_null();
    if (!certs) {
        printf("Error: failed to create PKCS#7 certificate chain object.\n");
        PKCS7_SIGNER_INFO_free(si);
        PKCS7_free(p7);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 1;
    }
    sk_X509_push(certs, cert);
    for (int i = 0; i < sk_X509_num(ca); i++) {
        X509 *cacert = sk_X509_value(ca, i);
        sk_X509_push(certs, cacert);
    }
    PKCS7_add_certificate(p7, cert);
    PKCS7_add_certificate_stack(p7, certs);

    // Create PKCS#7 content
    BIO *apk_bio = BIO_new_mem_buf(apk_data, apk_size);
    PKCS7_set_content(p7, PKCS7_DATA, apk_bio);
    BIO_free(apk_bio);

    // Sign PKCS#7 data
    if (!PKCS7_sign(p7, pkey, certs, NULL, PKCS7_BINARY)) {
        printf("Error: failed to sign PKCS#7 data.\n");
        sk_X509_pop_free(certs, X509_free);
        PKCS7_SIGNER_INFO_free(si);
        PKCS7_free(p7);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 1;
    }

    // Write signed data to output file
    FILE *out_fp = fopen("signed.apk", "wb");
    if (!out_fp) {
        printf("Error: failed to open output file for writing.\n");
        sk_X509_pop_free(certs, X509_free);
        PKCS7_SIGNER_INFO_free(si);
        PKCS7_free(p7);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        sk_X509_pop_free(ca, X509_free);
        return 1;
    }
    i2d_PKCS7_fp(out_fp, p7);
    fclose(out_fp);

    // Clean up
    sk_X509_pop_free(certs, X509_free);
    PKCS7_SIGNER_INFO_free(si);
    PKCS7_free(p7);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    sk_X509_pop_free(ca, X509_free);
    return 0;
}
