#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "hash.h"
#include "pkcs7.h"
#include "zip.h"

int main(int argc, char *argv[]) {

    // Read configuration file
    Config config = {0};
    int ret = parse_config(argv[1], &config);
    if (ret != 0) {
        return ret;
    }

    // Parse command line arguments
    if (argc < 4) {
        printf("Usage: pyapksigner <config file> <APK file> <keystore file> <key alias>\n");
        return 1;
    }
    const char *apk_file = argv[2];
    const char *keystore_file = argv[3];
    const char *key_alias = argv[4];

    // Read keystore file
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

    // Compute keystore hash
    unsigned char keystore_hash[SHA256_DIGEST_LENGTH];
    sha256(keystore_data, keystore_size, keystore_hash);

    // Read APK file
    ZipFile apk_zip;
    if (!zip_file_open(&apk_zip, apk_file)) {
        printf("Error: failed to open APK file for reading.\n");
        free(keystore_data);
        return 1;
    }

    // Compute APK hash
    unsigned char apk_hash[SHA256_DIGEST_LENGTH];
    zip_compute_hash(&apk_zip, apk_hash);

    // Create PKCS7 signature
    PKCS7Signature pkcs7;
    int pkcs7_ret = pkcs7_sign(&pkcs7, keystore_data, keystore_size, key_alias, config.sections[0].options[2].value, config.sections[0].options[1].value, apk_hash, SHA256_DIGEST_LENGTH);
    free(keystore_data);
    if (pkcs7_ret != 0) {
        printf("Error: failed to create PKCS7 signature.\n");
        zip_file_close(&apk_zip);
        return 1;
    }

    // Add signature to APK
    int add_sig_ret = zip_add_signature(&apk_zip, pkcs7.signature_data, pkcs7.signature_length, keystore_hash);
    if (add_sig_ret != 0) {
        printf("Error: failed to add signature to APK file.\n");
        pkcs7_free(&pkcs7);
        zip_file_close(&apk_zip);
        return 1;
    }

    // Save signed APK to output file
    char output_file[MAX_VALUE_LEN];
    snprintf(output_file, MAX_VALUE_LEN, "%s-signed.apk", apk_file);
    int save_ret = zip_save(&apk_zip, output_file);
    if (save_ret != 0) {
        printf("Error: failed to save signed APK file.\n");
        pkcs7_free(&pkcs7);
        zip_file_close(&apk_zip);
        return 1;
    }

    // Free resources
    pkcs7_free(&pkcs7);
    zip_file_close(&apk_zip);

    return 0;
}

