#include <openssl/evp.h>

int sha256(const unsigned char *data, size_t size, unsigned char *hash) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, size);
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_free(mdctx);

    return md_len;
}
