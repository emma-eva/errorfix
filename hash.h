#ifndef HASH_H
#define HASH_H

#include <openssl/sha.h>

void sha256(const unsigned char *data, size_t data_len, unsigned char *hash);

#endif
