#ifndef OPENSSL_SHA_H
#define OPENSSL_SHA_H

#include <stddef.h> // For size_t definition

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_LENGTH 32

typedef struct SHA256state_st {
    unsigned int h[8];
    unsigned int Nl, Nh;
    unsigned char data[64];
    unsigned int num;
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_SHA_H */ 