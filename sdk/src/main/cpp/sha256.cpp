/*
 * Copyright 2025 AppProtectionSDK
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <openssl/sha.h>
#include <string.h>

// Simple SHA-256 implementation
static const unsigned int K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

int SHA256_Init(SHA256_CTX *c) {
    if (c == NULL) return 0;
    
    c->h[0] = 0x6a09e667;
    c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372;
    c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f;
    c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab;
    c->h[7] = 0x5be0cd19;
    
    c->Nl = 0;
    c->Nh = 0;
    c->num = 0;
    
    return 1;
}

static void SHA256_Transform(SHA256_CTX *c, const unsigned char *data) {
    unsigned int a, b, d, e, f, g, h, i, j, t1, t2, m[64];
    
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
    
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    
    a = c->h[0];
    b = c->h[1];
    unsigned int c_temp = c->h[2];
    d = c->h[3];
    e = c->h[4];
    f = c->h[5];
    g = c->h[6];
    h = c->h[7];
    
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c_temp);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c_temp;
        c_temp = b;
        b = a;
        a = t1 + t2;
    }
    
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += c_temp;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

int SHA256_Update(SHA256_CTX *c, const void *data, size_t len) {
    if (c == NULL || data == NULL) return 0;
    
    const unsigned char *p = (const unsigned char *)data;
    unsigned int l;
    
    if (len == 0) return 1;
    
    l = (c->Nl + (((unsigned int)len) << 3)) & 0xffffffffUL;
    if (l < c->Nl) c->Nh++;
    c->Nh += (unsigned int)(len >> 29);
    c->Nl = l;
    
    if (c->num != 0) {
        unsigned int n = 64 - c->num;
        
        if (len < n) {
            memcpy(c->data + c->num, p, len);
            c->num += (unsigned int)len;
            return 1;
        } else {
            memcpy(c->data + c->num, p, n);
            SHA256_Transform(c, c->data);
            p += n;
            len -= n;
            c->num = 0;
        }
    }
    
    while (len >= 64) {
        SHA256_Transform(c, p);
        p += 64;
        len -= 64;
    }
    
    if (len != 0) {
        memcpy(c->data, p, len);
        c->num = (unsigned int)len;
    }
    
    return 1;
}

int SHA256_Final(unsigned char *md, SHA256_CTX *c) {
    if (c == NULL || md == NULL) return 0;
    
    unsigned char *p = c->data;
    unsigned int n = c->num;
    
    p[n] = 0x80;
    n++;
    
    if (n > 56) {
        memset(p + n, 0, 64 - n);
        SHA256_Transform(c, p);
        n = 0;
    }
    
    memset(p + n, 0, 56 - n);
    
    p[56] = (unsigned char)(c->Nh >> 24);
    p[57] = (unsigned char)(c->Nh >> 16);
    p[58] = (unsigned char)(c->Nh >> 8);
    p[59] = (unsigned char)(c->Nh);
    p[60] = (unsigned char)(c->Nl >> 24);
    p[61] = (unsigned char)(c->Nl >> 16);
    p[62] = (unsigned char)(c->Nl >> 8);
    p[63] = (unsigned char)(c->Nl);
    
    SHA256_Transform(c, p);
    
    for (n = 0; n < 8; n++) {
        md[4 * n] = (unsigned char)(c->h[n] >> 24);
        md[4 * n + 1] = (unsigned char)(c->h[n] >> 16);
        md[4 * n + 2] = (unsigned char)(c->h[n] >> 8);
        md[4 * n + 3] = (unsigned char)(c->h[n]);
    }
    
    return 1;
} 