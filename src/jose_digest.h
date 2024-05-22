/**
 *  Copyright 2014 Masatoshi Teruya. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 *
 *  jose_digest.h
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/27.
 */

#ifndef ___JOSE_DIGEST_LUA___
#define ___JOSE_DIGEST_LUA___

#include "jose_ssl.h"

#define JOSE_DIGEST_MT "jose.digest"

typedef struct {
    EVP_MD_CTX *ctx;
    EVP_PKEY *pk;
    const EVP_MD *md;
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t len;
} jose_digest_t;

// return 1 on success, <1 on failure
static inline int jose_digest_final(jose_digest_t *j, unsigned char *dest,
                                    size_t *dlen)
{
    return EVP_DigestFinal_ex(j->ctx, dest, (unsigned int *)dlen);
}

// return 1 on success, <1 on failure
static inline int jose_digest(unsigned char *dest, size_t *dlen,
                              const char *msg, size_t len, const EVP_MD *md)
{
    int rc          = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

    if (ctx) {
        if ((rc = EVP_DigestInit_ex(ctx, md, NULL)) == 1 &&
            (rc = EVP_DigestUpdate(ctx, msg, len)) == 1) {
            rc = EVP_DigestFinal_ex(ctx, dest, (unsigned int *)dlen);
        }
        EVP_MD_CTX_destroy(ctx);
    }

    // return error string
    return rc;
}

#endif
