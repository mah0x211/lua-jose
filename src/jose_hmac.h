/*
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
 *  jose_hmac.h
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/23.
 *
 */

#ifndef ___JOSE_HMAC_LUA___
#define ___JOSE_HMAC_LUA___

#include "jose.h"

typedef struct {
    EVP_MD_CTX *ctx;
    EVP_PKEY *pk;
} jose_hmac_t;


// return 1 on success, <1 on failure
static inline int jose_hmac_final( jose_hmac_t *j, unsigned char *dest, 
                                   size_t *dlen )
{
    return EVP_DigestSignFinal( j->ctx, dest, dlen );
}


// return 1 on success, <1 on failure
static inline int jose_hmac( unsigned char *sig, size_t *slen, 
                             const char *key, size_t klen, 
                             const char *msg, unsigned int len, 
                             const EVP_MD *md )
{
    int rc = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    
    if( ctx )
    {
        EVP_PKEY *pk = EVP_PKEY_new_mac_key( EVP_PKEY_HMAC, NULL, 
                                             (const unsigned char*)key, klen );
        if( pk )
        {
            if( ( rc = EVP_DigestSignInit( ctx, NULL, md, NULL, pk ) ) == 1 &&
                ( rc = EVP_DigestSignUpdate( ctx, msg, len ) ) == 1 ){
                rc = EVP_DigestSignFinal( ctx, sig, slen );
            }
            EVP_PKEY_free( pk );
        }
        
        EVP_MD_CTX_destroy( ctx );
    }
    
    return rc;
}

#endif



