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
 *  jose_pkey.h
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/27.
 *
 */

#ifndef ___JOSE_PKEY_LUA___
#define ___JOSE_PKEY_LUA___

#include "jose_ssl.h"

#define JOSE_PKEY_MT    "jose.pkey"

typedef struct {
    EVP_PKEY *pk;
} jose_pkey_t;


static inline int jose_rsa_has_privatekey( RSA *rsa ){
    return ( rsa->p && rsa->q ) ? 1 : 0;
}
static inline int jose_dsa_has_privatekey( DSA *dsa ){ 
    return ( dsa->priv_key ) ? 1 : 0;
}
static inline int jose_pkey_has_privatekey( EVP_PKEY *pk )
{
    switch( EVP_PKEY_type( pk->type ) ){
        case EVP_PKEY_RSA:
            return jose_rsa_has_privatekey( EVP_PKEY_get1_RSA( pk ) );
        break;
        case EVP_PKEY_DSA:
            return jose_dsa_has_privatekey( EVP_PKEY_get1_DSA( pk ) );
        break;
        default:
            return 0;
    }
}


#endif



