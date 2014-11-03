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
 *  jose.h
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 *
 */

#ifndef ___JOSE_LUA___
#define ___JOSE_LUA___

// openssl
#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>


#include "jose_util.h"

// define module names
#define JOSE_BUFFER_MT  "jose.buffer"
#define JOSE_DIGEST_MT  "jose.digest"
#define JOSE_PKEY_MT    "jose.pkey"
#define JOSE_RSA_MT     "jose.rsa"

// MARK: define prototypes
LUALIB_API int luaopen_jose_lib( lua_State *L );
LUALIB_API int luaopen_jose_buffer( lua_State *L );
LUALIB_API int luaopen_jose_hex( lua_State *L );
LUALIB_API int luaopen_jose_base64( lua_State *L );
LUALIB_API int luaopen_jose_digest( lua_State *L );
LUALIB_API int luaopen_jose_pkey( lua_State *L );
LUALIB_API int luaopen_jose_rsa( lua_State *L );
LUALIB_API int luaopen_jose_generate( lua_State *L );




static inline void jose_push_sslerror( lua_State *L )
{
    SSL_load_error_strings();
    lua_pushstring( L, ERR_error_string( ERR_get_error(), NULL ) );
    ERR_free_strings();
}


// check NID type
typedef enum {
    JOSE_NID_SHA256 = 256,
    JOSE_NID_SHA384 = 384,
    JOSE_NID_SHA512 = 512
} jose_nid_e;


static inline int jose_nid2rsa_nid( jose_nid_e nid )
{
    switch( nid ){
        case JOSE_NID_SHA256:
            return NID_sha256;
        case JOSE_NID_SHA384:
            return NID_sha384;
        case JOSE_NID_SHA512:
            return NID_sha512;
        // unsupported NID type
        default:
            return -1;
    }
}

static inline const EVP_MD *jose_nid2evp_md( const int nid )
{
    switch( nid ){
        case NID_sha1:
            return EVP_sha1();
        case NID_sha224:
            return EVP_sha224();
        case NID_sha256:
            return EVP_sha256();
        case NID_sha384:
            return EVP_sha384();
        case NID_sha512:
            return EVP_sha512();
        break;
        // unsupported NID type
        default:
            return NULL;
    }
}


// password index = idx + 1
static inline int jose_getopt_cipher( lua_State *L, int idx,
                                      const char **name,
                                      const EVP_CIPHER **ciph,
                                      const char **pswd, size_t *len )
{
    *name = luaL_optstring( L, idx, NULL );
    if( *name )
    {
        *ciph = EVP_get_cipherbyname( *name );
        if( !*ciph ){
            return -1;
        }
        // password required
        *pswd = luaL_checklstring( L, idx + 1, len );
    }
    
    return 0;
}


#endif
