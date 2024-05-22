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
 *  jose_ssl.h
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/11/02.
 */

#ifndef ___JOSE_SSL_LUA___
#define ___JOSE_SSL_LUA___

#include "jose_util.h"
// openssl
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

// MARK: helper functions

static inline void jose_push_sslerror(lua_State *L)
{
    SSL_load_error_strings();
    lua_pushstring(L, ERR_error_string(ERR_get_error(), NULL));
    ERR_free_strings();
}

// password index = idx + 1
static inline int jose_getopt_cipher(lua_State *L, int idx, const char **name,
                                     const EVP_CIPHER **ciph, const char **pswd,
                                     size_t *len)
{
    *name = luaL_optstring(L, idx, NULL);
    if (*name) {
        *ciph = EVP_get_cipherbyname(*name);
        if (!*ciph) {
            return -1;
        }
        // password required
        *pswd = luaL_checklstring(L, idx + 1, len);
    }

    return 0;
}

#endif
