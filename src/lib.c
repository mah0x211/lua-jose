/*
 *  Copyright 2014 Masatoshi Teruya. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 *  lib.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 *
 */

#include "jose.h"

static int dispose_lua( lua_State *L )
{
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    return 0;
}

LUALIB_API int luaopen_jose_lib( lua_State *L )
{
    //SSL_load_error_strings();
    //SSL_library_init();
    //OpenSSL_add_all_algorithms();
    //ENGINE_load_builtin_engines();
    //ENGINE_register_all_complete();
    //OPENSSL_config( NULL );
    
    lua_newtable( L );
    // hex
    luaopen_jose_hex( L );
    lua_setfield( L, -2, "hex" );
    // base64
    luaopen_jose_base64( L );
    lua_setfield( L, -2, "base64" );
    // digest
    luaopen_jose_digest( L );
    lua_setfield( L, -2, "digest" );
    // rsa
    luaopen_jose_rsa( L );
    lua_setfield( L, -2, "rsa" );
    // hmac
    luaopen_jose_hmac( L );
    lua_setfield( L, -2, "hmac" );
    // cleanup function
    lstate_fn2tbl( L, "dispose", dispose_lua );
    
    // constants
    // algorithms
    lstate_num2tbl( L, "SHA256", JOSE_NID_SHA256 );
    lstate_num2tbl( L, "SHA384", JOSE_NID_SHA384 );
    lstate_num2tbl( L, "SHA512", JOSE_NID_SHA512 );
    
    return 1;
}


