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
 *  lib.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 *
 */

#include "jose.h"
#include <ctype.h>


static inline void nameconv( char *dest, const char *src, size_t len )
{
    size_t i = 0;
    
    // name conversion
    for(; i < len; i++ )
    {
        // hyphen to underscore
        if( src[i] == '-' ){
            dest[i] = '_';
        }
        // lower to uppercase
        else {
            dest[i] = toupper( src[i] );
        }
    }
    dest[len] = 0;
}


static inline void add_name( const char *from, const char *to, void *arg )
{
    if( !to ){
        lua_State *L = (lua_State*)arg;
        static char fname[255];
        
        nameconv( fname, from, strlen( from ) );
        lstate_str2tbl( L, fname, from );
    }
}

static void add_cipher_name( const EVP_CIPHER *ciph, const char *from, 
                             const char *to, void *arg ){
    add_name( from, to, arg );
}

static void add_digest_name( const EVP_MD *md, const char *from, const char *to,
                             void *arg ){
    add_name( from, to, arg );
}

static int constants_lua( lua_State *L )
{
    // constants
    lua_newtable( L );
    
    // add cipher names
    lua_newtable( L );
    EVP_CIPHER_do_all_sorted( add_cipher_name, (void*)L );
    lua_setfield( L, -2, "CIPHER" );
    // add digest names
    lua_newtable( L );
    EVP_MD_do_all_sorted( add_digest_name, (void*)L );
    lua_setfield( L, -2, "DIGEST" );
    
    // add result format
    lstate_num2tbl( L, "FMT_RAW", JOSE_FMT_RAW );
    lstate_num2tbl( L, "FMT_HEX", JOSE_FMT_HEX );
    lstate_num2tbl( L, "FMT_BASE64", JOSE_FMT_BASE64 );
    lstate_num2tbl( L, "FMT_BASE64URL", JOSE_FMT_BASE64URL );
    lua_setfield( L, -2, "constants" );
    
    return 1;
}

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
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    //ENGINE_load_builtin_engines();
    //ENGINE_register_all_complete();
    //OPENSSL_config( NULL );
    
    lua_newtable( L );
    // rsa
    luaopen_jose_rsa( L );
    lua_setfield( L, -2, "rsa" );
    // key-pair generator
    luaopen_jose_generate( L );
    lua_setfield( L, -2, "generate" );
    // cleanup function
    lstate_fn2tbl( L, "dispose", dispose_lua );
    
    // append constants
    return constants_lua( L );
}


