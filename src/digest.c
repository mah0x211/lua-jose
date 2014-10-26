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
 *  digest.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 *
 */

#include "jose.h"


static int digest_lua( lua_State *L, const EVP_MD *md )
{
    int argc = lua_gettop( L );
    size_t len = 0;
    const char *src = luaL_checklstring( L, 1, &len );
    unsigned char dest[EVP_MAX_MD_SIZE];
    size_t dlen = 0;
    const char *errstr = NULL;
    
    // check argument
    if( argc > 1 ){
        size_t klen = 0;
        const char *key = luaL_checklstring( L, 2, &klen );
        jose_hmac( dest, &dlen, key, klen, src, len, md );
    }
    else {
        errstr = jose_digest( dest, &dlen, src, len, md );
    }
    
    if( !errstr )
    {
        const char *buf = NULL;
        
        len = dlen * 2;
        if( ( buf = pnalloc( len + 1, const char ) ) ){
            jose_hexencode( (unsigned char*)buf, dest, dlen );
            lua_pushlstring( L, buf, len );
            pdealloc( buf );
            return 1;
        }
        // alloc error
        errstr = strerror( errno );
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, errstr );
    
    return 2;
}

static int sha1_lua( lua_State *L ){
    return digest_lua( L, EVP_sha1() );
}
static int sha224_lua( lua_State *L ){
    return digest_lua( L, EVP_sha224() );
}
static int sha256_lua( lua_State *L ){
    return digest_lua( L, EVP_sha256() );
}
static int sha384_lua( lua_State *L ){
    return digest_lua( L, EVP_sha384() );
}
static int sha512_lua( lua_State *L ){
    return digest_lua( L, EVP_sha512() );
}


LUALIB_API int luaopen_jose_digest( lua_State *L )
{
    lua_newtable( L );
    lstate_fn2tbl( L, "sha1", sha1_lua );
    lstate_fn2tbl( L, "sha224", sha224_lua );
    lstate_fn2tbl( L, "sha256", sha256_lua );
    lstate_fn2tbl( L, "sha384", sha384_lua );
    lstate_fn2tbl( L, "sha512", sha512_lua );
    
    return 1;
}




