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
 *  hmac.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/23.
 *
 */

#include "jose.h"

typedef struct {
    EVP_MD *md;
    const char *key;
    size_t len;
} jose_hmac_t;


static int verify_lua( lua_State *L )
{
    jose_hmac_t *j = luaL_checkudata( L, 1, JOSE_HMAC_MT );
    size_t len = 0;
    const char *msg = luaL_checklstring( L, 2, &len );
    size_t slen = 0;
    const char *sig = luaL_checklstring( L, 3, &slen );
    unsigned char *bin = (unsigned char*)b64m_decode_url( (unsigned char*)sig, &slen );
    
    if( bin ){
        unsigned char digest[EVP_MAX_MD_SIZE];
        size_t dlen = 0;
        
        jose_hmac( digest, &dlen, j->key, j->len, msg, len, j->md );
        lua_pushboolean( L, memcmp( digest, bin, slen ) == 0 );
        pdealloc( bin );
        
        return 1;
    }
    
    // got error
    lua_pushboolean( L, 0 );
    lua_pushstring( L, strerror( errno ) );
    
    return 2;
}


static int sign_lua( lua_State *L )
{
    jose_hmac_t *j = luaL_checkudata( L, 1, JOSE_HMAC_MT );
    size_t len = 0;
    const char *msg = luaL_checklstring( L, 2, &len );
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t dlen = 0;
    const char *b64 = NULL;
    
    // check argument
    jose_hmac( digest, &dlen, j->key, j->len, msg, len, j->md );
    if( ( b64 = b64m_encode_url( digest, &dlen ) ) ){
        lua_pushstring( L, b64 );
        pdealloc( b64 );
        return 1;
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, strerror( errno ) );
    
    return 2;
}


static int tostring_lua( lua_State *L )
{
    return jose_tostring( L, JOSE_HMAC_MT );
}


static int gc_lua( lua_State *L )
{
    jose_hmac_t *j = lua_touserdata( L, 1 );
    
    pdealloc( j->key );
    
    return 0;
}


static int alloc_lua( lua_State *L )
{
    int nid = luaL_checkint( L, 1 );
    size_t len = 0;
    const char *key = luaL_checklstring( L, 2, &len );
    const char *errstr = "unsupported NID type";
    
    if( ( nid = jose_nid2rsa_nid( nid ) ) != -1 )
    {
        const EVP_MD *md = jose_nid2evp_md( nid );
        
        if( md )
        {
            jose_hmac_t *j = lua_newuserdata( L, sizeof( jose_hmac_t ) );
            
            if( j && ( j->key = pnalloc( len + 1, const char ) ) ){
                memcpy( (void*)j->key, key, len );
                ((char*)j->key)[len] = 0;
                j->len = len;
                j->md = (EVP_MD*)md;
                luaL_getmetatable( L, JOSE_HMAC_MT );
                lua_setmetatable( L, -2 );
                return 1;
            }
            else {
                errstr = strerror( errno );
            }
        }
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, errstr );
    
    return 2;
}


LUALIB_API int luaopen_jose_hmac( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "sign", sign_lua },
        { "verify", verify_lua },
        { NULL, NULL }
    };
    
    jose_define_mt( L, JOSE_HMAC_MT, mmethod, method );
    // add allocation method
    lua_pushcfunction( L, alloc_lua );
    
    return 1;
}


