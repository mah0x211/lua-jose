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
 *  hmac.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/23.
 *
 */

#include "jose_hmac.h"

#define MODULE_MT   JOSE_HMAC_MT


static int final_lua( lua_State *L )
{
    jose_hmac_t *j = luaL_checkudata( L, 1, MODULE_MT );
    jose_fmt_e fmt = jose_check_validfmt( L, 2, JOSE_FMT_HEX );
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t len = 0;
    
    // check format type
    if( fmt == JOSE_FMT_INVAL ){
        lua_pushnil( L );
        lua_pushstring( L, "invalid format type" );
        return 2;
    }
    else if( jose_hmac_final( j, digest, &len ) != 1 ){
        lua_pushnil( L );
        jose_push_sslerror( L );
        return 2;
    }
    else if( jose_pushfmtstr( L, fmt, digest, len ) == -1 ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    return 1;
}


static int update_lua( lua_State *L )
{
    jose_hmac_t *j = luaL_checkudata( L, 1, MODULE_MT );
    size_t len = 0;
    const char *msg = luaL_checklstring( L, 2, &len );
    
    if( EVP_DigestSignUpdate( j->ctx, msg, (unsigned int)len ) != 1 ){
        lua_pushboolean( L, 0 );
        jose_push_sslerror( L );
        return 2;
    }

    lua_pushboolean( L, 1 );
    
    return 1;
}


static int tostring_lua( lua_State *L )
{
    return jose_tostring( L, MODULE_MT );
}


static int gc_lua( lua_State *L )
{
    jose_hmac_t *j = lua_touserdata( L, 1 );
    
    EVP_MD_CTX_destroy( j->ctx );
    
    return 0;
}


static int alloc_lua( lua_State *L )
{
    const char *name = luaL_checkstring( L, 1 );
    size_t len = 0;
    const char *key = luaL_checklstring( L, 2, &len );
    const EVP_MD *md = EVP_get_digestbyname( name );
    EVP_PKEY *pk = NULL;
    jose_hmac_t *j = NULL;
    
    if( !md ){
        lua_pushnil( L );
        lua_pushfstring( L, "unsupported digest algorithm: %s", name );
        return 2;
    }
    else if( !( j = lua_newuserdata( L, sizeof( jose_hmac_t ) ) ) ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }
    else if( !( j->ctx = EVP_MD_CTX_create() ) ){
        lua_pushnil( L );
        jose_push_sslerror( L );
        return 2;
    }
    else if( !( pk = EVP_PKEY_new_mac_key( EVP_PKEY_HMAC, NULL, 
                                           (const unsigned char*)key, len ) ) ){
        EVP_MD_CTX_destroy( j->ctx );
        lua_pushnil( L );
        jose_push_sslerror( L );
        return 2;
    }
    else if( EVP_DigestSignInit( j->ctx, NULL, md, NULL, pk ) != 1 ){
        EVP_PKEY_free( pk );
        EVP_MD_CTX_destroy( j->ctx );
        lua_pushnil( L );
        jose_push_sslerror( L );
        return 2;
    }
    
    luaL_getmetatable( L, MODULE_MT );
    lua_setmetatable( L, -2 );
    
    return 1;
}


static int gen_lua( lua_State *L )
{
    const char *name = luaL_checkstring( L, 1 );
    size_t klen = 0;
    const char *key = luaL_checklstring( L, 2, &klen );
    size_t len = 0;
    const char *msg = luaL_checklstring( L, 3, &len );
    jose_fmt_e fmt = jose_check_validfmt( L, 4, JOSE_FMT_HEX );
    const EVP_MD *md = EVP_get_digestbyname( name );
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t dlen = 0;
    
    // invalid format type
    if( fmt == JOSE_FMT_INVAL ){
        lua_pushnil( L );
        lua_pushstring( L, "invalid format type" );
        return 2;
    }
    else if( !md ){
        lua_pushnil( L );
        lua_pushfstring( L, "unsupported digest algorithm: %s", name );
        return 2;
    }
    else if( jose_hmac( digest, &dlen, key, klen, msg, len, md ) != 1 ){
        lua_pushnil( L );
        jose_push_sslerror( L );
        return 2;
    }
    else if( jose_pushfmtstr( L, fmt, digest, dlen ) == -1 ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }

    return 1;
}


LUALIB_API int luaopen_jose_hmac( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "update", update_lua },
        { "final", final_lua },
        { NULL, NULL }
    };
    
    jose_define_mt( L, MODULE_MT, mmethod, method );
    
    lua_createtable( L, 0, 2 );
    lstate_fn2tbl( L, "new", alloc_lua );
    lstate_fn2tbl( L, "gen", gen_lua );
    
    return 1;
}


