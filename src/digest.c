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
 *  digest.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 *
 */

#include "jose_digest.h"
#include "jose_bin.h"

#define MODULE_MT   JOSE_DIGEST_MT


#define DIGEST_FINAL(j) \
    (j->pk ? \
    EVP_DigestSignFinal( j->ctx, j->digest, &j->len ) : \
    EVP_DigestFinal_ex( j->ctx, j->digest, (unsigned int*)&j->len ) )


static int final_lua( lua_State *L )
{
    jose_digest_t *j = luaL_checkudata( L, 1, MODULE_MT );
    char *data = NULL;
    
    if( !j->len && DIGEST_FINAL( j ) != 1 ){
        lua_pushnil( L );
        jose_push_sslerror( L );
        return 2;
    }
    else if( !( data = pnalloc( j->len + 1, char ) ) ||
             !jose_bin_alloc( L, data, j->len ) )
    {
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        if( data ){
            pdealloc( data );
        }
        return 2;
    }
    
    memcpy( data, j->digest, j->len );
    data[j->len] = 0;
    
    return 1;
}


static int update_lua( lua_State *L )
{
    jose_digest_t *j = luaL_checkudata( L, 1, MODULE_MT );
    size_t len = 0;
    const char *msg = luaL_checklstring( L, 2, &len );
    
    if( EVP_DigestUpdate( j->ctx, msg, len ) != 1 ){
        lua_pushboolean( L, 0 );
        jose_push_sslerror( L );
        return 2;
    }

    lua_pushboolean( L, 1 );
    
    return 1;
}


static int reset_lua( lua_State *L )
{
    jose_digest_t *j = luaL_checkudata( L, 1, MODULE_MT );
    
    if( j->pk )
    {
        if( EVP_DigestSignInit( j->ctx, NULL, j->md, NULL, j->pk ) != 1 ){
            lua_pushboolean( L, 0 );
            jose_push_sslerror( L );
            return 2;
        }
    }
    else if( !( EVP_DigestInit_ex( j->ctx, j->md, NULL ) ) ){
        lua_pushboolean( L, 0 );
        jose_push_sslerror( L );
        return 2;
    }
    
    j->len = 0;
    lua_pushboolean( L, 1 );
    return 1;
}


static int tostring_lua( lua_State *L )
{
    return jose_tostring( L, MODULE_MT );
}


static int gc_lua( lua_State *L )
{
    jose_digest_t *j = lua_touserdata( L, 1 );
    
    EVP_MD_CTX_destroy( j->ctx );
    if( j->pk ){
        EVP_PKEY_free( j->pk );
    }
    
    return 0;
}


static int alloc_lua( lua_State *L )
{
    const char *name = luaL_checkstring( L, 1 );
    size_t klen = 0;
    const char *key = luaL_optlstring( L, 2, NULL, &klen );
    const EVP_MD *md = EVP_get_digestbyname( name );
    jose_digest_t *j = NULL;
    
    // invalid digest name
    if( !md ){
        lua_pushnil( L );
        lua_pushfstring( L, "unsupported digest algorithm: %s", name );
        return 2;
    }
    else if( !( j = lua_newuserdata( L, sizeof( jose_digest_t ) ) ) ||
             !( j->ctx = EVP_MD_CTX_create() ) ){
        lua_pushnil( L );
        lua_pushstring( L, strerror( errno ) );
        return 2;
    }
    else if( !key )
    {
        j->pk = NULL;
        if( !( EVP_DigestInit_ex( j->ctx, md, NULL ) ) ){
            lua_pushnil( L );
            jose_push_sslerror( L );
            EVP_MD_CTX_destroy( j->ctx );
            return 2;
        }
    }
    // HMAC
    else if( !( j->pk = EVP_PKEY_new_mac_key( EVP_PKEY_HMAC, NULL, 
                                              (const unsigned char*)key, 
                                              klen ) ) ){
        lua_pushnil( L );
        jose_push_sslerror( L );
        EVP_MD_CTX_destroy( j->ctx );
        return 2;
    }
    else if( EVP_DigestSignInit( j->ctx, NULL, md, NULL, j->pk ) != 1 ){
        lua_pushnil( L );
        jose_push_sslerror( L );
        EVP_MD_CTX_destroy( j->ctx );
        EVP_PKEY_free( j->pk );
        return 2;
    }
    
    j->md = md;
    j->len = 0;
    luaL_getmetatable( L, MODULE_MT );
    lua_setmetatable( L, -2 );
    
    return 1;
}


static void add_digest_name( const EVP_MD *md, const char *from, const char *to,
                             void *arg )
{
    if( !to ){
        lua_State *L = (lua_State*)arg;
        static char fname[255];
        
        jose_conv2constant_name( fname, from, strlen( from ) );
        lstate_str2tbl( L, fname, from );
    }
}


LUALIB_API int luaopen_jose_digest( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "update", update_lua },
        { "final", final_lua },
        { "reset", reset_lua },
        { NULL, NULL }
    };
    
    OpenSSL_add_all_digests();
    jose_bin_define( L );
    jose_define_mt( L, MODULE_MT, mmethod, method );
    
    lua_newtable( L );
    EVP_MD_do_all_sorted( add_digest_name, (void*)L );
    lstate_fn2tbl( L, "new", alloc_lua );
    
    return 1;
}




