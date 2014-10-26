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
 *  jose.h
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 *
 */

#ifndef ___JOSE_LUA___
#define ___JOSE_LUA___

// sys
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
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
// lua
#include <lua.h>
#include <lauxlib.h>
#include "base64mix.h"

// memory alloc/dealloc
#define palloc(t)       (t*)malloc( sizeof(t) )
#define pnalloc(n,t)    (t*)malloc( (n) * sizeof(t) )
#define pcalloc(n,t)    (t*)calloc( n, sizeof(t) )
#define prealloc(n,t,p) (t*)realloc( p, (n) * sizeof(t) )
#define pdealloc(p)     (p ? free((void*)p) : NULL)

// helper macros for lua_State
#define lstate_setmetatable(L,tname) \
    (luaL_getmetatable(L,tname),lua_setmetatable(L,-2))

#define lstate_ref(L,idx) \
    (lua_pushvalue(L,idx),luaL_ref( L, LUA_REGISTRYINDEX ))

#define lstate_isref(ref) \
    ((ref) > 0)

#define lstate_pushref(L,ref) \
    lua_rawgeti( L, LUA_REGISTRYINDEX, ref )

#define lstate_unref(L,ref) \
    luaL_unref( L, LUA_REGISTRYINDEX, ref )

#define lstate_fn2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushcfunction(L,v); \
    lua_rawset(L,-3); \
}while(0)

#define lstate_str2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushstring(L,v); \
    lua_rawset(L,-3); \
}while(0)

#define lstate_num2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushnumber(L,v); \
    lua_rawset(L,-3); \
}while(0)


// define module names
#define JOSE_HMAC_MT    "jose.hmac"
#define JOSE_RSA_MT     "jose.rsa"

// define prototypes
LUALIB_API int luaopen_jose_lib( lua_State *L );
LUALIB_API int luaopen_jose_hex( lua_State *L );
LUALIB_API int luaopen_jose_base64( lua_State *L );
LUALIB_API int luaopen_jose_digest( lua_State *L );
LUALIB_API int luaopen_jose_hmac( lua_State *L );
LUALIB_API int luaopen_jose_rsa( lua_State *L );


// metanames
// module definition register
static inline int jose_define_mt( lua_State *L, const char *tname, 
                                  struct luaL_Reg mmethod[], 
                                  struct luaL_Reg method[] )
{
    struct luaL_Reg *ptr = mmethod;
    
    // create table __metatable
    luaL_newmetatable( L, tname );
    // metamethods
    do {
        lstate_fn2tbl( L, ptr->name, ptr->func );
        ptr++;
    } while( ptr->name );
    // methods
    lua_pushstring( L, "__index" );
    lua_newtable( L );
    ptr = method;
    do {
        lstate_fn2tbl( L, ptr->name, ptr->func );
        ptr++;
    } while( ptr->name );
    lua_rawset( L, -3 );
    lua_pop( L, 1 );

    return 1;
}

// common metamethods
#define jose_tostring(L,tname) ({ \
    lua_pushfstring( L, tname ": %p", lua_touserdata( L, 1 ) ); \
    1; \
})


// helper functions
// check NID type
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


// MARK: hex string
#define JOSE_MAX_DIGEST_HEX_SIZE    EVP_MAX_MD_SIZE*2+1

// dest length must be greater than len*2 + 1(null-term)
static inline void jose_hexencode( unsigned char *dest, unsigned char *src, 
                                   size_t len )
{
    static const char dec2hex[16] = "0123456789abcdef";
	unsigned char *ptr = dest;
	size_t i = 0;
	
    for(; i < len; i++ ){
		*ptr++ = dec2hex[src[i] >> 4];
		*ptr++ = dec2hex[src[i] & 0xf];
	}
	*ptr = 0;
}

// src length must be multiple of two
// dest length must be greater than len/2 + 1(null-term)
static inline int jose_hexdecode( unsigned char *dest, unsigned char *src, 
                                  size_t len )
{
    static const char hex2dec[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
    //  0  1  2  3  4  5  6  7  8  9
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 
    //  A   B   C   D   E   F
        10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
    //  a   b   c   d   e   f
        10, 11, 12, 13, 14, 15
    };
	unsigned char *ptr = dest;
	size_t i = 0;
	
    // invalid length
    if( len % 2 ){
        errno = EINVAL;
        return -1;
    }
    
	for(; i < len; i += 2 ){
        *ptr++ = hex2dec[src[i]] << 4 | hex2dec[src[i+1]];
	}
	*ptr = 0;
    
    return 0;
}

// MARK: digest
// return error sting
static inline const char *jose_digest( unsigned char *dest, size_t *dlen, 
                                       const char *msg, size_t len, 
                                       const EVP_MD *md )
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    
    if( ctx )
    {
        if( EVP_DigestInit_ex( ctx, md, NULL ) && 
            EVP_DigestUpdate( ctx, msg, len ) &&
            EVP_DigestFinal_ex( ctx, dest, (unsigned int*)dlen ) ){
            EVP_MD_CTX_destroy( ctx );
            return NULL;
        }
        EVP_MD_CTX_destroy( ctx );
    }
    
    // return error string
    return ERR_error_string( ERR_get_error(), NULL );
}

// MARK: hmac
static inline void jose_hmac( unsigned char *dest, size_t *dlen, 
                              const char *key, size_t klen, 
                              const char *msg, size_t len, 
                              const EVP_MD *md )
{
    HMAC_CTX ctx;
    
    HMAC_CTX_init( &ctx );
    HMAC_Init( &ctx, (const void*)key, (int)klen, md );
    HMAC_Update( &ctx, (unsigned char*)msg, (int)len );
    HMAC_CTX_set_flags( &ctx, EVP_MD_CTX_FLAG_ONESHOT);
    HMAC_Final( &ctx, dest, (unsigned int*)dlen );
    HMAC_CTX_cleanup( &ctx );
}

#endif
