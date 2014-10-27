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

#define lstate_strn2tbl(L,k,v,n) do{ \
    lua_pushstring(L,k); \
    lua_pushlstring(L,v,n); \
    lua_rawset(L,-3); \
}while(0)

#define lstate_num2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushnumber(L,v); \
    lua_rawset(L,-3); \
}while(0)


// define module names
#define JOSE_BUFFER_MT  "jose.buffer"
#define JOSE_DIGEST_MT  "jose.digest"
#define JOSE_HMAC_MT    "jose.hmac"
#define JOSE_RSA_MT     "jose.rsa"

// MARK: define prototypes
LUALIB_API int luaopen_jose_lib( lua_State *L );
LUALIB_API int luaopen_jose_buffer( lua_State *L );
LUALIB_API int luaopen_jose_hex( lua_State *L );
LUALIB_API int luaopen_jose_base64( lua_State *L );
LUALIB_API int luaopen_jose_digest( lua_State *L );
LUALIB_API int luaopen_jose_hmac( lua_State *L );
LUALIB_API int luaopen_jose_rsa( lua_State *L );
LUALIB_API int luaopen_jose_generate( lua_State *L );


// MARK: helper functions

// metanames
// module definition register
static inline int jose_define_method( lua_State *L, struct luaL_Reg method[] )
{
    struct luaL_Reg *ptr = method;
    
    // methods
    lua_newtable( L );
    do {
        lstate_fn2tbl( L, ptr->name, ptr->func );
        ptr++;
    } while( ptr->name );
    
    return 1;
}

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
    jose_define_method( L, method );
    lua_rawset( L, -3 );
    lua_pop( L, 1 );

    return 1;
}

// common metamethods
#define jose_tostring(L,tname) ({ \
    lua_pushfstring( L, tname ": %p", lua_touserdata( L, 1 ) ); \
    1; \
})


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
static inline int jose_hexdecode( char *dest, unsigned char *src, size_t len )
{
    static const char hex2dec[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
    //  0  1  2  3  4  5  6  7  8  9
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 
    //  A   B   C   D   E   F
        10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
    //  a   b   c   d   e   f
        10, 11, 12, 13, 14, 15,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
        -1, -1, -1, -1, -1, -1, -1, -1, -1
    };
    char *ptr = dest;
	size_t i = 0;
	
    // invalid length
    if( len % 2 ){
        errno = EINVAL;
        return -1;
    }
    
	for(; i < len; i += 2 )
    {
        if( hex2dec[src[i]] == -1 || hex2dec[src[i+1]] == -1 ){
            errno = EINVAL;
            return -1;
        }
        *ptr++ = hex2dec[src[i]] << 4 | hex2dec[src[i+1]];
	}
	*ptr = 0;
    
    return 0;
}

// MARK: push format string
// format types
typedef enum {
    JOSE_FMT_INVAL      = -1,
    JOSE_FMT_RAW        = 0,
    // default
    JOSE_FMT_HEX        = 1,
    JOSE_FMT_BASE64,
    JOSE_FMT_BASE64URL,
} jose_fmt_e;

static inline jose_fmt_e jose_check_validfmt( lua_State *L, int idx, 
                                              jose_fmt_e fmt )
{
    // check format type
    if( lua_gettop( L ) > ( idx - 1 ) && !lua_isnil( L, idx ) )
    {
        fmt = luaL_checkint( L, idx );
        if( fmt < JOSE_FMT_HEX || fmt > JOSE_FMT_BASE64URL ){
            return JOSE_FMT_INVAL;
        }
    }

    return fmt;
}

// return 0 on success, -1 on failure
static inline int jose_pushhex( lua_State *L, unsigned char *data, size_t len )
{
    // hex encoding
    size_t bytes = len * 2;
    const char *buf = pnalloc( bytes + 1, const char );
    
    // alloc error
    if( !buf ){
        return -1;
    }
    jose_hexencode( (unsigned char*)buf, data, len );
    lua_pushlstring( L, buf, bytes );
    pdealloc( buf );
    
    return 0;
}

// return 0 on success, -1 on failure
static inline int jose_pushbase64( lua_State *L, unsigned char *data, 
                                   size_t len )
{
    // base64 encoding
    char *buf = b64m_encode_std( data, &len );
    
    // alloc error
    if( !buf ){
        return -1;
    }
    
    lua_pushlstring( L, buf, len );
    pdealloc( buf );
    
    return 0;
}

static inline int jose_pushbase64url( lua_State *L, unsigned char *data, 
                                      size_t len )
{
    // base64url encoding
    char *buf = b64m_encode_url( data, &len );
    
    // alloc error
    if( !buf ){
        return -1;
    }
    
    lua_pushlstring( L, buf, len );
    pdealloc( buf );
    
    return 0;
}

static inline int jose_pushfmtstr( lua_State *L, jose_fmt_e fmt,
                                   unsigned char *data, size_t len )
{
    switch( fmt ){
        case JOSE_FMT_RAW:
            lua_pushlstring( L, (const char*)data, len );
            return 0;
        case JOSE_FMT_HEX:
            return jose_pushhex( L, data, len );
        case JOSE_FMT_BASE64:
            return jose_pushbase64( L, data, len );
        case JOSE_FMT_BASE64URL:
            return jose_pushbase64url( L, data, len );
        default:
            errno = EINVAL;
            return -1;
    }
}

#endif
