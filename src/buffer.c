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
 *  buffer.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/27.
 *
 */

#include "jose_buffer.h"

#define MODULE_MT   JOSE_BUFFER_MT

static int compare_lua( lua_State *L )
{
    jose_buffer_t *j = luaL_checkudata( L, 1, MODULE_MT );
    size_t len = 0;
    const char *data = luaL_checklstring( L, 2, &len );
    jose_fmt_e fmt = JOSE_FMT_RAW;
    const char *errstr = NULL;
    int cmp = 0;
    
    // check format
    if( lua_gettop( L ) > 2 && !lua_isnil( L, 3 ) ){
        fmt = luaL_checkint( L, 3 );
    }
    
    if( fmt == JOSE_FMT_RAW ){
        cmp = ( len == j->len && memcmp( data, j->data, j->len ) == 0 );
    }
    else if( fmt == JOSE_FMT_HEX )
    {
        char *buf = NULL;
        size_t blen = len;
        
        if( len % 2 ){
            errstr = "invalid data format";
        }
        // pass length
        else if( ( blen = len / 2 ) == j->len )
        {
            // allo error
            if( !( buf = pnalloc( blen, char ) ) ){
                errstr = strerror( errno );
            }
            else
            {
                if( jose_hexdecode( buf, (unsigned char *)data, len ) == -1 ){
                    errstr = strerror( errno );
                }
                else {
                    cmp = ( memcmp( buf, j->data, j->len ) == 0 );
                }
                pdealloc( buf );
            }
        }
        else {
            errstr = NULL;
        }
    }
    else if( fmt == JOSE_FMT_BASE64 || fmt == JOSE_FMT_BASE64URL )
    {
        char *buf = b64m_decode_mix( (unsigned char*)data, &len );
        
        if( !buf ){
            errstr = strerror( errno );
        }
        else {
            cmp = ( len == j->len && memcmp( buf, j->data, j->len ) == 0 );
            pdealloc( buf );
        }
    }
    else {
        errstr = "invalid format type";
    }
    
    if( errstr ){
        lua_pushboolean( L, 0 );
        lua_pushstring( L, errstr );
        return 2;
    }
    
    lua_pushboolean( L, cmp );
    return 1;
}


static int convert_lua( lua_State *L )
{
    jose_buffer_t *j = luaL_checkudata( L, 1, MODULE_MT );
    jose_fmt_e fmt = JOSE_FMT_RAW;
    
    // check format
    if( lua_gettop( L ) > 1 && !lua_isnil( L, 2 ) ){
        fmt = luaL_checkint( L, 2 );
    }
    
    if( jose_pushfmtstr( L, fmt, (unsigned char*)j->data, j->len ) == -1 ){
        lua_pushnil( L );
        lua_pushstring( L, "invalid format type" );
        return 2;
    }
    
    return 1;
}


static int eq_lua( lua_State *L )
{
    jose_buffer_t *j = luaL_checkudata( L, 1, MODULE_MT );
    size_t len = 0;
    const char *str = NULL;
    
    switch( lua_type( L, 2 ) ){
        case LUA_TSTRING:
            str = lua_tolstring( L, -1, &len );
        break;
        case LUA_TUSERDATA:
            if( lua_getmetatable( L, 2 ) )
            {
                lua_pop( L, 1 );
                if( luaL_callmeta( L, 2, "__tostring" ) ){
                    str = lua_tolstring( L, -1, &len );
                }
            }
        break;
    }

    lua_pushboolean( L, len && len == j->len && 
                     memcmp( str, j->data, j->len ) == 0 );
    return 1;
}


static int tostring_lua( lua_State *L )
{
    jose_buffer_t *j = luaL_checkudata( L, 1, MODULE_MT );
    
    lua_pushlstring( L, j->data, j->len );
    return 1;
}


static int gc_lua( lua_State *L )
{
    jose_buffer_t *j = lua_touserdata( L, 1 );
    
    pdealloc( j->data );
    
    return 0;
}


static int alloc_lua( lua_State *L )
{
    size_t len = 0;
    const char *data = luaL_checklstring( L, 1, &len );
    jose_fmt_e fmt = JOSE_FMT_RAW;
    jose_buffer_t *j = NULL;
    const char *errstr = NULL;
    
    // check format
    if( lua_gettop( L ) > 1 && !lua_isnil( L, 2 ) ){
        fmt = luaL_checkint( L, 2 );
    }
    
    if( !( j = lua_newuserdata( L, sizeof( jose_buffer_t ) ) ) ){
        errstr = strerror( errno );
    }
    else if( fmt == JOSE_FMT_RAW )
    {
        if( !( j->data = pnalloc( len + 1, char ) ) ){
            errstr = strerror( errno );
        }
        else {
            memcpy( j->data, data, len );
            j->data[len] = 0;
            j->len = len;
        }
    }
    else if( fmt == JOSE_FMT_HEX )
    {
        if( len % 2 ){
            errstr = "invalid data format";
        }
        else
        {
            j->len = len / 2;
            if( !( j->data = pnalloc( j->len + 1, char ) ) ){
                errstr = strerror( errno );
            }
            else if( jose_hexdecode( j->data, (unsigned char*)data, len ) == -1 ){
                errstr = strerror( errno );
                pdealloc( j->data );
            }
        }
    }
    else if( fmt == JOSE_FMT_BASE64 || fmt == JOSE_FMT_BASE64URL )
    {
        j->data = b64m_decode_mix( (unsigned char*)data, &len );
        if( !j->data ){
            errstr = strerror( errno );
        }
        else {
            j->len = len;
        }
    }
    // invalid format type
    else {
        errstr = "invalid format type";
    }
    
    if( errstr ){
        lua_pushnil( L );
        lua_pushstring( L, errstr );
        return 2;
    }
    
    luaL_getmetatable( L, MODULE_MT );
    lua_setmetatable( L, -2 );
    
    return 1;
}


LUALIB_API int luaopen_jose_buffer( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { "__eq", eq_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        { "convert", convert_lua },
        { "compare", compare_lua },
        { NULL, NULL }
    };
    
    jose_define_mt( L, MODULE_MT, mmethod, method );
    // add allocation method
    lua_pushcfunction( L, alloc_lua );
    
    return 1;
}


