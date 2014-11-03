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
 *  jose_buffer.h
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/27.
 *
 */

#ifndef ___JOSE_BUFFER_LUA___
#define ___JOSE_BUFFER_LUA___

#include "jose_util.h"

#define JOSE_BUFFER_MT   "jose.buffer"

typedef struct {
    char *data;
    size_t len;
} jose_buffer_t;

LUALIB_API int luaopen_jose_buffer( lua_State *L );

static inline jose_buffer_t *jose_buffer_alloc( lua_State *L, char *data, 
                                                size_t len )
{
    jose_buffer_t *j = lua_newuserdata( L, sizeof( jose_buffer_t ) );
    
    if( j ){
        j->data = data;
        j->len = len;
        luaL_getmetatable( L, JOSE_BUFFER_MT );
        lua_setmetatable( L, -2 );
    }
    
    return j;
}

#endif

