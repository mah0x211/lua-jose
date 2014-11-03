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

#include "jose_util.h"

// define module names
#define JOSE_RSA_MT     "jose.rsa"

// MARK: define prototypes
LUALIB_API int luaopen_jose_lib( lua_State *L );
LUALIB_API int luaopen_jose_hex( lua_State *L );
LUALIB_API int luaopen_jose_base64( lua_State *L );
LUALIB_API int luaopen_jose_digest( lua_State *L );
LUALIB_API int luaopen_jose_pkey( lua_State *L );
LUALIB_API int luaopen_jose_rsa( lua_State *L );
LUALIB_API int luaopen_jose_generate( lua_State *L );


#endif
