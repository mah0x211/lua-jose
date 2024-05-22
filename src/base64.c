/**
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
 *  base64.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 */

#include "jose_util.h"

#define encode_lua(L, fn)                                                      \
    do {                                                                       \
        size_t len      = 0;                                                   \
        const char *str = lauxh_checklstr(L, 1, &len);                         \
        char *b64       = fn((unsigned char *)str, &len);                      \
        if (b64) {                                                             \
            lua_pushlstring(L, b64, len);                                      \
            pdealloc(b64);                                                     \
            return 1;                                                          \
        }                                                                      \
        lua_pushnil(L);                                                        \
        lua_pushstring(L, strerror(errno));                                    \
        return 2;                                                              \
    } while (0)

static int encode_std_lua(lua_State *L)
{
    encode_lua(L, b64m_encode_std);
}

static int encode_url_lua(lua_State *L)
{
    encode_lua(L, b64m_encode_url);
}

static int decode_lua(lua_State *L)
{
    size_t len      = 0;
    const char *b64 = lauxh_checklstr(L, 1, &len);
    char *str       = b64m_decode_mix((unsigned char *)b64, &len);

    if (str) {
        lua_pushlstring(L, str, len);
        pdealloc(str);
        return 1;
    }

    // got error
    lua_pushnil(L);
    lua_pushstring(L, strerror(errno));
    return 2;
}

LUALIB_API int luaopen_jose_base64(lua_State *L)
{
    // utility functions
    lua_createtable(L, 0, 2);
    lauxh_pushfn2tbl(L, "encode", encode_std_lua);
    lauxh_pushfn2tbl(L, "encodeURL", encode_url_lua);
    lauxh_pushfn2tbl(L, "decode", decode_lua);

    return 1;
}
