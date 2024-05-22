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
 *  bin.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/27.
 */

#include "jose_bin.h"

#define MODULE_MT JOSE_BIN_MT

static int compare_lua(lua_State *L)
{
    jose_bin_t *j    = lauxh_checkudata(L, 1, MODULE_MT);
    size_t len       = 0;
    const char *data = lauxh_checklstr(L, 2, &len);
    jose_fmt_e fmt   = lauxh_optint(L, 3, JOSE_FMT_RAW);

    if (fmt == JOSE_FMT_RAW) {
        lua_pushboolean(L, len == j->len && memcmp(data, j->data, j->len) == 0);
    } else {
        char *buf   = NULL;
        size_t blen = len;

        if (fmt == JOSE_FMT_HEX) {
            // invalid length
            if (len % 2) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, "invalid data format");
                return 2;
            }
            // length does not match
            else if ((blen = len / 2) != j->len) {
                lua_pushboolean(L, 0);
                return 1;
            }
            // alloc error
            else if (!(buf = pnalloc(blen + 1, char))) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, strerror(errno));
                return 2;
            } else if (jose_hexdecode(buf, (unsigned char *)data, len) == -1) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, strerror(errno));
                pdealloc(buf);
                return 2;
            }

            lua_pushboolean(L, memcmp(buf, j->data, j->len) == 0);
            pdealloc(buf);
        } else if (fmt == JOSE_FMT_BASE64 || fmt == JOSE_FMT_BASE64URL) {
            if (!(buf = b64m_decode_mix((unsigned char *)data, &len))) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, strerror(errno));
                return 2;
            }
            lua_pushboolean(L,
                            len == j->len && memcmp(buf, j->data, j->len) == 0);
            pdealloc(buf);
        } else {
            lua_pushboolean(L, 0);
            lua_pushliteral(L, "invalid format type");
            return 2;
        }
    }

    return 1;
}

static int tohex_lua(lua_State *L)
{
    jose_bin_t *j = lauxh_checkudata(L, 1, MODULE_MT);

    if (jose_pushfmtstr(L, JOSE_FMT_HEX, (unsigned char *)j->data, j->len) ==
        -1) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    return 1;
}

static int tobase64_lua(lua_State *L)
{
    jose_bin_t *j = lauxh_checkudata(L, 1, MODULE_MT);

    if (jose_pushfmtstr(L, JOSE_FMT_BASE64, (unsigned char *)j->data, j->len) ==
        -1) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    return 1;
}

static int tobase64url_lua(lua_State *L)
{
    jose_bin_t *j = lauxh_checkudata(L, 1, MODULE_MT);

    if (jose_pushfmtstr(L, JOSE_FMT_BASE64URL, (unsigned char *)j->data,
                        j->len) == -1) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    return 1;
}

static int eq_lua(lua_State *L)
{
    jose_bin_t *j   = lauxh_checkudata(L, 1, MODULE_MT);
    size_t len      = 0;
    const char *str = NULL;

    switch (lua_type(L, 2)) {
    case LUA_TSTRING:
        str = lua_tolstring(L, 2, &len);
        break;
    case LUA_TUSERDATA:
        if (lua_getmetatable(L, 2)) {
            lua_pop(L, 1);
            if (luaL_callmeta(L, 2, "__tostring")) {
                str = lua_tolstring(L, -1, &len);
            }
        }
        break;
    }

    lua_pushboolean(L,
                    len && len == j->len && memcmp(str, j->data, j->len) == 0);
    return 1;
}

static int tostring_lua(lua_State *L)
{
    jose_bin_t *j = lauxh_checkudata(L, 1, MODULE_MT);
    lua_pushlstring(L, j->data, j->len);
    return 1;
}

static int len_lua(lua_State *L)
{
    jose_bin_t *j = lauxh_checkudata(L, 1, MODULE_MT);
    lua_pushinteger(L, j->len);
    return 1;
}

static int gc_lua(lua_State *L)
{
    jose_bin_t *j = lua_touserdata(L, 1);
    pdealloc(j->data);
    return 0;
}

static int alloc_lua(lua_State *L)
{
    size_t rlen     = 0;
    const char *raw = lauxh_checklstr(L, 1, &rlen);
    jose_fmt_e fmt  = lauxh_optint(L, 2, JOSE_FMT_RAW);
    size_t len      = rlen;
    char *data      = NULL;

    switch (fmt) {
    case JOSE_FMT_RAW:
        if (!(data = pnalloc(len + 1, char))) {
            lua_pushnil(L);
            lua_pushstring(L, strerror(errno));
            return 2;
        }
        memcpy(data, raw, len);
        data[len] = 0;
        break;

    case JOSE_FMT_BASE64:
    case JOSE_FMT_BASE64URL:
        if (!(data = b64m_decode_mix((unsigned char *)raw, &len))) {
            lua_pushnil(L);
            lua_pushstring(L, strerror(errno));
            return 2;
        }
        break;

    case JOSE_FMT_HEX:
        if (len % 2) {
            lua_pushnil(L);
            lua_pushliteral(L, "invalid data format");
            return 2;
        } else if (!(data = pnalloc((len /= 2) + 1, char)) ||
                   jose_hexdecode(data, (unsigned char *)raw, rlen) == -1) {
            lua_pushnil(L);
            lua_pushstring(L, strerror(errno));
            if (data) {
                pdealloc(data);
            }
            return 2;
        }
        break;

    // invalid format type
    default:
        lua_pushnil(L);
        lua_pushliteral(L, "invalid format type");
        return 2;
    }

    if (!jose_bin_alloc(L, data, len)) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    return 1;
}

void jose_bin_define(lua_State *L)
{
    struct luaL_Reg mmethod[] = {
        {"__gc",       gc_lua      },
        {"__tostring", tostring_lua},
        {"__eq",       eq_lua      },
        {"__len",      len_lua     },
        {NULL,         NULL        }
    };
    struct luaL_Reg method[] = {
        {"toHex",       tohex_lua      },
        {"toBase64",    tobase64_lua   },
        {"toBase64URL", tobase64url_lua},
        {"compare",     compare_lua    },
        {NULL,          NULL           }
    };

    jose_define_mt(L, MODULE_MT, mmethod, method);
}

LUALIB_API int luaopen_jose_bin(lua_State *L)
{
    jose_bin_define(L);

    lua_newtable(L);
    lauxh_pushfn2tbl(L, "new", alloc_lua);
    // add format constants
    lauxh_pushint2tbl(L, "FMT_RAW", JOSE_FMT_RAW);
    lauxh_pushint2tbl(L, "FMT_HEX", JOSE_FMT_HEX);
    lauxh_pushint2tbl(L, "FMT_BASE64", JOSE_FMT_BASE64);
    lauxh_pushint2tbl(L, "FMT_BASE64URL", JOSE_FMT_BASE64URL);

    return 1;
}
