--
-- Copyright (C) 2014 Masatoshi Teruya
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--
-- util.lua
-- lua-jose
--
-- Created by Masatoshi Teruya on 14/11/04.
--
-- module
local cjson = require('cjson.safe')
local base64 = require('jose.base64')

local function encodeToken(tbl)
    local err

    tbl, err = cjson.encode(tbl)
    if err then
        return nil, err
    end
    tbl, err = base64.encodeURL(tbl)
    if err then
        return nil, err
    end

    return tbl
end

local function decodeToken(token)
    local err

    token, err = base64.decode(token)
    if err then
        return nil, err
    end
    token, err = cjson.decode(token)
    if err then
        return nil, err
    end

    return token
end

return {
    encodeToken = encodeToken,
    decodeToken = decodeToken,
}
