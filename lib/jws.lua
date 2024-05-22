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
-- jws.lua
-- lua-jose
--
-- Created by Masatoshi Teruya on 14/11/04.
--
-- module
local concat = table.concat
local util = require('jose.util')
-- constants
local KTY = {
    none = 'jose.jws.none',
    oct = 'jose.jws.HMAC',
    RSA = 'jose.jws.RSA',
    -- EC
}

--- @class jose.jws
--- @field alg string
--- @field jwk table
local JWS = {}

--- sign
--- @param data string
--- @return string signature
--- @return any err
function JWS:sign(data)
    return nil
end

--- verify
--- @return boolean ok
--- @return any err
function JWS:verify()
    return true
end

--- createToken
--- @param claims table
--- @return string token
--- @return any err
function JWS:createToken(claims)
    local arr = {}
    local err

    -- encode header
    arr[1], err = util.encodeToken({
        alg = self.jwk.alg,
        kid = self.jwk.kid,
    })
    if err then
        return nil, err
    end

    -- encode payload
    arr[2], err = util.encodeToken(claims)
    if err then
        return nil, err
    end

    -- create signature
    arr[3], err = self:sign(concat(arr, '.'))
    if err then
        return nil, err
    end

    return concat(arr, '.')
end

JWS = require('metamodule').new(JWS)

--- create
--- @param jwk table
--- @return jose.jws jws
--- @return any err
local function create(jwk)
    if type(jwk) ~= 'table' then
        return nil, 'jwk must be table'
    elseif type(jwk.kty) ~= 'string' or type(jwk.alg) ~= 'string' then
        return nil, 'invalid jwk format'
    elseif not KTY[jwk.kty] then
        return nil, ('kty %q is unsupported key type'):format(jwk.kty)
    end

    -- create instance
    return require(KTY[jwk.kty])(jwk)
end

return {
    create = create,
}

