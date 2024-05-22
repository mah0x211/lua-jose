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
-- hmac.lua
-- lua-jose
--
-- Created by Masatoshi Teruya on 14/11/04.
--
-- module
local digest = require('jose.digest')
local base64 = require('jose.base64')
-- constants
local FMT_BASE64URL = require('jose.bin').FMT_BASE64URL
-- alg
local ALG = {
    HS256 = digest.SHA256,
    HS384 = digest.SHA384,
    HS512 = digest.SHA512,
}

--- @class jose.jws.hmac : jose.jws
local HMAC = {}

--- init
--- @param jwk table
--- @return jose.jws.hmac hmac
--- @return any err
function HMAC:init(jwk)
    local alg = ALG[jwk.alg]
    local engine, key, err

    -- check key
    if not alg then
        return nil, ('alg %q is unsupported algorithm'):format(jwk.alg)
    elseif type(jwk.k) ~= 'string' then
        return nil, 'invalid jwk format'
    end

    key, err = base64.decode(jwk.k)
    if err then
        return nil, 'invalid parameter k: ' .. err
    end

    engine, err = digest.new(alg, key)
    if err then
        return nil, err
    end

    self.jwk = jwk
    self.alg = alg
    self.engine = engine
    return self
end

--- verify
--- @param data string
--- @param sig string
--- @return boolean ok
--- @return any err
function HMAC:verify(data, sig)
    local engine = self.engine
    local ok, err = engine:reset()
    local bin

    if ok then
        ok, err = engine:update(data)
        if ok then
            bin, err = engine:final()
            if bin then
                ok = bin:toBase64URL() == sig
            end
        end
    end

    return ok, err
end

--- sign
--- @param data string
--- @return string sig
--- @return any err
function HMAC:sign(data)
    local engine = self.engine
    local ok, err = engine:reset()
    local bin

    if ok then
        ok, err = engine:update(data)
        if ok then
            bin, err = engine:final()
            if bin then
                bin, err = bin:toBase64URL()
            end
        end
    end

    return bin, err
end

HMAC = require('metamodule').new(HMAC)
return HMAC

