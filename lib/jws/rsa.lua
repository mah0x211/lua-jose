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
-- rsa.lua
-- lua-jose
--
-- Created by Masatoshi Teruya on 14/11/04.
--
-- module
local pkey = require('jose.pkey')
local bin = require('jose.bin')
local digest = require('jose.digest')
-- constants
-- alg
local ALG = {
    RS256 = digest.SHA256,
    RS384 = digest.SHA384,
    RS512 = digest.SHA512,
}
-- class
local RSA = require('halo').class.RSA

RSA.inherits {
    'jose.jws.JWS',
    -- remove unused methods
    except = {
        static = {
            'create',
        },
    },
}

function RSA:init(jwk)
    local own = protected(self)
    local alg = ALG[jwk.alg]
    local engine, ok, err

    if not alg then
        return nil, ('alg %q is unsupported algorithm'):format(jwk.alg)
    end

    engine, err = pkey.new()
    if err then
        return nil, err
    end
    ok, err = engine:setRSAComponent(jwk)
    if err then
        return nil, err
    end

    self.jwk = jwk
    own.alg = alg
    own.engine = engine

    return self
end

function RSA:verify(data, sig)
    local own = protected(self)
    local err

    sig, err = bin.new(sig, bin.FMT_BASE64URL)
    if err then
        return false, err
    end

    return own.engine:verify(own.alg, sig, data)
end

function RSA:sign(data)
    local own = protected(self)
    local sig, err = own.engine:sign(own.alg, data)

    if sig then
        sig, err = sig:toBase64URL()
    end

    return sig, err
end

return RSA.exports
