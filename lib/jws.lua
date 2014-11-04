--[[

  Copyright (C) 2014 Masatoshi Teruya
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
 
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
 
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

  jws.lua
  lua-jose
  
  Created by Masatoshi Teruya on 14/11/04.
  
--]]
-- module
local util = require('jose.util');
-- constants
local KTY = {
    none = 'jose.jws.none',
    oct = 'jose.jws.HMAC',
    RSA = 'jose.jws.RSA',
    -- EC
};

-- class
local JWS = require('halo').class.JWS;

-- require: kty, alg
function JWS.create( jwk )
    if type( jwk ) ~= 'table' then
        return nil, 'jwk must be table';
    elseif type( jwk.kty ) ~= 'string' or type( jwk.alg ) ~= 'string' then
        return nil, 'invalid jwk format';
    elseif not KTY[jwk.kty] then
        return nil, ('kty %q is unsupported key type'):format( jwk.kty );
    end
    
    -- create instance
    return require(KTY[jwk.kty]).new( jwk );
end


function JWS:createToken( claims )
    local own = protected(self);
    local token = {};
    local sig, err;
    
    token[1], err = util.encodeToken({
        alg = self.jwk.alg,
        kid = self.jwk.kid
    });
    if err then
        return nil, err;
    end
    
    token[2], err = util.encodeToken( claims );
    if err then
        return nil, err;
    end
    
    token[3], err = self:sign( table.concat( token, '.' ) );
    if err then
        return nil, err;
    end
    
    return table.concat( token, '.' );
end


return JWS.exports;

