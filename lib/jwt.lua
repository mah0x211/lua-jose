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

  jwt.lua
  lua-jose
  
  Created by Masatoshi Teruya on 14/11/04.
  
--]]

-- module
local util = require('jose.util');
-- errors
local EFORMAT   = 'invalid token format';
local EEXPIRE   = 'token expired';
local EBEFORE   = 'token effective from %q';

--[[
    JSON Web Token (JWT)
    draft-ietf-oauth-json-web-token-30
    https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30
--]]
-- schema
local schema = require('lschema').new('JWT');
local struct, enum, isa = schema.struct, schema.enum, schema.isa;

struct 'header' {
    alg = isa('string'):notNull(),
    kid = isa('string')
};

-- 4.1.  Registered Claim Names
-- https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-30#section-4.1
struct 'claims' {
    -- Issuer
    iss = isa('string'),
    -- Subject
    sub = isa('string'),
    -- Audience
    aud = isa('string'),
    -- Expiration Time
    exp = isa('uint'),
    -- Not Before
    nbf = isa('uint'),
    -- Issued At
    iat = isa('uint'),
    -- JWT ID
    jti = isa('string'),
    -- Type
    typ = isa('string')
};

struct 'JWT' {
    header  = isa('struct'):of( struct.header ):notNull(),
    claims  = isa('struct'):of( struct.claims ):notNull(),
    sign    = isa('string')
};


-- private
local function decodeJWT( jwt )
    local items = {};
    local i = 0;
    local data, err;
    
    -- extract
    for str in jwt:gmatch( '[^%.]+' ) do
        i = i + 1;
        items[i] = str;
    end
    
    -- invalid token format
    if i < 2 then
        return nil, EFORMAT;
    end
    
    -- set data
    data = items[1] .. '.' .. items[2];
    -- decode header and payload
    items[1], err = util.decodeToken( items[1] );
    if err then
        return nil, err;
    end
    items[2], err = util.decodeToken( items[2] );
    if err then
        return nil, err;
    end
    
    -- verify format
    jwt, err = struct.JWT({
        header = items[1],
        claims = items[2],
        sign = items[3]
    });
    if err then
        return nil, err;
    elseif jwt.header.alg ~= 'none' then
        jwt.data = data;
    end
    
    return jwt;
end


-- reader
local function read( jwt )
    local epoch, err;
    
    jwt, err = decodeJWT( jwt );
    if err then
        return nil, EFORMAT;
    -- none alg
    -- should not defined kid and signature
    elseif jwt.header.alg == 'none' and ( jwt.header.kid or jwt.sign ) then
        return nil, EFORMAT;
    end
    
    -- check epoch
    epoch = os.time();
    -- expired
    if jwt.claims.exp and epoch >= jwt.claims.exp then
        return nil, EEXPIRE;
    end
    -- should not use before
    if jwt.claims.nbf and epoch < jwt.claims.nbf then
        return nil, EBEFORE:format( os.date( '%FT%TZ', jwt.claims.nbf ) );
    end
    
    return jwt;
end


return {
    read = read
};
