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

  jose.lua
  lua-jose
  
  Created by Masatoshi Teruya on 14/10/26.
  
--]]

-- module
local cjson = require('cjson.safe');
local encodeJSON = cjson.encode;
local decodeJSON = cjson.decode;
local lib = require('jose.lib');
local encodeBase64 = lib.base64.encode;
local decodeBase64 = lib.base64.decode;
local HMAC = lib.hmac;
local RSA = lib.rsa;
-- constants
local ALGORITHM = {
    HS  = HMAC,
    RS  = RSA
};
local DIGEST = {
    none    = 'none',
    ['256'] = lib.SHA256, 
    ['384'] = lib.SHA384, 
    ['512'] = lib.SHA512
};
local KEY_TYPE = {
    HS  = {
        ['string']  = 'string'
    },
    RS  = {
        ['string']  = 'string',
        ['table']   = 'table'
    }
};
-- errors
local EFORMAT   = 'invalid token format';
local ENOTSUP   = 'unsupported alg %q';
local EPRVKEY   = 'secret or private key for alg %q required';
local EPUBKEY   = 'secret or public key for alg %q required';
local EMODEXP   = 'undefined modulus and exponent for alg %q';

-- private
local function encodePlainJWT( header, payload )
    local plain = {
        header = header,
        payload = payload
    };
    local err;
    
    for k, v in pairs( plain ) do
        v, err = encodeJSON( v );
        if err then
            return nil, err;
        end
        v, err = encodeBase64( v );
        if err then
            return nil, err;
        end
        plain[k] = v;
    end
    
    return plain.header .. '.' .. plain.payload;
end


local function decodePlainJWT( jwt )
    local items = {};
    local i = 0;
    local plain, err;
    
    -- extract
    for str in jwt:gmatch( '[^%.]+' ) do
        i = i + 1;
        items[i] = str;
    end
    
    -- invalid token format
    if i < 2 then
        return nil, nil, EFORMAT;
    end
    
    -- set data
    plain = items[1] .. '.' .. items[2];
    
    -- decode header and payload
    for i = 1, 2 do
        items[i], err = decodeBase64( items[i] );
        if err then
            return nil, nil, err;
        end
        items[i], err = decodeJSON( items[i] );
        if err then
            return nil, nil, err;
        end
    end
    
    return items, plain;
end


-- module
local JOSE = {};

function JOSE.createJWT( header, payload, key )
    local alg = ALGORITHM[header.alg:sub(1,2)];
    local digest = DIGEST[header.alg:sub(3)];
    local plain, sign, err;
    
    if not alg or not digest then
        return nil, ENOTSUP:format( header.alg );
    elseif digest == 'none' then
        return encodePlainJWT( header, payload );
    elseif type( key ) ~= 'string' then
        return nil, EPRVKEY:format( header.alg );
    end
    
    -- create plain JWT
    plain, err = encodePlainJWT( header, payload );
    if err then
        return nil, err;
    end
    
    -- create instance
    if alg == HMAC then
        alg, err = alg( digest, key );
    -- crypto
    else
        alg, err = alg( digest );
        if not err then
            err = alg:setPrivateKey( key );
        end
    end
    
    -- failed to setup instance
    if err then
        return nil, err;
    end
    
    -- sign
    sign, err = alg:sign( plain );
    if err then
        return nil, err;
    end
    
    -- append signature(JWS)
    return plain .. '.' .. sign;
end


function JOSE.verifyJWT( jwt, key )
    local token, plain, err = decodePlainJWT( jwt );
    
    if err then
        return nil, err;
    -- plain JWT
    elseif not token[3] then
        -- invalid format
        if token[1].alg ~= 'none' then
            return nil, EFORMAT;
        end
    -- alg should not be nil
    elseif type( token[1].alg ) ~= 'string' then
        return nil, EFORMAT;
    -- signed JWT(JWS)
    else
        local header = token[1];
        local alg = header.alg:sub(1,2);
        local ktype = alg and KEY_TYPE[alg] and KEY_TYPE[alg][type(key)];
        local digest = DIGEST[header.alg:sub(3)];
        local ok;
        
        alg = ALGORITHM[alg];
        -- unsupported alg
        if not alg or not digest then
            return nil, ENOTSUP:format( header.alg );
        -- digest should not be none
        elseif digest == 'none' then
            return nil, EFORMAT;
        -- invalid key type
        elseif not ktype then
            return nil, EPUBKEY:format( header.alg );
        -- modulus and exponent required if key is table
        elseif ktype == 'table' and 
              ( type( key.modulus ) ~= 'string' or 
                type( key.exponent ) ~= 'string' ) then
            return nil, EMODEXP:format( header.alg );
        end
        
        -- create instance
        if alg == HMAC then
            alg, err = alg( digest, key );
        -- for crypto
        else
            alg, err = alg( digest );
            if not err then
                -- key as PEM
                if ktype == 'string' then
                    err = alg:setPublicKey( key );
                else
                    err = alg:setModExp( key.modulus, key.exponent );
                end
            end
        end
        
        -- failed to setup instance
        if err then
            return nil, err;
        end
        
        -- verify
        ok, err = alg:verify( plain, token[3] );
        if not ok then
            return nil, err;
        end
    end
    
    return token;
end


return JOSE;
