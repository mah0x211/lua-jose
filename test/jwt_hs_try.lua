local util = require('util');
local jose = require('jose');
local SECRET = 'secret';
local HSALG = { 
    'HS256', 'HS384', 'HS512'
};


local function createJWT( alg )
    local header = { 
        alg = alg,
        typ = 'JWT'
    };
    local payload = {
        sub = 1234567890,
        name = 'John Doe',
        admin = true
    };
    
    return ifNil( jose.createJWT( header, payload, SECRET ) );
end

local function verifyJWT( jwt )
    local token = ifNil( jose.verifyJWT( jwt, SECRET ) );
end


for _, alg in ipairs( HSALG ) do
    verifyJWT( createJWT( alg ) );
end
