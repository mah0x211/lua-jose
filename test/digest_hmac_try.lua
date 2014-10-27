local lib = require('jose.lib');
local key = 'test key';
local DIGESTS = {
    sha1    = { 
        key = key,
        res = '53215e7288d3bf91fff950b58f8c2908eefa95b0'
    },
    sha224  = { 
        key = key,
        res = '64f7e16243f3daaf411df1bdc6fa38e23fa50bfa7e45fb0fbf7da989'
    },
    sha256  = { 
        key = key,
        res = '9913ea3b1ea0f95a40accb5dc888fa355f25745fd4e1ae4448d633fbe7523704'
    },
    sha384  = {
        key = key,
        res = '7b72250cd2fe8ac358c9b852b87b3351c8e97792e325e72b28e40a2c15d26e824955c7572f8a0d0c8d8c8e1b6c3ad935'
    },
    sha512  = {
        key = key,
        res = '7d165b805efd9777d6d21ac19da711d8259622c5eab7b6e730844ea316a15badb0b3c1fd0f2e19f787ba836a96993ccc0a9d97237136ba7356c0441e2b482bd8'
    }
};

local function create( k, key, src, fmt )
    local h = ifNil( lib.hmac.new( k, key ) );
    
    ifNotTrue( h:update( src ) );
    
    return ifNil( h:final( fmt ) );
end


local function digest( src )
    local buf, hex, ghex;
    
    for k, v in pairs( DIGESTS ) do
        hex = create( k, v.key, src );
        ifNotEqual( hex, v.res );
        
        ghex = ifNil( lib.hmac.gen( k, v.key, src ) );
        ifNotEqual( ghex, v.res );
        
        -- raw memory check
        buf = ifNil( lib.buffer( hex, lib.FMT_HEX ) );
        ifNotTrue( 
            buf:compare( 
                create( k, v.key, src, lib.FMT_BASE64 ), 
                lib.FMT_BASE64 
            )
        );
        ifNotTrue( 
            buf:compare( 
                create( k, v.key, src, lib.FMT_BASE64URL ), 
                lib.FMT_BASE64URL 
            )
        );
        ifNotTrue( 
            buf:compare( 
                lib.hmac.gen( k, v.key, src, lib.FMT_BASE64 ), 
                lib.FMT_BASE64 
            )
        );
        ifNotTrue( 
            buf:compare( 
                lib.hmac.gen( k, v.key, src, lib.FMT_BASE64URL ), 
                lib.FMT_BASE64URL
            )
        );
    end
end

digest( '{"baz":"hello","foo":{"bar":1}}' );
