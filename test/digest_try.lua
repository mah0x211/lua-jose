local bin = require('jose.buffer');
local digest = require('jose.digest');
local FMT_HEX = bin.FMT_HEX;


local function digest_sha( src )
    local d, gd;
    
    for k, v in pairs({
        sha1    = 'bb6b6554504a4fec2f64f493ed2be2d0c447dbdb',
        sha224  = 'b82f368fd62553945745741502a2c46ee94ce16b83a044f569e68789',
        sha256  = 'd712653e1ae58ecf6ed612a8a95a4cfb77146bc7e438d07ae76af79ea56196de',
        sha384  = '224919d9f36df928bfac09db9f5b7047cea9a96cd03fa86461a9d887706d3ddcd7b5d92521bff1efac6fa41134a3812a',
        sha512  = '7708d97f4f251cb91f9ac1df4bcc282514d57e05f8cfa652a2bca063645a8974a74d6b7a3634aba7a5539f559aedc7f3a6dc587d7828fa913035bd5e83840b3e'
    }) do
        d = ifNil( digest.new( k ) );
        ifNotTrue( d:update( src ) );
        d = ifNil( d:final() );
        ifNotTrue( d:compare( v, FMT_HEX ) );
        ifNotEqual( d:toHex(), v );
    end
end


local function digest_hmac( src )
    local key = 'test key';
    local d;
    
    for k, v in pairs({
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
    }) do
        d = ifNil( digest.new( k, v.key ) );
        ifNotTrue( d:update( src ) );
        d = ifNil( d:final() );
        ifNotTrue( d:compare( v.res, FMT_HEX ) );
        ifNotEqual( d:toHex(), v.res );
    end
end


digest_sha( '{"baz":"hello","foo":{"bar":1}}' );
digest_hmac( '{"baz":"hello","foo":{"bar":1}}' );
