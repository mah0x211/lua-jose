local lib = require('jose.lib');
local DIGESTS = {
    sha1    = 'bb6b6554504a4fec2f64f493ed2be2d0c447dbdb',
    sha224  = 'b82f368fd62553945745741502a2c46ee94ce16b83a044f569e68789',
    sha256  = 'd712653e1ae58ecf6ed612a8a95a4cfb77146bc7e438d07ae76af79ea56196de',
    sha384  = '224919d9f36df928bfac09db9f5b7047cea9a96cd03fa86461a9d887706d3ddcd7b5d92521bff1efac6fa41134a3812a',
    sha512  = '7708d97f4f251cb91f9ac1df4bcc282514d57e05f8cfa652a2bca063645a8974a74d6b7a3634aba7a5539f559aedc7f3a6dc587d7828fa913035bd5e83840b3e'
};


local function create( k, src, fmt )
    local d = ifNil( lib.digest.new( k ) );
    
    ifNotTrue( d:update( src ) );
    
    return ifNil( d:final( fmt ) );
end


local function digest( src )
    local buf, hex, ghex;
    
    for k, v in pairs( DIGESTS ) do
        hex = create( k, src );
        ifNotEqual( hex, v );
        
        ghex = ifNil( lib.digest.gen( k, src ) );
        ifNotEqual( ghex, v );
        
        -- raw memory check
        buf = ifNil( lib.buffer( hex, lib.FMT_HEX ) );
        ifNotTrue( 
            buf:compare( 
                create( k, src, lib.FMT_BASE64 ), 
                lib.FMT_BASE64 
            ) 
        );
        ifNotTrue( 
            buf:compare( 
                create( k, src, lib.FMT_BASE64URL ), 
                lib.FMT_BASE64URL 
            )
        );
        ifNotTrue( 
            buf:compare( 
                lib.digest.gen( k, src, lib.FMT_BASE64 ), 
                lib.FMT_BASE64 
            )
        );
        ifNotTrue( 
            buf:compare( 
                lib.digest.gen( k, src, lib.FMT_BASE64URL ), 
                lib.FMT_BASE64URL
            )
        );
    end
end


digest('{"baz":"hello","foo":{"bar":1}}');
