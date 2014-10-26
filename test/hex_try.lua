local jose = require('jose.lib');

local function dec( src, dest )
    dest = ifNil( jose.hex.decode( dest ) );
    ifNotEqual( src, dest );
end

local function enc( src )
    dec( src, ifNil( jose.hex.encode( src ) ) );
end

enc('{"foo":{"bar":1},"baz":"hello"}');
