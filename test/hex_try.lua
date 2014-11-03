local hex = require('jose.hex');

local function dec( src, dest )
    dest = ifNil( hex.decode( dest ) );
    ifNotEqual( src, dest );
end

local function enc( src )
    dec( src, ifNil( hex.encode( src ) ) );
end

enc('{"foo":{"bar":1},"baz":"hello"}');
