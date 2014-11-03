local base64 = require('jose.base64');

local function dec( src, dest )
    dest = ifNil( base64.decode( dest ) );
    ifNotEqual( src, dest );
end

local function enc( src )
    dec( src, ifNil( base64.encode( src ) ) );
end

enc('{"foo":{"bar":1},"baz":"hello"}');
