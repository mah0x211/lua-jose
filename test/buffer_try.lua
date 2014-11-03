local buffer = require('jose.buffer');
local data = '{"foo":{"bar":1},"baz":"hello"}';

local buf = ifNil( buffer.new( data ) );
local hex = ifNil( buf:toHex() );
local b64 = ifNil( buf:toBase64() );
local b64url = ifNil( buf:toBase64URL() );

ifNil( buf );
ifNotEqual( tostring(buf), data );

local function compare( raw, fmt, hex, b64, b64url )
    local buf = ifNil( buffer.new( raw, fmt ) );
    
    ifNotTrue( buf:compare( data ) );
    ifNotTrue( buf:compare( hex, buffer.FMT_HEX ) );
    ifNotTrue( buf:compare( b64, buffer.FMT_BASE64 ) );
    ifNotTrue( buf:compare( b64, buffer.FMT_BASE64URL ) );
    ifNotTrue( buf:compare( b64url, buffer.FMT_BASE64 ) );
    ifNotTrue( buf:compare( b64url, buffer.FMT_BASE64URL ) );
    ifNotFalse( buf:compare( '{"foo":{"bar":1},"baz":"hello"|' ) );
end

for _, v in ipairs({ 
    {
        data = hex,
        fmt = buffer.FMT_HEX
    },
    {
        data = b64,
        fmt = buffer.FMT_BASE64
    },
    {
        data = b64url,
        fmt = buffer.FMT_BASE64URL
    }
}) do
    compare( v.data, v.fmt, hex, b64, b64url );
end
