local lib = require('jose.lib');
local data = '{"foo":{"bar":1},"baz":"hello"}';

local buf = ifNil( lib.buffer( data ) );
local hex = ifNil( buf:convert( lib.FMT_HEX ) );
local b64 = ifNil( buf:convert( lib.FMT_BASE64 ) );
local b64url = ifNil( buf:convert( lib.FMT_BASE64URL ) );

ifNil( buf:convert() );
ifNotEqual( buf:convert(), data );

local function compare( raw, fmt, hex, b64, b64url )
    local buf = ifNil( lib.buffer( raw, fmt ) );
    
    ifNotTrue( buf:compare( data ) );
    ifNotTrue( buf:compare( hex, lib.FMT_HEX ) );
    ifNotTrue( buf:compare( b64, lib.FMT_BASE64 ) );
    ifNotTrue( buf:compare( b64, lib.FMT_BASE64URL ) );
    ifNotTrue( buf:compare( b64url, lib.FMT_BASE64 ) );
    ifNotTrue( buf:compare( b64url, lib.FMT_BASE64URL ) );
    ifNotFalse( buf:compare( '{"foo":{"bar":1},"baz":"hello"|' ) );
end

for _, v in ipairs({ 
    {
        data = hex,
        fmt = lib.FMT_HEX
    },
    {
        data = b64,
        fmt = lib.FMT_BASE64
    },
    {
        data = b64url,
        fmt = lib.FMT_BASE64URL
    }
}) do
    compare( v.data, v.fmt, hex, b64, b64url );
end
