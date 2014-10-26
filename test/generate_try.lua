local jose = require('jose.lib');
local modulus = 1024;
local exponent = 65537;
local password = 'pass phrase';
local pem, rsa;
local encryption = {};

for idx, name in ipairs({
    'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc', 
    'bf', 'bf-cbc', 'bf-cfb', 'bf-ofb', 
    'cast', 'cast-cbc', 'cast5-cbc', 'cast5-cfb', 'cast5-ofb', 
    'des', 'des-cbc', 'des-cfb', 'des-ede-cbc', 
    'des-ede-cfb', 'des-ede-ofb', 'des-ede3-cbc', 'des-ede3-cfb', 
    'des-ede3-ofb', 'des-ofb', 'des3', 'desx', 'rc2', 'rc2-40-cbc', 
    'rc2-64-cbc', 'rc2-cbc', 'rc2-cfb', 'rc2-ofb', 
    'rc5', 'rc5-cbc', 'rc5-cfb', 'rc5-ofb', 'seed', 'seed-cbc', 
    'seed-cfb', 'seed-ofb'
}) do
    encryption[idx] = {
        name = name,
        pswd = password
    };
end
-- non encrypt
encryption[#encryption+1] = {
    name = nil,
    pswd = nil
};

for _, enc in ipairs( encryption ) do
    pem = ifNil( jose.generate.rsa( modulus, exponent, enc.name, enc.pswd ) );
    rsa = ifNil( jose.rsa( jose.SHA256 ) );
    ifNotNil( rsa:setPrivateKey( pem.private, enc.pswd ) );
end

