local pkey = require('jose.pkey');
local digest = require('jose.digest');
local bits = 1024;
local password = 'pass phrase';
local data = 'hello world';
local SHA512 = digest.SHA512;
local pem, pk, cmp, sig;
local cipher = {};

for _, name in pairs( pkey ) do
    if type(name) == 'string' and not name:find('ecb') and 
       name ~= 'id-aes128-GCM' and
       name ~= 'id-aes192-GCM' and
       name ~= 'id-aes256-GCM' and
       name ~= 'des-ede3' and
       name ~= 'des-ede' and
       name ~= 'rc4' and
       name ~= 'rc4-40' and
       name ~= 'rc4-hmac-md5' and
       name ~= 'aes-128-gcm' and
       name ~= 'aes-192-gcm' and
       name ~= 'aes-256-gcm'
    then
    cipher[#cipher+1] = {
        name = name,
        pswd = password
    };
    end
end

-- non cipher
cipher[#cipher+1] = {
    name = nil,
    pswd = nil
};

for _, ciph in ipairs( cipher ) do
    -- check generate
    pk = ifNil( pkey.new() );
    ifNotTrue( pk:initAsRSA( bits ) );
    pem = {
        public = ifNil( pk:getPublicPEM() ),
        private = ifNil( pk:getPrivatePEM( ciph.name, ciph.pswd ) )
    };
    cmp = ifNil( pk:getComponent() );
    -- check sign
    sig = ifNil( pk:sign( SHA512, data ) );
    -- check verify
    ifNotTrue( pk:verify( SHA512, sig, data ) );
    
    
    -- check generated pem
    pk = ifNil( pkey.new() );
    
    -- private pem can be generate both of private/public pem
    ifNotTrue( pk:setPrivatePEM( pem.private, ciph.pswd ) );
    ifNil( pk:getPrivatePEM() );
    ifNotEqual( pem.public, ifNil( pk:getPublicPEM() ) );
    ifNotEqual( sig, ifNil( pk:sign( SHA512, data ) ) );
    ifNotTrue( pk:verify( SHA512, sig, data ) );
    
    -- public pem can be generate public pem
    ifNotTrue( pk:setPublicPEM( pem.public ) );
    ifNotEqual( pem.public, ifNil( pk:getPublicPEM() ) );
    ifNotNil( pk:getPrivatePEM() );
    ifNotNil( pk:sign( SHA512, data ) );
    ifNotTrue( pk:verify( SHA512, sig, data ) );
    
    -- check generated component
    pk = ifNil( pkey.new() );
    -- private pem can be generate both of private/public pem
    ifNotTrue( pk:setRSAComponent( cmp ) );
    ifNil( pk:getPrivatePEM() );
    ifNotEqual( pem.public, ifNil( pk:getPublicPEM() ) );
    ifNotEqual( sig, ifNil( pk:sign( SHA512, data ) ) );
    ifNotTrue( pk:verify( SHA512, sig, data ) );
end

