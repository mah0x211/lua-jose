local base64 = require('jose.base64');
local jose = require('jose');
local rsaComponent = {
    n = "s8xGhgK4RowoGq4SPcSVU4JREXnMctqXZ5OrMH3bYTGZbMm0pvkR8X9QkrwAwlQEKTy6FxD2CyxoRtKzyFrlaukrwh7oZ-oaTbUNcVnEwDuCLoRWtipz9exCrqibr67LN-Zv27h0Si5MSQcZNa-xi3EB4TyqEVClTz9abg1D80c",
    e = "AQAB",
    d = "IYcdO440SMuICvmc4zHOWsU5UtXwnxZOF3189czyZNx37MZsTpqxkuQX5VTzm0lJgVsWpIiAKTM9ur890UXJ8-ZH-NtNk7Lbfuy3EkHpVaoL1MTjKiDKAHc0gCHgzXOol_3H6P86aOa21H5AZtTE-HXca1cmH2vL8FKBUmwhHik"
}
local secret = ifNil( base64.encodeURL('test key') );
local jws, jwt;

local KTY = {
    HS256 = 'oct',
    HS384 = 'oct',
    HS512 = 'oct',
    RS256 = 'RSA',
    RS384 = 'RSA',
    RS512 = 'RSA',
    none = 'none'
};

for alg, v in pairs({
    none = {},
    HS256 = {
        k = secret
    },
    HS384 = {
        k = secret
    },
    HS512 = {
        k = secret
    },
    RS256 = rsaComponent,
    RS384 = rsaComponent,
    RS512 = rsaComponent
}) do
    -- create JWT
    v.kty = KTY[alg]
    v.alg = alg;
    if alg ~= 'none' then
        v.kid = 'kid-' .. tostring( math.random(1000000) );
    end
    jws = ifNil( jose.jws.create( v ) );
    jwt = ifNil( jws:createToken({
        -- Issuer
        iss = 'issuer',
        -- Subject
        sub = 'user id',
        -- Audience
        aud = 'audience',
        -- Expiration Time
        exp = os.time() + 10,
        -- Not Before
        nbf = os.time(),
        -- Issued At
        iat = os.time(),
        -- JWT ID
        jti = 'token id'
    }));
    
    -- read and verify JWT
    jwt = ifNil( jose.jwt.read( jwt ) );
    ifNotTrue( jws:verify( jwt.data, jwt.sign ) );
end
