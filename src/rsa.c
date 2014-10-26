/*
 *  Copyright 2014 Masatoshi Teruya. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a 
 *  copy of this software and associated documentation files (the "Software"), 
 *  to deal in the Software without restriction, including without limitation 
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 *  and/or sell copies of the Software, and to permit persons to whom the 
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL 
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 *  DEALINGS IN THE SOFTWARE.
 *
 *  rsa.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/22.
 *
 */

#include "jose.h"

typedef struct {
    RSA *rsa;
    int nid;
    EVP_MD *md;
    int verified;
} jose_rsa_t;


static inline char *bignum64encode( BIGNUM *bn, int *len )
{
    char *bn64 = NULL;
    size_t bytes = BN_num_bytes( bn );
    unsigned char *buf = pnalloc( bytes, unsigned char );

    if( buf )
    {
        bytes = BN_bn2bin( bn, buf );
        if( ( bn64 = b64m_encode_url( buf, &bytes ) ) ){
            *len = bytes;
        }
        pdealloc( buf );
    }
    
    return bn64;
}

 
static inline BIGNUM *bignum64decode( const unsigned char *src, size_t len )
{
    BIGNUM *bn = NULL;
    unsigned char *dec = (unsigned char*)b64m_decode_url( src, &len );
    
    if( dec )
    {
        if( len ){
            bn = BN_bin2bn( dec, len, NULL );
        }
        pdealloc( dec );
    }
    
    return bn;
}


static int verify_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    size_t len = 0;
    const char *msg = luaL_checklstring( L, 2, &len );
    size_t slen = 0;
    const char *sig = luaL_checklstring( L, 3, &slen );
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t dlen = 0;
    const char *errstr = NULL;
    
    if( !( errstr = jose_digest( digest, &dlen, msg, len, j->md ) ) &&
        ( sig = b64m_decode_url( (unsigned char*)sig, &slen ) ) ){
        lua_pushboolean( L, 
            RSA_verify( j->nid, digest, dlen, (unsigned char*)sig, strlen(sig), 
                        j->rsa )
        );
        pdealloc( sig );
        return 1;
    }
    
    // got error
    lua_pushboolean( L, 0 );
    lua_pushstring( L, errstr );
    
    return 2;
}


static int sign_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    size_t len = 0;
    const char *msg = luaL_checklstring( L, 2, &len );
    const char *errstr = "invalid private key";
    
    // has valid private key
    if( j->verified == 1 )
    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        size_t dlen = 0;
        
        if( !( errstr = jose_digest( digest, &dlen, msg, len, j->md ) ) )
        {
            unsigned int slen = 0;
            unsigned char *sig = pnalloc( RSA_size( j->rsa ), unsigned char );
            
            if( RSA_sign( j->nid, digest, dlen, sig, &slen, j->rsa ) ){
                size_t blen = slen;
                char *b64 = b64m_encode_url( sig, &blen );
                
                lua_pushlstring( L, b64, blen );
                pdealloc( b64 );
                pdealloc( sig );
                return 1;
            }
            pdealloc( sig );
            errstr = ERR_error_string( ERR_get_error(), NULL );
        }
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, errstr );
    
    return 2;
}


static int set_modexp_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    size_t mlen = 0;
    const char *modulus = luaL_checklstring( L, 2, &mlen );
    size_t elen = 0;
    const char *exponent = luaL_checklstring( L, 3, &elen );
    const char *errstr = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    
    if( !elen || mlen < elen ){
        errstr = "modulus length must be greater than exponent";
    }
    else if( !( n = bignum64decode( (const unsigned char*)modulus, mlen ) ) ){
        errstr = strerror( errno );
    }
    else if( !( e = bignum64decode( (const unsigned char*)exponent, elen ) ) ){
        BN_free( n );
        errstr = strerror( errno );
    }
    else {
        BN_free( j->rsa->n );
        BN_free( j->rsa->e );
        j->rsa->n = n;
        j->rsa->e = e;
        return 0;
    }
    
    // got error
    lua_pushstring( L, errstr );
    
    return 1;
}

/*
    n   : modulus (n=pq)
    e   : Public exponent
    d   : Private exponent (d=e−1(modϕ(n)))
    p   : First prime
    q   : Second prime
    dp  : First exponent, used for Chinese remainder theorem (dP=d mod p−1)
    dQ  : Second exponent, used for CRT (dQ=d mod q−1)
    qinv: Coefficient, used for CRT (qinv=q−1 mod p)
    
    Public Key required: n, e
    Private Key required: n, e, d, p, q
*/
static int get_modexp_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    int mlen = 0;
    char *modulus = bignum64encode( j->rsa->n, &mlen );
    int elen = 0;
    char *exponent = bignum64encode( j->rsa->e, &elen );
    
    if( modulus && exponent ){
        lua_pushlstring( L, modulus, mlen );
        lua_pushlstring( L, exponent, elen );
        pdealloc( modulus );
        pdealloc( exponent );
        return 2;
    }
    
    pdealloc( modulus );
    pdealloc( exponent );

    // got error
    lua_pushnil( L );
    lua_pushnil( L );
    lua_pushstring( L, strerror( errno ) );
    
    return 3;
}


static int set_pubkey_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    size_t len = 0;
    const char *pem = luaL_checklstring( L, 2, &len );
    BIO *mem = BIO_new_mem_buf( (void*)pem, len );
    const char *errstr = NULL;
    
    if( !mem ){
        errstr = strerror( errno );
    }
    else
    {
        RSA *rsa = RSA_new();
        
        if( rsa )
        {
            char *nhex = NULL;
            char *ehex = NULL;
                
            if( !( PEM_read_bio_RSA_PUBKEY( mem, &rsa, NULL, NULL ) ) ||
                !( nhex = BN_bn2hex( rsa->n ) ) ||
                !( ehex = BN_bn2hex( rsa->e ) ) ||
                !BN_hex2bn( &j->rsa->n, nhex ) || 
                !BN_hex2bn( &j->rsa->e, ehex ) ){
                errstr = ERR_error_string( ERR_get_error(), NULL );
            }
            
            pdealloc( nhex );
            pdealloc( ehex );
            RSA_free( rsa );
        }
        else {
            errstr = ERR_error_string( ERR_get_error(), NULL );
        }
    
        BIO_free_all( mem );
    }
    
    // got error
    if( errstr ){
        lua_pushstring( L, errstr );
        return 1;
    }
    
    return 0;
}


static int get_pubkey_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    BIO *buf = BIO_new( BIO_s_mem() );
    
    if( buf ){
        BUF_MEM *ptr = NULL;
        
        PEM_write_bio_RSA_PUBKEY( buf, j->rsa );
        BIO_get_mem_ptr( buf, &ptr );
        lua_pushlstring( L, ptr->data, ptr->length - 1 );
        BIO_free_all( buf );
        return 1;
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, strerror( errno ) );
    
    return 2;
}


static int set_prvkey_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    size_t len = 0;
    const char *pem = luaL_checklstring( L, 2, &len );
    const char *pswd = NULL;
    BIO *mem = NULL;
    const char *errstr = NULL;
    
    // check password
    if( lua_gettop( L ) > 2 && !lua_isnil( L, 3 ) ){
        pswd = luaL_checkstring( L, 3 );
    }
    
    if( !( mem = BIO_new_mem_buf( (void*)pem, len ) ) ){
        errstr = strerror( errno );
    }
    else
    {
        OpenSSL_add_all_ciphers();
        if( !( PEM_read_bio_RSAPrivateKey( mem, &j->rsa, NULL, (void*)pswd ) ) ){
            SSL_load_error_strings();
            errstr = ERR_error_string( ERR_get_error(), NULL );
            ERR_free_strings();
        }
        else if( !( j->verified = RSA_check_key( j->rsa ) ) ){
            errstr = "invalid private key";
        }
        
        EVP_cleanup();
        BIO_free( mem );
        
    }
    
    // got error
    if( errstr ){
        lua_pushstring( L, errstr );
        return 1;
    }
    
    return 0;
}

/*
static int get_prvkey_lua( lua_State *L )
{
    jose_rsa_t *j = luaL_checkudata( L, 1, JOSE_RSA_MT );
    BIO *buf = BIO_new( BIO_s_mem() );
    
    if( buf ){
        BUF_MEM *ptr = NULL;
        
        PEM_write_bio_RSAPrivateKey( buf, j->rsa );
        BIO_get_mem_ptr( buf, &ptr );
        lua_pushlstring( L, ptr->data, ptr->length - 1 );
        BIO_free_all( buf );
        return 1;
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, strerror( errno ) );
    
    return 2;
}
*/


static int tostring_lua( lua_State *L )
{
    return jose_tostring( L, JOSE_RSA_MT );
}


static int gc_lua( lua_State *L )
{
    jose_rsa_t *j = lua_touserdata( L, 1 );
    
    RSA_free( j->rsa );
    
    return 0;
}


static int alloc_lua( lua_State *L )
{
    int nid = luaL_checkint( L, 1 );
    const char *errstr = "unsupported NID type";
    
    if( ( nid = jose_nid2rsa_nid( nid ) ) != -1 )
    {
        const EVP_MD *md = jose_nid2evp_md( nid );
        
        if( md )
        {
            jose_rsa_t *j = lua_newuserdata( L, sizeof( jose_rsa_t ) );
            
            if( j )
            {
                if( ( j->rsa = RSA_new() ) ){
                    j->nid = nid;
                    j->md = (EVP_MD*)md;
                    j->verified = 0;
                    luaL_getmetatable( L, JOSE_RSA_MT );
                    lua_setmetatable( L, -2 );
                    return 1;
                }
                errstr = ERR_error_string( ERR_get_error(), NULL );
            }
            else {
                errstr = strerror( errno );
            }
        }
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, errstr );
    
    return 2;
}


LUALIB_API int luaopen_jose_rsa( lua_State *L )
{
    struct luaL_Reg mmethod[] = {
        { "__gc", gc_lua },
        { "__tostring", tostring_lua },
        { NULL, NULL }
    };
    struct luaL_Reg method[] = {
        // use pem string
        { "setPrivateKey", set_prvkey_lua },
        //{ "getPrivateKey", get_prvkey_lua },
        { "setPublicKey", set_pubkey_lua },
        { "getPublicKey", get_pubkey_lua },
        // use modulus and exponent
        { "setModExp", set_modexp_lua },
        { "getModExp", get_modexp_lua },
        { "sign", sign_lua },
        { "verify", verify_lua },
        { NULL, NULL }
    };
    
    jose_define_mt( L, JOSE_RSA_MT, mmethod, method );
    // add allocation method
    lua_pushcfunction( L, alloc_lua );
    
    return 1;
}


