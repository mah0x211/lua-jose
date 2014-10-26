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
 *  generate.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/27.
 *
 */

#include "jose.h"

#define set_osslerror( L ) do { \
    SSL_load_error_strings(); \
    lua_pushnil( L ); \
    lua_pushstring( L, ERR_error_string( ERR_get_error(), NULL ) ); \
    ERR_free_strings(); \
}while(0)


static int gen_rsa( lua_State *L )
{
    // bit
    int modulus = luaL_checkint( L, 1 );
    int exponent = luaL_checkint( L, 2 );
    const EVP_CIPHER *enc = NULL;
    size_t len = 0;
    unsigned char *pswd = NULL;
    RSA *rsa = NULL;
    int rc = 2;
    
    // check cipher
    if( lua_gettop( L ) > 2 && !lua_isnil( L, 3 ) )
    {
        const char *cipher = luaL_checkstring( L, 3 );
        
        enc = EVP_get_cipherbyname( cipher );
        if( !enc ){
            lua_pushnil( L );
            lua_pushfstring( L, "unsupported cipher: %s", cipher );
            return 2;
        }
        // password required
        pswd = (unsigned char*)luaL_checklstring( L, 4, &len );
    }
    
    if( !( rsa = RSA_generate_key( modulus, exponent, 0, 0 ) ) ){
        set_osslerror( L );
    }
    else
    {
        BIO *bio = BIO_new( BIO_s_mem() );
        
        if( !bio ){
            set_osslerror( L );
        }
        else
        {
            BUF_MEM *ptr = NULL;
            
            lua_createtable( L, 0, 2 );
            // failed to generate private key
            if( PEM_write_bio_RSAPrivateKey( bio, rsa, enc, pswd, (int)len,
                                             NULL, NULL ) != 1 ){
                set_osslerror( L );
            }
            else
            {
                BIO_get_mem_ptr( bio, &ptr );
                lstate_strn2tbl( L, "private", ptr->data, ptr->length );
                
                // reset buffer cursor
                ptr->length = 0;
                // failed to generate public key
                if( PEM_write_bio_RSA_PUBKEY( bio, rsa ) != 1 ){
                    set_osslerror( L );
                }
                else {
                    BIO_get_mem_ptr( bio, &ptr );
                    lstate_strn2tbl( L, "public", ptr->data, ptr->length );
                    rc = 1;
                }
            }
            
            BIO_free_all( bio );
        }
        
        RSA_free( rsa );
    }
    
    return rc;
}


#define generate_lua( L, generator ) ({ \
    int rc = 2; \
    if( RAND_load_file( "/dev/urandom", 1024 ) != 1024 ){ \
        lua_pushnil( L ); \
        lua_pushstring( L, "failed to RAND_load_file: /dev/urandom" ); \
    } \
    else { \
        OpenSSL_add_all_ciphers(); \
        rc = generator( L ); \
        EVP_cleanup(); \
        RAND_cleanup(); \
    } \
    rc; \
})


static int rsa_lua( lua_State *L )
{
    return generate_lua( L, gen_rsa );
}


LUALIB_API int luaopen_jose_generate( lua_State *L )
{
    struct luaL_Reg method[] = {
        { "rsa", rsa_lua },
        { NULL, NULL }
    };
    
    return jose_define_method( L, method );
}


