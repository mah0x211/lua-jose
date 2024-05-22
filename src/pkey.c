/**
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
 *  pkey.c
 *  lua-jose
 *
 *  Created by Masatoshi Teruya on 14/10/27.
 */

#include "jose_bin.h"
#include "jose_pkey.h"

#define MODULE_MT JOSE_PKEY_MT

static inline char *bignum64encode(BIGNUM *bn, int *len)
{
    char *bn64         = NULL;
    size_t bytes       = BN_num_bytes(bn);
    unsigned char *buf = pnalloc(bytes, unsigned char);

    if (buf) {
        bytes = BN_bn2bin(bn, buf);
        if ((bn64 = b64m_encode_url(buf, &bytes))) {
            *len = bytes;
        }
        pdealloc(buf);
    }

    return bn64;
}

static inline BIGNUM *bignum64decode(const unsigned char *src, size_t len)
{
    BIGNUM *bn         = NULL;
    unsigned char *dec = (unsigned char *)b64m_decode_url(src, &len);

    if (dec) {
        if (len) {
            bn = BN_bin2bn(dec, len, NULL);
        }
        pdealloc(dec);
    }

    return bn;
}

#define get_b64component(ptr, field, L, idx)                                   \
    ({                                                                         \
        int rc             = 0;                                                \
        size_t len         = 0;                                                \
        unsigned char *val = NULL;                                             \
        lua_getfield(L, idx, #field);                                          \
        if (lua_isstring(L, -1)) {                                             \
            val = (unsigned char *)lua_tolstring(L, -1, &len);                 \
            if (!((ptr)->field = bignum64decode(val, len))) {                  \
                rc = -1;                                                       \
            }                                                                  \
        }                                                                      \
        rc;                                                                    \
    })

#define set_b64component(ptr, field, L)                                        \
    ({                                                                         \
        int rc = 0;                                                            \
        if ((ptr)->field) {                                                    \
            int len   = 0;                                                     \
            char *val = bignum64encode((ptr)->field, &len);                    \
            if (val) {                                                         \
                lauxh_pushstr2tbl(L, #field, val);                             \
                pdealloc(val);                                                 \
            } else {                                                           \
                rc = -1;                                                       \
            }                                                                  \
        }                                                                      \
        rc;                                                                    \
    })

static int verify_lua(lua_State *L)
{
    jose_pkey_t *j   = luaL_checkudata(L, 1, MODULE_MT);
    const char *name = luaL_checkstring(L, 2);
    jose_bin_t *sig  = luaL_checkudata(L, 3, JOSE_BIN_MT);
    size_t len       = 0;
    const char *msg  = luaL_checklstring(L, 4, &len);
    const EVP_MD *md = EVP_get_digestbyname(name);
    EVP_MD_CTX *ctx  = NULL;
    int rc           = 0;

    // invalid digest name
    if (!md) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "unsupported digest algorithm: %s", name);
        return 2;
    } else if (!j->pk) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "pkey is not initialized");
        return 2;
    } else if (!(ctx = EVP_MD_CTX_create())) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, strerror(errno));
        return 2;
    } else if (EVP_VerifyInit(ctx, md) != 1 ||
               EVP_VerifyUpdate(ctx, msg, len) != 1) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        EVP_MD_CTX_cleanup(ctx);
        EVP_MD_CTX_destroy(ctx);
        return 2;
    } else if ((rc = EVP_VerifyFinal(ctx, (const unsigned char *)sig->data,
                                     (unsigned int)sig->len, j->pk)) < 0) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        EVP_MD_CTX_cleanup(ctx);
        EVP_MD_CTX_destroy(ctx);
        return 2;
    }

    lua_pushboolean(L, rc);
    EVP_MD_CTX_cleanup(ctx);
    EVP_MD_CTX_destroy(ctx);

    return 1;
}

static int sign_lua(lua_State *L)
{
    jose_pkey_t *j     = luaL_checkudata(L, 1, MODULE_MT);
    const char *name   = luaL_checkstring(L, 2);
    size_t len         = 0;
    const char *msg    = luaL_checklstring(L, 3, &len);
    const EVP_MD *md   = EVP_get_digestbyname(name);
    unsigned char *sig = NULL;
    EVP_MD_CTX *ctx    = NULL;

    // invalid digest name
    if (!md) {
        lua_pushnil(L);
        lua_pushfstring(L, "unsupported digest algorithm: %s", name);
        return 2;
    } else if (!j->pk) {
        lua_pushnil(L);
        lua_pushstring(L, "pkey is not initialized");
        return 2;
    } else if (!jose_pkey_has_privatekey(j->pk)) {
        lua_pushnil(L);
        lua_pushstring(L, "private key is not defined");
        return 2;
    } else if (!(ctx = EVP_MD_CTX_create()) ||
               !(sig = pnalloc(EVP_PKEY_size(j->pk), unsigned char))) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        if (ctx) {
            EVP_MD_CTX_cleanup(ctx);
            EVP_MD_CTX_destroy(ctx);
        }
        return 2;
    } else if (EVP_SignInit(ctx, md) != 1 ||
               EVP_SignUpdate(ctx, msg, len) != 1 ||
               EVP_SignFinal(ctx, sig, (unsigned int *)&len, j->pk) != 1) {
        lua_pushnil(L);
        jose_push_sslerror(L);
        EVP_MD_CTX_cleanup(ctx);
        EVP_MD_CTX_destroy(ctx);
        pdealloc(sig);
        return 2;
    } else if (!jose_bin_alloc(L, (char *)sig, len)) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        EVP_MD_CTX_cleanup(ctx);
        EVP_MD_CTX_destroy(ctx);
        pdealloc(sig);
        return 2;
    }

    EVP_MD_CTX_cleanup(ctx);
    EVP_MD_CTX_destroy(ctx);

    return 1;
}

/*
    n   : modulus (n=pq)
    e   : Public exponent
    d   : Private exponent (d=e−1(modϕ(n)))
    p   : First prime
    q   : Second prime
    dmp1: First exponent, used for Chinese remainder theorem (dP=d mod p−1)
    dmq1: Second exponent, used for CRT (dQ=d mod q−1)
    iqmp: Coefficient, used for CRT (qinv=q−1 mod p)

    JWK https://tools.ietf.org/html/draft-ietf-jose-json-web-key-36
        dp: dmp1
        dq: dmq1
        qi: iqmp

    Public Key required: n, e
    Private Key required: n, e, d, p, q
*/

static int set_rsa_component_lua(lua_State *L)
{
    jose_pkey_t *j = luaL_checkudata(L, 1, MODULE_MT);
    EVP_PKEY *pk   = NULL;
    RSA *rsa       = NULL;

    luaL_checktype(L, 2, LUA_TTABLE);
    if (!(rsa = RSA_new()) || get_b64component(rsa, n, L, 2) == -1 ||
        get_b64component(rsa, e, L, 2) == -1 ||
        get_b64component(rsa, d, L, 2) == -1 ||
        get_b64component(rsa, p, L, 2) == -1 ||
        get_b64component(rsa, q, L, 2) == -1 ||
        get_b64component(rsa, dmp1, L, 2) == -1 ||
        get_b64component(rsa, dmq1, L, 2) == -1 ||
        get_b64component(rsa, iqmp, L, 2) == -1 || !(pk = EVP_PKEY_new())) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, strerror(errno));
        if (rsa) {
            RSA_free(rsa);
        }
        return 2;
    } else if (EVP_PKEY_assign_RSA(pk, rsa) != 1) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        EVP_PKEY_free(pk);
        RSA_free(rsa);
        return 2;
    } else if (j->pk) {
        EVP_PKEY_free(j->pk);
    }

    j->pk = pk;
    lua_pushboolean(L, 1);

    return 1;
}

static inline int get_rsa_component_lua(lua_State *L, EVP_PKEY *pk)
{
    RSA *rsa = EVP_PKEY_get1_RSA(pk);

    lua_newtable(L);
    if (set_b64component(rsa, n, L) == -1 ||
        set_b64component(rsa, e, L) == -1 ||
        set_b64component(rsa, d, L) == -1 ||
        set_b64component(rsa, p, L) == -1 ||
        set_b64component(rsa, q, L) == -1 ||
        set_b64component(rsa, dmp1, L) == -1 ||
        set_b64component(rsa, dmq1, L) == -1 ||
        set_b64component(rsa, iqmp, L) == -1) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        RSA_free(rsa);
        return 2;
    }
    RSA_free(rsa);

    return 1;
}

static int get_component_lua(lua_State *L)
{
    jose_pkey_t *j = luaL_checkudata(L, 1, MODULE_MT);

    if (!j->pk) {
        lua_pushnil(L);
        lua_pushstring(L, "pkey is not initialized");
        return 2;
    }

    // check key type
    switch (EVP_PKEY_type(j->pk->type)) {
    case EVP_PKEY_RSA:
        return get_rsa_component_lua(L, j->pk);
        break;
    default:
        lua_pushnil(L);
        lua_pushfstring(L, "unsupported type");
        return 2;
    }
}

static int get_public_pem_lua(lua_State *L)
{
    jose_pkey_t *j = luaL_checkudata(L, 1, MODULE_MT);
    BIO *mem       = NULL;
    BUF_MEM *ptr   = NULL;

    if (!j->pk) {
        lua_pushnil(L);
        lua_pushstring(L, "pkey is not initialized");
        return 2;
    } else if (!(mem = BIO_new(BIO_s_mem()))) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    } else if (PEM_write_bio_PUBKEY(mem, j->pk) != 1) {
        BIO_free_all(mem);
        lua_pushnil(L);
        jose_push_sslerror(L);
        return 2;
    }

    BIO_get_mem_ptr(mem, &ptr);
    lua_pushlstring(L, ptr->data, ptr->length);
    BIO_free_all(mem);

    return 1;
}

static inline int get_rsa_private_pem_lua(lua_State *L, EVP_PKEY *pk)
{
    RSA *rsa = EVP_PKEY_get1_RSA(pk);

    if (jose_rsa_has_privatekey(rsa)) {
        const char *name       = NULL;
        size_t len             = 0;
        const char *pswd       = NULL;
        const EVP_CIPHER *ciph = NULL;
        BIO *mem               = NULL;
        BUF_MEM *ptr           = NULL;

        if (jose_getopt_cipher(L, 2, &name, &ciph, &pswd, &len) == -1) {
            lua_pushnil(L);
            lua_pushfstring(L, "unsupported cipher: %s", name);
            RSA_free(rsa);
            return 2;
        } else if (!(mem = BIO_new(BIO_s_mem()))) {
            lua_pushnil(L);
            lua_pushstring(L, strerror(errno));
            RSA_free(rsa);
            return 2;
        } else if (PEM_write_bio_RSAPrivateKey(mem, rsa, ciph,
                                               (unsigned char *)pswd, (int)len,
                                               NULL, NULL) != 1) {
            lua_pushnil(L);
            jose_push_sslerror(L);
            BIO_free_all(mem);
            RSA_free(rsa);
            return 2;
        }

        BIO_get_mem_ptr(mem, &ptr);
        lua_pushlstring(L, ptr->data, ptr->length);
        BIO_free_all(mem);
        RSA_free(rsa);
        return 1;
    }

    lua_pushnil(L);
    lua_pushstring(L, "private key is not defined");
    RSA_free(rsa);

    return 2;
}

static inline int get_dsa_private_pem_lua(lua_State *L, EVP_PKEY *pk)
{
    DSA *dsa = EVP_PKEY_get1_DSA(pk);

    if (jose_dsa_has_privatekey(dsa)) {
        const char *name       = NULL;
        size_t len             = 0;
        const char *pswd       = NULL;
        const EVP_CIPHER *ciph = NULL;
        BIO *mem               = NULL;
        BUF_MEM *ptr           = NULL;

        if (jose_getopt_cipher(L, 2, &name, &ciph, &pswd, &len) == -1) {
            lua_pushnil(L);
            lua_pushfstring(L, "unsupported cipher: %s", name);
            DSA_free(dsa);
            return 2;
        } else if (!(mem = BIO_new(BIO_s_mem()))) {
            lua_pushnil(L);
            lua_pushstring(L, strerror(errno));
            DSA_free(dsa);
            return 2;
        } else if (PEM_write_bio_DSAPrivateKey(mem, dsa, ciph,
                                               (unsigned char *)pswd, (int)len,
                                               NULL, NULL) != 1) {
            lua_pushnil(L);
            jose_push_sslerror(L);
            BIO_free_all(mem);
            DSA_free(dsa);
            return 2;
        }

        BIO_get_mem_ptr(mem, &ptr);
        lua_pushlstring(L, ptr->data, ptr->length);
        BIO_free_all(mem);
        DSA_free(dsa);
        return 1;
    }

    lua_pushnil(L);
    lua_pushstring(L, "private key is not defined");
    DSA_free(dsa);
    return 2;
}

static int get_private_pem_lua(lua_State *L)
{
    jose_pkey_t *j = luaL_checkudata(L, 1, MODULE_MT);

    if (!j->pk) {
        lua_pushnil(L);
        lua_pushstring(L, "pkey is not initialized");
        return 2;
    }

    // check key type
    switch (EVP_PKEY_type(j->pk->type)) {
    case EVP_PKEY_RSA:
        return get_rsa_private_pem_lua(L, j->pk);
        break;
    case EVP_PKEY_DSA:
        return get_dsa_private_pem_lua(L, j->pk);
        break;
    default:
        lua_pushnil(L);
        lua_pushfstring(L, "unsupported type");
        return 2;
    }
}

typedef EVP_PKEY *(pem_reader)(BIO *, EVP_PKEY **, pem_password_cb *, void *);

static inline int set_pem_lua(lua_State *L, pem_reader *reader)
{
    jose_pkey_t *j  = luaL_checkudata(L, 1, MODULE_MT);
    size_t len      = 0;
    const char *pem = luaL_checklstring(L, 2, &len);
    void *pswd      = (void *)luaL_optstring(L, 3, NULL);
    BIO *mem        = NULL;
    EVP_PKEY *pk    = NULL;

    if (!(mem = BIO_new_mem_buf((void *)pem, len))) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, strerror(errno));
        return 2;
    } else if (!(pk = reader(mem, NULL, NULL, pswd))) {
        BIO_free_all(mem);
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        return 2;
    } else if (j->pk) {
        EVP_PKEY_free(j->pk);
    }

    BIO_free_all(mem);
    j->pk = pk;
    lua_pushboolean(L, 1);

    return 1;
}

static int set_public_pem_lua(lua_State *L)
{
    return set_pem_lua(L, PEM_read_bio_PUBKEY);
}

static int set_private_pem_lua(lua_State *L)
{
    return set_pem_lua(L, PEM_read_bio_PrivateKey);
}

static int initas_dsa_lua(lua_State *L)
{
    jose_pkey_t *j    = luaL_checkudata(L, 1, MODULE_MT);
    int bits          = luaL_checkint(L, 2);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    EVP_PKEY *param   = NULL;
    EVP_PKEY *pk      = NULL;

    if (!ctx) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        return 2;
    } else if (EVP_PKEY_paramgen_init(ctx) != 1 ||
               EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, bits) != 1 ||
               EVP_PKEY_paramgen(ctx, &param) != 1) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        EVP_PKEY_CTX_free(ctx);
        return 2;
    }
    EVP_PKEY_CTX_free(ctx);

    if (!(ctx = EVP_PKEY_CTX_new(param, NULL))) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        EVP_PKEY_free(param);
        return 2;
    }
    EVP_PKEY_free(param);

    if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &pk) != 1) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        EVP_PKEY_CTX_free(ctx);
        return 2;
    } else if (j->pk) {
        EVP_PKEY_free(j->pk);
    }
    EVP_PKEY_CTX_free(ctx);

    j->pk = pk;
    lua_pushboolean(L, 1);

    return 1;
}

static int initas_rsa_lua(lua_State *L)
{
    jose_pkey_t *j    = luaL_checkudata(L, 1, MODULE_MT);
    int bits          = luaL_checkint(L, 2);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pk      = NULL;

    if (!ctx) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        return 2;
    } else if (EVP_PKEY_keygen_init(ctx) != 1 ||
               EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) != 1 ||
               EVP_PKEY_keygen(ctx, &pk) != 1) {
        lua_pushboolean(L, 0);
        jose_push_sslerror(L);
        EVP_PKEY_CTX_free(ctx);
        return 2;
    } else if (j->pk) {
        EVP_PKEY_free(j->pk);
    }

    EVP_PKEY_CTX_free(ctx);
    j->pk = pk;

    lua_pushboolean(L, 1);
    return 1;
}

static int typeof_lua(lua_State *L)
{
    jose_pkey_t *j = luaL_checkudata(L, 1, MODULE_MT);

    if (!j->pk) {
        lua_pushnil(L);
        lua_pushstring(L, "pkey is not initialized");
        return 2;
    }

    // check key type
    switch (EVP_PKEY_type(j->pk->type)) {
    case EVP_PKEY_RSA:
        lua_pushstring(L, "RSA");
        break;
    case EVP_PKEY_EC:
        lua_pushstring(L, "EC");
        break;
    case EVP_PKEY_DH:
        lua_pushstring(L, "DH");
        break;
    case EVP_PKEY_DSA:
        lua_pushstring(L, "DSA");
        break;
    case EVP_PKEY_HMAC:
        lua_pushstring(L, "HMAC");
        break;
    case EVP_PKEY_CMAC:
        lua_pushstring(L, "CMAC");
        break;
    default:
        lua_pushnil(L);
        lua_pushfstring(L, "unknown type");
        return 2;
    }

    return 1;
}

static int tostring_lua(lua_State *L)
{
    return jose_tostring(L, MODULE_MT);
}

static int gc_lua(lua_State *L)
{
    jose_pkey_t *j = lua_touserdata(L, 1);

    if (j->pk) {
        EVP_PKEY_free(j->pk);
    }

    return 0;
}

static int alloc_lua(lua_State *L)
{
    jose_pkey_t *j = lua_newuserdata(L, sizeof(jose_pkey_t));

    if (!j) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }

    j->pk = NULL;
    luaL_getmetatable(L, MODULE_MT);
    lua_setmetatable(L, -2);

    return 1;
}

static void add_cipher_name(const EVP_CIPHER *ciph, const char *from,
                            const char *to, void *arg)
{
    if (!to) {
        lua_State *L = (lua_State *)arg;
        static char fname[255];

        jose_conv2constant_name(fname, from, strlen(from));
        lauxh_pushstr2tbl(L, fname, from);
    }
}

LUALIB_API int luaopen_jose_pkey(lua_State *L)
{
    struct luaL_Reg mmethod[] = {
        {"__gc",       gc_lua      },
        {"__tostring", tostring_lua},
        {NULL,         NULL        }
    };
    struct luaL_Reg method[] = {
        // attributes
        {"typeof",          typeof_lua           },
        // initialize
        {"initAsRSA",       initas_rsa_lua       },
        //{ "initAsDSA", initas_dsa_lua },
        // use pem string
        {"setPrivatePEM",   set_private_pem_lua  },
        {"setPublicPEM",    set_public_pem_lua   },
        {"getPrivatePEM",   get_private_pem_lua  },
        {"getPublicPEM",    get_public_pem_lua   },
        // use modulus and exponent
        {"getComponent",    get_component_lua    },
        {"setRSAComponent", set_rsa_component_lua},
        // signature
        {"sign",            sign_lua             },
        {"verify",          verify_lua           },
        {NULL,              NULL                 }
    };

    OpenSSL_add_all_ciphers();
    jose_bin_define(L);
    jose_define_mt(L, MODULE_MT, mmethod, method);

    lua_newtable(L);
    EVP_CIPHER_do_all_sorted(add_cipher_name, (void *)L);
    lauxh_pushfn2tbl(L, "new", alloc_lua);

    return 1;
}
