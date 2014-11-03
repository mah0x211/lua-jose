package = "jose"
version = "scm-1"
source = {
    url = "git://github.com/mah0x211/lua-jose.git"
}
description = {
    summary = "JOSE(JSON Object Signing and Encryption) module",
    homepage = "https://github.com/mah0x211/lua-jose", 
    license = "MIT/X11",
    maintainer = "Masatoshi Teruya"
}
dependencies = {
    "lua >= 5.1",
    "lua-cjson >= 2.1.0"
}
external_dependencies = {
    OPENSSL = {
        header = "openssl/ssl.h",
        library = "ssl"
    }
}
build = {
    type = "builtin",
    modules = {
        jose = "jose.lua",
        ["jose.base64"] = {
            sources = { 
                "src/base64.c",
            }
        },
        ["jose.hex"] = {
            sources = { 
                "src/hex.c",
            }
        },
        ["jose.bin"] = {
            sources = { 
                "src/bin.c",
            }
        },
        ["jose.digest"] = {
            sources = { 
                "src/bin.c",
                "src/digest.c"
            },
            libraries = {
                "ssl"
            },
            incdirs = {
                "$(OPENSSL_INCDIR)"
            },
            libdirs = {
                "$(OPENSSL_LIBDIR)"
            }
        },
        ["jose.pkey"] = {
            sources = { 
                "src/pkey.c"
            },
            libraries = {
                "ssl"
            },
            incdirs = {
                "$(OPENSSL_INCDIR)"
            },
            libdirs = {
                "$(OPENSSL_LIBDIR)"
            }
        }
    }
}

