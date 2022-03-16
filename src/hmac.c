/**
 *  Copyright (C) 2022 Masatoshi Fukunaga
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

#include "../deps/hmac/hmac_sha2.h"
#include <lauxhlib.h>

typedef struct {
#define T_SHA224 224
#define T_SHA256 256
#define T_SHA384 384
#define T_SHA512 512
    int bit;
    int ref;
    unsigned int len;
    const unsigned char *key;
    hmac_sha512_ctx ctx;
} lhmac_ctx;

#define MODULE_MT "hmac"

static int gc_lua(lua_State *L)
{
    lhmac_ctx *hctx = lauxh_checkudata(L, 1, MODULE_MT);
    lauxh_unref(L, hctx->ref);
    return 0;
}

static int tostring_lua(lua_State *L)
{
    lhmac_ctx *hctx = lauxh_checkudata(L, 1, MODULE_MT);

#define push_string(bits)                                                      \
 do {                                                                          \
  lua_pushfstring(L, MODULE_MT ".sha" #bits ": %p", hctx);                     \
  return 1;                                                                    \
 } while (0)

    switch (hctx->bit) {
    case T_SHA224:
        push_string(224);
    case T_SHA256:
        push_string(256);
    case T_SHA384:
        push_string(384);
    case T_SHA512:
        push_string(512);
    default:
        return lauxh_argerror(L, 1, "invalid context");
    }

#undef push_string
}

// dest length must be greater than len*2
static inline int digest2hex(lua_State *L, unsigned char *digest, size_t len)
{
    static const char dec2hex[16] = "0123456789abcdef";
    size_t hexlen                 = len * 2;
    luaL_Buffer b                 = {0};
    unsigned char *buf            = NULL;
    unsigned char *ptr            = NULL;
    size_t i                      = 0;
    size_t n                      = 0;

    luaL_buffinit(L, &b);
    buf = (unsigned char *)luaL_prepbuffer(&b);
    if (hexlen > LUAL_BUFFERSIZE) {
        n = hexlen / LUAL_BUFFERSIZE;
        for (size_t k = 0; k < n; k++) {
            ptr = buf;
            for (; i < len; i++) {
                *ptr++ = dec2hex[digest[i] >> 4];
                *ptr++ = dec2hex[digest[i] & 0xf];
            }
            luaL_addsize(&b, (uintptr_t)ptr - (uintptr_t)buf);
            buf = (unsigned char *)luaL_prepbuffer(&b);
        }
    }

    ptr = buf;
    for (; i < len; i++) {
        *ptr++ = dec2hex[digest[i] >> 4];
        *ptr++ = dec2hex[digest[i] & 0xf];
    }
    luaL_addsize(&b, (uintptr_t)ptr - (uintptr_t)buf);
    luaL_pushresult(&b);

    return 1;
}

static int final_lua(lua_State *L)
{
    static unsigned char digest[SHA512_DIGEST_SIZE];
    lhmac_ctx *hctx = lauxh_checkudata(L, 1, MODULE_MT);
    size_t len      = SHA512_DIGEST_SIZE;

#define final_context(bits)                                                    \
 do {                                                                          \
  len = SHA##bits##_DIGEST_SIZE;                                               \
  if ((hctx)->key) {                                                           \
   hmac_sha##bits##_final((hmac_sha##bits##_ctx *)&(hctx)->ctx, digest, len);  \
  } else {                                                                     \
   sha##bits##_final((sha##bits##_ctx *)&(hctx)->ctx, digest);                 \
  }                                                                            \
 } while (0)

    switch (hctx->bit) {
    case T_SHA224:
        final_context(224);
        break;
    case T_SHA256:
        final_context(256);
        break;
    case T_SHA384:
        final_context(384);
        break;
    case T_SHA512:
        final_context(512);
        break;
    default:
        return luaL_error(L, "unknown bit type: %d", hctx->bit);
    }

#undef final_context

    return digest2hex(L, digest, len);
}

static int update_lua(lua_State *L)
{
    lhmac_ctx *hctx = lauxh_checkudata(L, 1, MODULE_MT);
    size_t len      = 0;
    const unsigned char *msg =
        (const unsigned char *)lauxh_checklstring(L, 2, &len);

    if (len > UINT_MAX) {
        return lauxh_argerror(
            L, 2, "message length must be less than or equal to %d", UINT_MAX);
    }

#define update_context(bits)                                                   \
 do {                                                                          \
  if ((hctx)->key) {                                                           \
   hmac_sha##bits##_update((hmac_sha##bits##_ctx *)&(hctx)->ctx, msg, len);    \
  } else {                                                                     \
   sha##bits##_update((sha##bits##_ctx *)&(hctx)->ctx, msg, len);              \
  }                                                                            \
 } while (0)

    switch (hctx->bit) {
    case T_SHA224:
        update_context(224);
        break;
    case T_SHA256:
        update_context(256);
        break;
    case T_SHA384:
        update_context(384);
        break;
    case T_SHA512:
        update_context(512);
        break;
    default:
        return luaL_error(L, "unknown bit type: %d", hctx->bit);
    }

#undef update_context

    return 0;
}

static inline void init_context(lua_State *L, lhmac_ctx *hctx, int reinit)
{
#define init_bit_context(bits)                                                 \
 do {                                                                          \
  if ((hctx)->key) {                                                           \
   if (reinit) {                                                               \
    hmac_sha##bits##_reinit((hmac_sha##bits##_ctx *)&(hctx)->ctx);             \
   } else {                                                                    \
    hmac_sha##bits##_init((hmac_sha##bits##_ctx *)&(hctx)->ctx, (hctx)->key,   \
                          (hctx)->len);                                        \
   }                                                                           \
  } else {                                                                     \
   sha##bits##_init((sha##bits##_ctx *)&(hctx)->ctx);                          \
  }                                                                            \
 } while (0)

    switch (hctx->bit) {
    case T_SHA224:
        init_bit_context(224);
        break;
    case T_SHA256:
        init_bit_context(256);
        break;
    case T_SHA384:
        init_bit_context(384);
        break;
    case T_SHA512:
        init_bit_context(512);
        break;
    default:
        luaL_error(L, "unknown bit type: %d", hctx->bit);
    }

#undef init_bit_context
}

static int init_lua(lua_State *L)
{
    lhmac_ctx *hctx = lauxh_checkudata(L, 1, MODULE_MT);
    size_t len      = 0;
    const char *key = lauxh_optlstring(L, 2, NULL, &len);
    int reinit      = key == NULL;

    if (!reinit) {
        if (len > UINT_MAX) {
            return lauxh_argerror(
                L, 2, "key length must be less than or equal to %d", UINT_MAX);
        }
        // remove current key
        hctx->len = (unsigned int)len;
        hctx->key = NULL;
        hctx->ref = lauxh_unref(L, hctx->ref);
        if (len) {
            // set new key
            lua_settop(L, 2);
            hctx->key = (const unsigned char *)key;
            hctx->ref = lauxh_ref(L);
        }
        lua_settop(L, 1);
    }

    init_context(L, hctx, reinit);

    return 0;
}

static int new_lua(lua_State *L)
{
    size_t len      = 0;
    const char *key = lauxh_optlstring(L, 1, NULL, &len);
    lhmac_ctx *hctx = NULL;

    if (len) {
        if (len > UINT_MAX) {
            return lauxh_argerror(
                L, 1, "key length must be less than or equal to %d", UINT_MAX);
        }
        lua_settop(L, 1);
    } else {
        lua_settop(L, 0);
    }
    hctx = lua_newuserdata(L, sizeof(lhmac_ctx));
    lua_pushvalue(L, lua_upvalueindex(1));
    *hctx = (lhmac_ctx){
        .ref = LUA_NOREF,
        .len = (unsigned int)len,
        .key = (const unsigned char *)key,
        .bit = lua_tointeger(L, -1),
        .ctx = {0},
    };
    lua_pop(L, 1);
    init_context(L, hctx, 0);
    lauxh_setmetatable(L, MODULE_MT);

    return 1;
}

LUALIB_API int luaopen_hmac(lua_State *L)
{
    if (luaL_newmetatable(L, MODULE_MT)) {
        struct luaL_Reg mmethod[] = {
            {"__gc",       gc_lua      },
            {"__tostring", tostring_lua},
            {NULL,         NULL        }
        };
        struct luaL_Reg method[] = {
            {"init",   init_lua  },
            {"update", update_lua},
            {"final",  final_lua },
            {NULL,     NULL      }
        };
        struct luaL_Reg *ptr = mmethod;

        for (; ptr->name; ptr++) {
            lauxh_pushfn2tbl(L, ptr->name, ptr->func);
        }
        // methods
        lua_pushstring(L, "__index");
        lua_newtable(L);
        for (ptr = method; ptr->name; ptr++) {
            lauxh_pushfn2tbl(L, ptr->name, ptr->func);
        }
        lua_rawset(L, -3);
        lua_pop(L, 1);
    }

    lua_newtable(L);
#define push_closure(name, type)                                               \
 do {                                                                          \
  lua_pushinteger(L, (type));                                                  \
  lua_pushcclosure(L, new_lua, 1);                                             \
  lua_setfield(L, -2, (name));                                                 \
 } while (0)
    push_closure("sha224", T_SHA224);
    push_closure("sha256", T_SHA256);
    push_closure("sha384", T_SHA384);
    push_closure("sha512", T_SHA512);
#undef push_closure

    return 1;
}
