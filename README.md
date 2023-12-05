# lua-hmac

[![test](https://github.com/mah0x211/lua-hmac/actions/workflows/test.yml/badge.svg)](https://github.com/mah0x211/lua-hmac/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/mah0x211/lua-hmac/branch/master/graph/badge.svg)](https://codecov.io/gh/mah0x211/lua-hmac)


Compute the SHA-224, SHA-256, SHA-384, and SHA-512 message digests and the Hash-based Message Authentication Code (HMAC).

this module is Lua binding for https://github.com/ogay/hmac.

## Installation

```sh
luarocks install hmac
```

## Usage

```lua
local hmac = require('hmac')
```

## Create a context

```lua
ctx = hmac.sha224( [key] )
ctx = hmac.sha256( [key] )
ctx = hmac.sha384( [key] )
ctx = hmac.sha512( [key] )
```

**Parameters**

- `key:string`: the secret key used to calculate the HMAC value. If `nil` is specified, only the message digest is computed.

**Returns**

- `ctx:hmac.sha<N>`: the context.


## Input a message

```lua
ctx = ctx:update( [msg] )
```

**Parameters**

- `msg:string`: a message string.

**Returns**

- `ctx:hmac.sha<N>`: the context.


## Generate a digest string

```lua
local s = ctx:final( [tobinary] )
```

**Parameters**

- `tobinary:boolean`: If `true` is specified, a binary digest string is returned. otherwise, return the hexadecimal digest string. (default: `false`)

**Returns**

- `s:string`: a digest string.



## Reset a context

```lua
ctx = ctx:init( [key] )
```

**Parameters**

- `key:string`: the new secret key used to calculate the HMAC value.
  - if a `nil` is specified, initialize the internal data and the context can be reused.
  - if an empty-string (`''`) is specified, the current secret key is cleared and the context will compute only the message digest.

**Returns**

- `ctx:hmac.sha<N>`: the context.
