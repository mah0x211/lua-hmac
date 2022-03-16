local testcase = require('testcase')
local hmac = require('hmac')

local MSG = {
    'hello',
    ' ',
    'hmac',
    ' ',
    'world!',
}
local SHA = {
    sha224 = 'dfacba9733bd8ce28b603574eefa5f8b508aa95d8064a9930d9e5e28',
    sha256 = '331373f986ddc3162beca0e9688366b42b4bad8a6436e2d8910e76eea5676e7f',
    sha384 = 'b05485f15418e5b0f7eb02e5e5bc39f01977289d5fa6da71148b29112cfd98845991d851b509b29b74f3a70c8cf1ff09',

    sha512 = 'f441fe86e527500ddf9fa7a73bd597a20cad04ba3b18c1d580310490ac46fcff7c5831cbfcfcf954907c96a45a9f7ef84788a5cba1cf56c5d01f12d0963f15af',
}
local HMAC_SHA = {
    sha224 = 'e962836d0951faa48da9c66343510ee340fd72945d5eff1fc59e18f9',
    sha256 = '1f4f26b23327df8e770be106b16227201bcf1158427fce30015d5e5a1236a732',
    sha384 = 'af518ae1b0f65445c49abd2793fa719c129d624c37910856e2d7b4cccfcebfe48d5e8cf96682a56d3b1f99cd72094dcf',
    sha512 = '80783b4073e203966a31b4232daa077fad19c18b2aa192ecfe81bad61a2d183b2c5b8cea02ae3f72c25e259c6784ad4a13f1af300ed0cb7627aee6cd3b63b79c',
}

function testcase.create_context()
    -- test that create context
    for k, new in pairs(hmac) do
        local ctx = new()
        assert.match(tostring(ctx), '^hmac.' .. k .. ': ', false)
    end
end

function testcase.sha()
    for k, new in pairs(hmac) do
        local ctx = new()
        -- test that create digest with update
        ctx:update(table.concat(MSG, ''))
        local digest1 = ctx:final()
        assert.equal(digest1, SHA[k])

        -- test that initialize context
        ctx:init()

        -- test that create digest with multi update
        for _, s in ipairs(MSG) do
            ctx:update(s)
        end
        local digest2 = ctx:final()
        assert.equal(digest1, digest2)
    end
end

function testcase.hmac()
    local KEY = 'foo bar baz'

    for k, new in pairs(hmac) do
        local ctx = new(KEY)
        -- test that create digest with update
        ctx:update(table.concat(MSG, ''))
        local digest1 = ctx:final()
        assert.equal(digest1, HMAC_SHA[k])

        -- test that initialize context
        ctx:init()

        -- test that create digest with multi update
        for _, s in ipairs(MSG) do
            ctx:update(s)
        end
        local digest2 = ctx:final()
        assert.equal(digest1, digest2)

        -- test that initialize context with new key
        ctx:init('new-key')
        ctx:update(table.concat(MSG, ''))
        digest1 = ctx:final()
        assert.not_equal(digest1, HMAC_SHA[k])
    end
end

