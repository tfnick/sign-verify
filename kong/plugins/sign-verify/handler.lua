local BasePlugin = require "kong.plugins.base_plugin"
local singletons = require "kong.singletons"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"
-- fix bug for 'KONG_HEADER_FILTER_STARTED_AT' (a nil value)
local ngx_now     = ngx.now
local update_time = ngx.update_time
local ngx_set_header = ngx.req.set_header

local SignVerifyHandler = BasePlugin:extend()

-- the number is more big and the priority is more high
SignVerifyHandler.PRIORITY = 9990

local function get_now()
    update_time()
    return ngx_now() * 1000 -- time is kept in seconds with millisecond resolution.
end

-- iterator for ascii sort

local function pairsByKeys(t)
    local a = {}

    for n in pairs(t) do
        a[#a + 1] = n
    end

    table.sort(a)

    local i = 0

    return function()
        i = i + 1
        return a[i], t[a[i]]
    end
end

local function concat_params_detail(token_name, args)
    local sorted_tbl = {}
    local params = ''
    for k, v in pairsByKeys(args) do
        if k ~= token_name then
            params = params .. k
            params = params .. v
        end
    end
    sorted_tbl = nil
    return params

end

-- return sign,err

local function build_sign(debug, concat_str, app_secret)
    local final_str = app_secret .. concat_str
    local sign_server = ngx.md5(final_str)
    if debug == 1 then
        ngx.log(ngx.NOTICE, "server to sign string is ", final_str)
        ngx.log(ngx.NOTICE, "server sign md5 value is", sign_server)
    end
    return sign_server
end

-- return concat_str,err

local function retrieved_args(conf, request)
    local args = nil
    local request_method = ngx.var.request_method

    if "POST" == request_method then
        -- application/multi-part will not be support
        request.read_body()
        args = request.get_post_args()
        return args, nil
    elseif "GET" == request_method then
        args = request.get_uri_args()
        return args, nil
    else
        -- not supported http action such as put batch delete etc
        return nil, "sign-verify supported POST/GET request only"
    end
end

local function retrieved_server_token(conf, args, jwt_secret)
    if args then
        local concat_str = concat_params_detail(conf.token_name, args)
        local built_sign = build_sign(conf.open_debug, concat_str, jwt_secret)
        return built_sign, nil
    else
        return nil, 'appId and ts and sign must not be empty'
    end
end

local function retrieve_appkey(conf, args)
    return args[conf.appKey_name]
end

local function retrieve_sign(conf, args)
    return args[conf.token_name]
end

local function load_consumer(consumer_id, anonymous)
    local result, err = singletons.db.consumers:select { id = consumer_id }
    if not result then
        if anonymous and not err then
            err = 'anonymous consumer "' .. consumer_id .. '" not found'
        end
        return nil, err
    end
    return result
end

local function set_consumer(consumer, jwt_secret, token)
    ngx_set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    ngx_set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    ngx_set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    ngx.ctx.KONG_HEADER_FILTER_STARTED_AT = get_now()
    ngx.ctx.authenticated_consumer = consumer
    if jwt_secret then
        ngx.ctx.authenticated_credential = jwt_secret
        ngx.ctx.authenticated_jwt_token = token
        ngx_set_header(constants.HEADERS.ANONYMOUS, nil) -- in case of auth plugins concatenation
    else
        ngx_set_header(constants.HEADERS.ANONYMOUS, true)
    end

end

local function load_credential(jwt_secret_key)
    local rows, err = singletons.dao.jwt_secrets:find_all { key = jwt_secret_key }
    if err then
        return nil, err
    end
    return rows[1]
end

function SignVerifyHandler:new()
    SignVerifyHandler.super.new(self, "sign-verify")
end

function SignVerifyHandler:access(conf)
    SignVerifyHandler.super.access(self)

    local args = retrieved_args(conf, ngx.req)

    local jwt_secret_key = retrieve_appkey(conf, args)

    if not jwt_secret_key then
        -- return responses.send_HTTP_INTERNAL_SERVER_ERROR( message = "missing key param appId"})
        return responses.send(401, "missing key param appId")
    end

    local sign = retrieve_sign(conf, args)

    local jwt_secret_cache_key = singletons.dao.jwt_secrets:cache_key(jwt_secret_key)
    local jwt_secret, err = singletons.cache:get(jwt_secret_cache_key, nil,
            load_credential, jwt_secret_key)
    if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end

    if not jwt_secret then
        return responses.send(403, "appId is not invalid")
    end

    local token, err = retrieved_server_token(conf, args, jwt_secret.secret)

    if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end

    -- check sign is ok ?
    if sign == nil then
        return responses.send(401, "missing key param sign")
    end

    if sign ~= token then
        return responses.send(403, "Invalid signature")
    else
        -- However this should not happen
        if not consumer then
            return responses.send(403, string_format("Could not find consumer for '%s=%s'", conf.key_claim_name, jwt_secret_key))
        else
            ngx.log(ngx.NOTICE, "consumer found and custom_id is ", consumer.custom_id)
        end

        set_consumer(consumer, jwt_secret, token)

    end

end

return SignVerifyHandler


