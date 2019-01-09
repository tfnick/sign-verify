local BasePlugin = require "kong.plugins.base_plugin"
local singletons = require "kong.singletons"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"

local ipairs         = ipairs
local string_format  = string.format
local table = table
local ngx_set_header = ngx.req.set_header
local request_method = ngx.var.request_method

local SignVerifyHandler = BasePlugin:extend()

-- the number is more big and the priority is more high

SignVerifyHandler.PRIORITY = 9990


local function concat_params_detail(token_name,args)

    local sorted_tbl = {}

    for k,v in pairs(args) do
        if k ~= token_name then
            sorted_tbl[k] = v
        end
    end

    table.sort(sorted_tbl)

    local params = ''

    for k,v in pairs(sorted_tbl) do
        params = params..k
        params = params..v
    end

    return params

end

-- return sign,err

local function build_sign(debug,concat_str,app_secret)
    local final_str = app_secret..concat_str
    if debug == 1 then
        ngx.log(ngx.ERR,"to md5 string is",final_str)
    end
    return ngx.md5(final_str)
end

-- return concat_str,err

local function retrieved_server_token(conf,request,jwt_secret)
    local args = nil
    if "POST" == request_method then
        -- application/multi-part will not be support
        request.read_body()
        args = request.get_post_args()
    elseif "GET" == request_method then
        args = request.get_uri_args()
    else
        -- not supported http action such as put batch delete etc
        return nil, "sign-verify supported POST/GET request only"
    end

    if args then
        local concat_str = concat_params_detail(conf.token_name,args)
        local built_sign = build_sign(conf.open_debug,concat_str,jwt_secret)
        return built_sign ,nil
    else
        return nil,'appId and ts and sign must not be empty'
    end
end


local function retrieve_appkey(conf,request)

    return request['"'..conf.appKey_name..'"']

end

local function retrieve_sign(conf,request)

    return request['"'..conf.token_name..'"']

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
    ngx.ctx.authenticated_consumer = consumer
    if jwt_secret then
        ngx.ctx.authenticated_credential = jwt_secret
        ngx.ctx.authenticated_jwt_token = token
        ngx_set_header(constants.HEADERS.ANONYMOUS, nil) -- in case of auth plugins concatenation
    else
        ngx_set_header(constants.HEADERS.ANONYMOUS, true)
    end

end



function SignVerifyHandler:new()
    SignVerifyHandler.super.new(self, "sign-verify")
end

function SignVerifyHandler:access(conf)
    SignVerifyHandler.super.access(self)

    local jwt_secret_key = retrieve_appkey(conf,ngx.req)

    local sign = retrieve_sign(conf,ngx.req)

    -- 
    local jwt_secret_cache_key = singletons.dao.jwt_secrets:cache_key(jwt_secret_key)
    local jwt_secret, err      = singletons.cache:get(jwt_secret_cache_key, nil,
            load_credential, jwt_secret_key)
    if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end


    local token, err = retrieved_server_token(conf,ngx.req,jwt_secret)

    if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end

    -- check sign is ok ?

    if sign == nil  then
        return fresponses.send_HTTP_INTERNAL_SERVER_ERROR({status = 401, message = "missing key param sign"})
    end

    if sign ~= token then
        return fresponses.send_HTTP_INTERNAL_SERVER_ERROR({status = 403, message = "Invalid signature"})
    end

    -- Retrieve the consumer
    local consumer_cache_key = singletons.db.consumers:cache_key(jwt_secret.consumer_id)
    local consumer, err      = singletons.cache:get(consumer_cache_key, nil,
            load_consumer,
            jwt_secret.consumer_id, true)
    if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end

    -- However this should not happen
    if not consumer then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR({status = 403, message = string_format("Could not find consumer for '%s=%s'", conf.key_claim_name, jwt_secret_key)})
    end

    set_consumer(consumer, jwt_secret, token)

end

return SignVerifyHandler