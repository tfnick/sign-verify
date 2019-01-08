local singletons = require "kong.singletons"
local BasePlugin = require "kong.plugins.base_plugin"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"

local ipairs         = ipairs
local request_method = ngx.var.request_method

local SignVerifyHandler = BasePlugin:extend()


-- the number is more big and the priority is more high

SignVerifyHandler.PRIORITY = 9990

-- return concat_str,err

local function retrieve_token(conf,request)
    if "POST" == request_method
        -- application/multi-part will not be support
        request.read_body()
        args = request.get_post_args()
    else if "GET" == request_method
        args = request.get_uri_args()
    else
        -- not supported http action such as put batch delete etc
        return nil, "sign-verify supported POST/GET request only"
    end

    if args then
        local concat_str = concat_params_detail(conf.token_name,args)
        local app_secret = nil
        return build_sign(concat_str,app_secret),nil
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



local function concat_params_detail(token_name,args)

    local sorted_tbl = {}

    for k,v in pairs(args) do
        if k ~= token_name
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

local function build_sign(concat_str,app_secret)
    local final_str = app_secret..concat_str
    return ngx.md5(final_str)
end


function SignVerifyHandler:new()
    SignVerifyHandler.super.new(self, "sign-verify")
end

function SignVerifyHandler:access(conf)
    SignVerifyHandler.super.access(self)

    local jwt_secret_key = retrieve_appkey(conf,ngx.req)

    local sign = retrieve_sign(conf,ngx.req)

    local jwt_secret_cache_key = singletons.dao.jwt_secrets:cache_key(jwt_secret_key)
    local jwt_secret, err      = singletons.cache:get(jwt_secret_cache_key, nil,
                                                    load_credential, jwt_secret_key)
    if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end


    local token, err = retrieve_token(conf,ngx.req)
    
    if err then
        return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
    end

    local ttype = type(token)
    if ttype ~= "string" then
        if ttype == "nil" then
          return false, {status = 401}
        elseif ttype == "table" then
          return false, {status = 401, message = "Multiple tokens provided"}
        else
          return false, {status = 401, message = "Unrecognizable token"}
        end
    end

    -- check sign is ok ?

    if sign == nil 
        return false, {status = 401, message = "missing key param sign"}
    end 

    if sign ~= token
        return false, {status = 403, message = "Invalid signature"}
    end

end

return SignVerifyHandler