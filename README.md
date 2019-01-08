
### 插件顺序

jwt-header-rewrite -> jwt | sign-verify -> quota-check -> charge-msg-produce

### 插件级别

jwt-header-rewrite(global) -> jwt | sign-verify(route) -> quota-check(route) -> charge-msg-produce(route)


### sign-verify

- 与jwt插件共用jwt_secrets表，用来存储客户的[appKey,appSecret](appId,appKey)

- 处理过程 : appId,ts,sign -> appId,appKey,custom_id -> verify sign -> add http headers -> next plugin



### header传递 

必须与jwt签名认证传送的header一样，这样系统才能兼容jwt与sign两种方式

```

Upstream Headers
When a JWT is valid, a Consumer has been authenticated, the plugin will append some headers to the request before proxying it to the upstream service, so that you can identify the Consumer in your code:

X-Consumer-ID, the ID of the Consumer on Kong
X-Consumer-Custom-ID, the custom_id of the Consumer (if set)
X-Consumer-Username, the username of the Consumer (if set)
X-Anonymous-Consumer, will be set to true when authentication failed, and the ‘anonymous’ consumer was set instead.

```