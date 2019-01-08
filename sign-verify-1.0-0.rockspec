package = "sign-verify"
version = "1.0-0"
local pluginName = "sign-verify"

source = {
  url = "git://github.com/tfnick/sign-verify.git",
}

description = {
  summary = "A Kong plugin sign-verify",
  license = "Apache 2.0"
}
dependencies = {
  "lua ~> 5.1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.sign-verify.handler"] = "kong/plugins/sign-verify/handler.lua",
    ["kong.plugins.sign-verify.schema"]  = "kong/plugins/sign-verify/schema.lua"
  }
}