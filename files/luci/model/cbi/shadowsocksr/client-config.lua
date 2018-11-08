-- Copyright (C) 2017 yushi studio <ywb94@qq.com> github.com/ywb94
-- Licensed to the public under the GNU General Public License v3.

local m, s, o,kcp_enable
local shadowsocksr = "shadowsocksr"
local uci = luci.model.uci.cursor()
local ipkg = require("luci.model.ipkg")
local fs = require "nixio.fs"
local sys = require "luci.sys"
local sid = arg[1]

local function isKcptun(file)
    if not fs.access(file, "rwx", "rx", "rx") then
        fs.chmod(file, 755)
    end

    local str = sys.exec(file .. " -v | awk '{printf $1}'")
    return (str:lower() == "kcptun")
end


local server_table = {}
local arp_table =  luci.ip.neighbors()
local encrypt_methods = {
	"table",
	"rc4",
	"rc4-md5",
	"rc4-md5-6",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",	
	"bf-cfb",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"cast5-cfb",
	"des-cfb",
	"idea-cfb",
	"rc2-cfb",
	"seed-cfb",
	"salsa20",
	"chacha20",
	"chacha20-ietf",
}

local protocol = {
	"origin",
	"verify_simple",
	"verify_sha1",		
	"auth_sha1",
	"auth_sha1_v2",
	"auth_sha1_v4",
	"auth_aes128_sha1",
	"auth_aes128_md5",
}

obfs = {
	"plain",
	"http_simple",
	"http_post",
	"tls_simple",	
	"tls1.2_ticket_auth",
}

m = Map(shadowsocksr, translate("Edit ShadowSocksR Server"))
m.redirect = luci.dispatcher.build_url("admin/services/shadowsocksr/client")
if m.uci:get(shadowsocksr, sid) ~= "servers" then
	luci.http.redirect(m.redirect) 
	return
end

-- [[ Servers Setting ]]--
s = m:section(NamedSection, sid, "servers")
s.anonymous = true
s.addremove   = false

o = s:option(Value, "alias", translate("Alias(optional)"))

o = s:option(Flag, "auth_enable", translate("Onetime Authentication"))
o.rmempty = false

o = s:option(Flag, "switch_enable", translate("Auto Switch"))
o.rmempty = false

o = s:option(Value, "server", translate("Server Address"))
o.datatype = "host"
o.rmempty = false

o = s:option(Value, "server_port", translate("Server Port"))
o.datatype = "port"
o.rmempty = false

o = s:option(Value, "local_port", translate("Local Port"))
o.datatype = "port"
o.default = 1234
o.rmempty = false

o = s:option(Value, "timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 60
o.rmempty = false

o = s:option(Value, "password", translate("Password"))
o.password = true
o.rmempty = false

o = s:option(ListValue, "encrypt_method", translate("Encrypt Method"))
for _, v in ipairs(encrypt_methods) do o:value(v) end
o.rmempty = false

o = s:option(ListValue, "protocol", translate("Protocol"))
for _, v in ipairs(protocol) do o:value(v) end
o.rmempty = false


o = s:option(ListValue, "obfs", translate("Obfs"))
for _, v in ipairs(obfs) do o:value(v) end
o.rmempty = false

o = s:option(Value, "obfs_param", translate("Obfs param(optional)"))

o = s:option(Flag, "fast_open", translate("TCP Fast Open"))
o.rmempty = false

kcp_enable = s:option(Flag, "kcp_enable", translate("KcpTun Enable"), translate("bin:/usr/bin/ssr-kcptun"))
kcp_enable.rmempty = false


o = s:option(Value, "kcp_port", translate("KcpTun Port"))
o.datatype = "port"
o.default = 4000
function o.validate(self, value, section)
		local kcp_file="/usr/bin/ssr-kcptun"
		local enable = kcp_enable:formvalue(section) or kcp_enable.disabled
		if enable == kcp_enable.enabled then
    if not fs.access(kcp_file)  then
        return nil, translate("Haven't a Kcptun executable file")
    elseif  not isKcptun(kcp_file) then
        return nil, translate("Not a Kcptun executable file")    
    end
    end

    return value
end

o = s:option(Value, "kcp_password", translate("KcpTun Password"))
o.password = true

o = s:option(Value, "kcp_param", translate("KcpTun Param"))
o.default = "--nocomp"


return m
