-- Copyright (C) 2017 yushi studio <ywb94@qq.com> github.com/ywb94
-- Licensed to the public under the GNU General Public License v3.

local m, s,sec, o,kcp_enable
local shadowsocksr = "shadowsocksr"
local uci = luci.model.uci.cursor()
local ipkg = require("luci.model.ipkg")

local sys = require "luci.sys"

local gfwmode=0

local pdnsd_flag=0

if nixio.fs.access("/etc/dnsmasq.ssr/gfw_list.conf") then
gfwmode=1		
end

if nixio.fs.access("/etc/pdnsd.conf") then
pdnsd_flag=1		
end

m = Map(shadowsocksr, translate("ShadowSocksR Client"))

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



uci:foreach(shadowsocksr, "servers", function(s)
	if s.alias then
		server_table[s[".name"]] = s.alias
	elseif s.server and s.server_port then
		server_table[s[".name"]] = "%s:%s" %{s.server, s.server_port}
	end
end)



-- [[ Servers Setting ]]--
sec = m:section(TypedSection, "servers", translate("Servers Setting"))
sec.anonymous = true
sec.addremove = true
sec.sortable = true
sec.template = "cbi/tblsection"
sec.extedit = luci.dispatcher.build_url("admin/services/shadowsocksr/client/%s")
function sec.create(...)
	local sid = TypedSection.create(...)
	if sid then
		luci.http.redirect(sec.extedit % sid)
		return
	end
end

o = sec:option(DummyValue, "alias", translate("Alias"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or translate("None")
end


o = sec:option(DummyValue, "server", translate("Server Address"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "?"
end

o = sec:option(DummyValue, "server_port", translate("Server Port"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "?"
end

o = sec:option(DummyValue, "encrypt_method", translate("Encrypt Method"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "?"
end

o = sec:option(DummyValue, "protocol", translate("Protocol"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "?"
end


o = sec:option(DummyValue, "obfs", translate("Obfs"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "?"
end

o = sec:option(DummyValue, "kcp_enable", translate("KcpTun"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "?"
end

o = sec:option(DummyValue, "switch_enable", translate("Auto Switch"))
function o.cfgvalue(...)
	return Value.cfgvalue(...) or "0"
end

-- [[ Global Setting ]]--
s = m:section(TypedSection, "global", translate("Global Setting"))
s.anonymous = true

o = s:option(ListValue, "global_server", translate("Global Server"))
o:value("nil", translate("Disable"))
for k, v in pairs(server_table) do o:value(k, v) end
o.default = "nil"
o.rmempty = false

o = s:option(ListValue, "udp_relay_server", translate("UDP Relay Server"))
o:value("", translate("Disable"))
o:value("same", translate("Same as Global Server"))
for k, v in pairs(server_table) do o:value(k, v) end

o = s:option(Flag, "monitor_enable", translate("Enable Process Monitor"))
o.rmempty = false

o = s:option(Flag, "enable_switch", translate("Enable Auto Switch"))
o.rmempty = false

o = s:option(Value, "switch_time", translate("Switch check cycly(second)"))
o.datatype = "uinteger"
o:depends("enable_switch", "1")
o.default = 600

o = s:option(Value, "switch_timeout", translate("Check timout(second)"))
o.datatype = "uinteger"
o:depends("enable_switch", "1")
o.default = 3

if gfwmode==0 then 

o = s:option(Flag, "tunnel_enable", translate("Enable Tunnel(DNS)"))
o.default = 0
o.rmempty = false

o = s:option(Value, "tunnel_port", translate("Tunnel Port"))
o.datatype = "port"
o.default = 5300
o.rmempty = false

else



o = s:option(ListValue, "gfw_enable", translate("Operating mode"))
o:value("router", translate("IP Route Mode"))
o:value("gfw", translate("GFW List Mode"))
o.rmempty = false

if pdnsd_flag==1 then
o = s:option(ListValue, "pdnsd_enable", translate("Resolve Dns Mode"))
o:value("0", translate("Use DNS Tunnel"))
o:value("1", translate("Use Pdnsd"))
o.rmempty = false
end

end

o = s:option(Value, "tunnel_forward", translate("DNS Server IP and Port"))
o.default = "8.8.4.4:53"
o.rmempty = false

-- [[ SOCKS5 Proxy ]]--
s = m:section(TypedSection, "socks5_proxy", translate("SOCKS5 Proxy"))
s.anonymous = true

o = s:option(ListValue, "server", translate("Server"))
o:value("nil", translate("Disable"))
for k, v in pairs(server_table) do o:value(k, v) end
o.default = "nil"
o.rmempty = false

o = s:option(Value, "local_port", translate("Local Port"))
o.datatype = "port"
o.default = 1234
o.rmempty = false


-- [[ Access Control ]]--
s = m:section(TypedSection, "access_control", translate("Access Control"))
s.anonymous = true

-- Part of WAN
s:tab("wan_ac", translate("Interfaces - WAN"))

o = s:taboption("wan_ac", Value, "wan_bp_list", translate("Bypassed IP List"))
o:value("/dev/null", translate("NULL - As Global Proxy"))

o.default = "/dev/null"
o.rmempty = false

o = s:taboption("wan_ac", DynamicList, "wan_bp_ips", translate("Bypassed IP"))
o.datatype = "ip4addr"

o = s:taboption("wan_ac", DynamicList, "wan_fw_ips", translate("Forwarded IP"))
o.datatype = "ip4addr"

-- Part of LAN
s:tab("lan_ac", translate("Interfaces - LAN"))

o = s:taboption("lan_ac",ListValue, "router_proxy", translate("Router Proxy"))
o:value("1", translatef("Normal Proxy"))
o:value("0", translatef("Bypassed Proxy"))
o:value("2", translatef("Forwarded Proxy"))
o.rmempty = false

o = s:taboption("lan_ac", ListValue, "lan_ac_mode", translate("LAN Access Control"))
o:value("0", translate("Disable"))
o:value("w", translate("Allow listed only"))
o:value("b", translate("Allow all except listed"))
o.rmempty = false

o = s:taboption("lan_ac", DynamicList, "lan_ac_ips", translate("LAN Host List"))
o.datatype = "ipaddr"
for _, v in ipairs(arp_table) do o:value(v["IP address"]) end

return m
