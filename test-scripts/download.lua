-- Global common include file
dofile("/system/srv/www/htdocs/webinternals/common.lua")

profilename = cgilua.QUERY.profilename
index = string.find(profilename, "/[^/]*$")
name = string.sub(profilename, index + 1)

-- Make sure browser dont cache this webpage
if _G.magnetLighty then
  _G.magnetLighty.header["Cache-Control"] = "no-cache"
  _G.magnetLighty.header["Expires"] = "Tue, 29 Jul 1980 20:17:00 GMT"
  _G.magnetLighty.header["Content-Disposition"] = "attachment; filename=" .. name
end

f = io.open(profilename, "r")
local t = f:read("*all")
print(t)
f:close()
