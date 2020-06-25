#!/usr/bin/env lua
-- $$DATE$$ : jeu. 25 juin 2020 11:56:52

exec_path=debug.getinfo(1,"S").source:sub(2)
exec_path=exec_path:match("(.*/)") or "./"
package.path = package.path .. ";" .. exec_path  .. "?.lua;" .. exec_path .. "?"
fstools = require("fs_tools")

db = fstools.load_or_create_table( "database")

for ip, v in pairs(db) do
  if (v.nb_hosts > 3) then
    for k,v2 in pairs(v) do
      if string.match( k,"^[0-9]") then
        date_host_added=os.date("%a %d %b %Y %H:%M", v2.host_added )
        print(ip, date_host_added)
      end
    end
  end
end
