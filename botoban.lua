#!/usr/bin/env lua
-- $$DATE$$ : ven. 27 mars 2020 (16:25:39)

--[[
 - bannissement par plage des networks qui utilisent plusieurs hotes.
 - les IPs qui n'insistent pas sont débans, pour soulager netfilter.
 - sauvegarde et chargement de l'état du bannissement.
--]]


function coroutine_logs( unit, since)
  local corout = coroutine.create( function()
    local cmd = string.format('journalctl -u %s --no-pager --since "%s ago"', unit, since)
    for l in io.popen( cmd):lines() do
      coroutine.yield(l)
    end
  end )
  return corout
end

function parse_logs( unit, since, filter)
  local t_ip = { }
  local co = coroutine_logs( unit, since)
  while coroutine.status( co) ~= "dead" do
    local is_running,line = coroutine.resume( co)
    if ( line and line:find( filter)) then
      local ip = line:match( "%d+%.%d+%.%d+%.%d+")
      local network=ip:match("%d+%.%d+%.%d+%.")
      local host=ip:match(".*%.(%d+)")

      if not t_ip[network] then
        -- ajouter le network qui n'était pas encore référencé.
        t_ip[network] = { net_added=os.time(), last_host_added=os.time() }
      end

      if t_ip[network][host] then
        t_ip[network][host].count = t_ip[network][host].count + 1
      else
        t_ip[network][host] = { host=host, count=1, host_added=os.time() }
        -- il suffit de comparer net_added à last_host_added pour voir si
        -- il convient de bannir le network. (si une seule IP, les deux valeurs sont == )
        t_ip[network].last_host_added=os.time()
      end
    end

  end
  return t_ip
end

-- fonction de debug
function display_base( t_ip)
  for net,hosts in pairs(t_ip) do
    print(" === ",net .. "*" )
    if type(hosts)=="table" then
      local net_details=""
      for net_detail_name,net_detail_value in pairs(hosts) do
        if type(net_detail_value) ~= "table" then
          net_details = net_details ..
                      " -> " .. net_detail_name .. " : " .. os.date("%c",et_detail_value) .. "\n"
        else
          print("    --> ." .. net_detail_value.host,
                          "count: " .. net_detail_value.count,
                          "host added: " .. os.date("%c",net_detail_value.host_added))
        end
      end
      print(net_details)
    end
    --print("")
    end
end

function create_drop_chain()
  -- true/nil , exec, code sortie
  print(" -- création chain botoban")
  local res, _, code = os.execute( "iptables -N botoban; iptables -A botoban -j DROP")
end

function add_drop( ip)
-- iptables -A INPUT -s [ip] -j botoban
end

function remove_drop( ip, criterion)

end


function main()
  local t_ip = parse_logs( "sshd","1 hour", "invalid user")
  display_base( t_ip)
  --for k,v in pairs(t_ip) do print(k,v.count,os.date( "%H:%M:%S", v.added)) end
  --for k,v in pairs(t_ip) do print(k,v) end

  create_drop_chain()

end

main()

