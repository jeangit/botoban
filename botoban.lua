#!/usr/bin/env lua
-- $$DATE$$ : ven. 27 mars 2020 (12:20:08)

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
        -- il suffit de comparer added à last_addition pour voir si
        -- l'ip capturée était juste un robot qui s'est perdu.
        t_ip[network] = { added=os.time(), last_addition=os.time() }
      end

        if t_ip[network][host] then
          t_ip[network][host].count = t_ip[network][host].count + 1
        else
          t_ip[network][host] = { count=1 }
          t_ip[network].last_addition=os.time()
        end
      end

    end
  return t_ip
end

-- fonction de debug
function display_base( t_ip)
  for net,hosts in pairs(t_ip) do
    print(" * ",net, "added",os.date(net.added),"last addition", os.date(net.last_addition))
    if type(hosts)=="table" then
      for host,host_detail in pairs(hosts) do
        print("   -->", host,host_detail)
      end
    end
    --print("")
    end
--[[
    for net,v in pairs(t_ip) do
      print(net,v)
      for i,v2 in pairs(v) do
        print(" ->",i,v2)
      end
    end
--]]

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

