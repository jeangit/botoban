#!/usr/bin/env lua
-- $$DATE$$ : lun. 30 mars 2020 (17:09:22)

--[[
 - bannissement par plage des networks qui utilisent plusieurs hotes.
 - les IPs qui n'insistent pas sont débans, pour soulager netfilter.
 - sauvegarde et chargement de l'état du bannissement.
--]]

local threshold_for_network = 3 --limite d'hotes à ne pas dépasser avant de bannir le network

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
        t_ip[network] = { net_added=os.time(), last_host_added=os.time(), nb_hosts=0 }
      end

      if t_ip[network][host] then
        -- l'hôte existe déjà, incrémenter son compteur de hits
        t_ip[network][host].count = t_ip[network][host].count + 1
      else
        t_ip[network][host] = { host=host, count=1, host_added=os.time() }
        -- il suffit de comparer net_added à last_host_added pour voir si
        -- il convient de bannir le network. (si une seule IP, les deux valeurs sont == )
        t_ip[network].last_host_added=os.time()
        -- en moins violent, on peut aussi décider de bannir si le nombre d'hôtes dépasse un seuil.
        t_ip[network].nb_hosts = t_ip[network].nb_hosts + 1
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
          -- ATTENTION! Toutes les valeurs ne sont pas forcément des dates.
          -- je pars du principe que si > à 1e6 , c'est une date.
          if net_detail_value > 1e6 then net_detail_value = os.date("%c",net_detail_value) end
          net_details = net_details ..
                      " -> " .. net_detail_name .. " : " .. net_detail_value .. "\n"
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
  local drop = string.format("iptables -A INPUT -s %s -j botoban", ip)
  --print( drop)
  os.execute( drop)
end

function remove_drop( ip, criterion)

end

function drop_rascals( t_ip)
  for net,hosts in pairs( t_ip) do
    nb_hosts_in_this_network = t_ip[net].nb_hosts
    print ("net",net,"nb hotes", nb_hosts_in_this_network)
    if nb_hosts_in_this_network > threshold_for_network then
      -- trop d'hotes dans ce network, bannir sa plage
      add_drop( net .. "0/24")
    else
      -- itérer sur les hotes en dessous du seuil et les bannir individuellement
      if type(hosts) == "table" then
        for _, host in pairs( hosts) do
          if type(host) == "table" then
            add_drop ( net .. host.host)
          end
        end
      end
    end

  end

end

function main()
  local t_ip = parse_logs( "sshd","1 hour", "invalid user")
  
  --display_base( t_ip)
  create_drop_chain()
  drop_rascals( t_ip)


end

main()

