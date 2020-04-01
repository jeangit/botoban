#!/usr/bin/env lua
-- $$DATE$$ : mer. 01 avril 2020 (19:06:05)

--[[
 - bannissement par plage des networks qui utilisent plusieurs hotes.
 - les IPs qui n'insistent pas sont débans, pour soulager netfilter.
 - sauvegarde et chargement de l'état du bannissement.
--]]

--[[ trouver networks repères de pirates:
iptables -L INPUT -n | sed 's/.*\-\-\ \+\(\([0-9]\+\.\)\{3\}\).*/\1/' | sort | uniq -c -d
--]]

local threshold_for_network = 3 --limite d'hotes à ne pas dépasser avant de bannir le network
exec_path=debug.getinfo(1,"S").source:sub(2)
exec_path=exec_path:match("(.*/)") or "./"
package.path = package.path .. ";" .. exec_path  .. "?.lua"
tprint = require "tprint"

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

function get_existing_rules()
  local rules = {}
--  rules = os.execute("
  local extract_ips = [[iptables -L INPUT -n | sed '/botoban/!d;s/[^\-]*--[\t\ ]\+\(\([0-9\.]\+\)\{4\}\).*/\1/']]
  for l in io.popen( extract_ips):lines() do
    rules[l]=l
  end

  return rules
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
  print(" -- create botoban chain (if doesn't exist)")
  -- true/nil , exec, code sortie
  local res, _, code = os.execute( "iptables -L botoban >/dev/null || (iptables -N botoban && iptables -A botoban -j DROP)")
end

function add_drop( ip, existing_rules)
  if not existing_rules[ip] then
    local drop = string.format("iptables -A INPUT -s %s -j botoban", ip)
    print( "ban :",ip)
    os.execute( drop)
  else
    print ("already banned :",ip)
  end
end

function remove_drop( ip, criterion)

end

function drop_rascals( t_ip, existing_rules)
  for net,hosts in pairs( t_ip) do
    nb_hosts_in_this_network = t_ip[net].nb_hosts
    --print ("net",net,"nb hotes", nb_hosts_in_this_network)
    if nb_hosts_in_this_network > threshold_for_network then
      -- trop d'hotes dans ce network, bannir sa plage
      add_drop( net .. "0/24", existing_rules)
    else
      -- itérer sur les hotes en dessous du seuil et les bannir individuellement
      if type(hosts) == "table" then
        for _, host in pairs( hosts) do
          if type(host) == "table" then
            add_drop ( net .. host.host, existing_rules)
          end
        end
      end
    end

  end

end

function save_base( t_ip, t_ip_filename)
  local dump_location = exec_path .. t_ip_filename
  local hFile = io.open( dump_location, "w+")
  if hFile then
    local is_ok,err = hFile:write( tprint( t_ip))
    if not is_ok then
      print( err)
    else
      print( "written :",dump_location)
    end
    hFile:close()
  else
    print( "something funny happened when attempting to create ", t_ip_filename)
  end
end

function load_base( t_ip_filename)
  local t_ip = {}

  return t_ip
end

function main()
  local existing_rules = get_existing_rules()
  local t_ip = parse_logs( "sshd","1 hour", "invalid user")
  -- pour postfix: LOGIN authentication failed

  --display_base( t_ip)
  create_drop_chain()
  drop_rascals( t_ip, existing_rules)

  save_base( t_ip, "database.lua")


end

main()

