#!/usr/bin/env lua
-- $$DATE$$ : mer. 27 mai 2020 12:07:07

--[[
 - bannissement par plage des networks qui utilisent plusieurs hotes.
 - les IPs qui n'insistent pas sont débans, pour soulager netfilter.
 - sauvegarde et chargement de l'état du bannissement.
--]]

--[[ trouver networks repères de pirates:
iptables -L INPUT -n | sed 's/.*\-\-\ \+\(\([0-9]\+\.\)\{3\}\).*/\1/' | sort | uniq -c -d
--]]

exec_path=debug.getinfo(1,"S").source:sub(2)
exec_path=exec_path:match("(.*/)") or "./"
package.path = package.path .. ";" .. exec_path  .. "?.lua;" .. exec_path .. "?"
tprint = require "tprint"
range = require "range"
ip_tools = require "ip_tools"
fs_tools = require "fs_tools"

local filename_banned_nets = "/tmp/banned_nets"
local filename_banned_hosts = "/tmp/banned_hosts"

local function add_database( db_ip, line)
  local ip = line:match( "%d+%.%d+%.%d+%.%d+")
  local network=ip:match("%d+%.%d+%.%d+%.")
  local host=ip:match(".*%.(%d+)")
  --print(ip,host,network)
  if not db_ip[network] then
    -- ajouter le network qui n'était pas encore référencé.
    db_ip[network] = { net_added=os.time(), last_host_added=os.time(), nb_hosts=0, unit=unit }
  end

  if db_ip[network][host] then
    -- l'hôte existe déjà, incrémenter son compteur de hits
    db_ip[network][host].count = db_ip[network][host].count + 1
  else
    db_ip[network][host] = { host=host, count=1, host_added=os.time() }
    -- il suffit de comparer net_added à last_host_added pour voir si
    -- il convient de bannir le network. (si une seule IP, les deux valeurs sont == )
    db_ip[network].last_host_added=os.time()
    -- en moins violent, on peut aussi décider de bannir si le nombre d'hôtes dépasse un seuil.
    db_ip[network].nb_hosts = db_ip[network].nb_hosts + 1
  end

  return db_ip
end

function coroutine_logs( cmd)
  local corout = coroutine.create( function()
    for l in io.popen( cmd):lines() do
      coroutine.yield(l)
    end
  end )
  return corout
end

function call_coroutine_logs( cmd, db_ip, filter)
  local co = coroutine_logs( cmd)
  while coroutine.status( co) ~= "dead" do
    local is_running,line = coroutine.resume( co)
    if ( line and line:find( filter)) then
      db_ip = add_database( db_ip,line)
      --print("added",filter,line)
    end

  end
  return db_ip
end

function parse_journald_logs( unit, since, filter, db_ip)
  local cmd = string.format('journalctl -u %s --no-pager --since "%s ago"', unit, since)
  db_ip = call_coroutine_logs( cmd, db_ip, filter)
  return db_ip
end

function parse_dmesg_logs( filter, db_ip)
  local cmd = string.format("dmesg") -- | sed '/%s/!d;s/.*SRC=\([0-9\.]\+\).*/\1/' | sort | uniq", filter)
  db_ip = call_coroutine_logs(cmd, db_ip, filter)
  return db_ip
end


-- fonction de debug
function display_base( db_ip)
  for net,hosts in pairs(db_ip) do
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

-- TODO à factoriser (voir create_ipset() qui contient ce qu'il faut pour remplacer ça)
function create_drop_chain()
  print(" -- create iplist blacklists")
  os.execute( "ipset create banned_hosts hash:ip")
  os.execute( "ipset create banned_nets hash:net")
  print(" -- adding to blacklist")
  os.execute( "ipset restore -! < " .. filename_banned_hosts)
  os.execute( "ipset restore -! < " .. filename_banned_nets)
  -- TODO prévoir un flush si la liste existe, et que le flush est prévu dans la config
  print(" -- create botoban chain (if doesn't exist)")
  -- true/nil , exec, code sortie
  local res, _, code = os.execute( "iptables -L botoban >/dev/null || (iptables -N botoban && iptables -A botoban -j DROP)")
  local res, _, code = os.execute( "if [ $(iptables -L INPUT | grep blacklist | wc -l) -eq 0 ]; then iptables -I INPUT -m set --match-set banned_hosts src -j botoban; iptables -I INPUT -m set --match-set banned_nets src -j botoban; fi")
  local res, _, code = os.execute( "if [ $(iptables -L FORWARD | grep blacklist | wc -l) -eq 0 ]; then iptables -I FORWARD -m set --match-set banned_hosts src -j botoban; iptables -I FORWARD -m set --match-set banned_nets src -j botoban; fi")
end


function add_drop_to_file( ip, existing_rules, whitelist, ipfilter_name, destfile)

  if not existing_rules[ip] then
    if not whitelist[ip] then
      --local drop = string.format("iptables -A INPUT -s %s -j botoban", ip)
      local drop = string.format("add %s %s\n", ipfilter_name, ip)
      print( "ban :",ip)
      destfile.write( drop)
    else
      print( "do not ban (whitelisted) :",ip)
    end
  else
    print ("already banned :",ip)
  end
end

function remove_drop( ip, criterion)

end

-- les networks déja bannis pour cette session
-- TODO : avec les données de la base d'IPs bloquées, retirer les hotes correspondant à ces networks
local session_network_bans = {}

function drop_rascals( db_ip, ip_already_banned, config)
  local network_threshold = config.threshold_for_network
  local host_threshold = config.threshold_for_hosts

  local Hbanned_nets = fs_tools.open_truncate( filename_banned_nets)
  local Hbanned_hosts = fs_tools.open_truncate( filename_banned_hosts)

  for net,hosts in pairs( db_ip) do
    nb_hosts_in_this_network = db_ip[net].nb_hosts
    --print ("net",net,"nb hotes", nb_hosts_in_this_network)
    if nb_hosts_in_this_network > network_threshold then
      -- trop d'hotes dans ce network, bannir sa plage
      local net_ban = net .. "0/24"
      if not session_network_bans[net_ban] then
        add_drop_to_file( net_ban, ip_already_banned, config.whitelist, "banned_nets",Hbanned_nets)
        session_network_bans[net_ban] = net_ban
      end
    else
      -- itérer sur les hotes en dessous du seuil et les bannir individuellement
      if type(hosts) == "table" then
        for _, host in pairs( hosts) do
          if type(host) == "table" and host.count > host_threshold then
            add_drop_to_file ( net .. host.host, ip_already_banned, config.whitelist, "banned_hosts",Hbanned_hosts)
          end
        end
      end
    end

  end

end


-- sourcefile contains NET (not host !) ip list (one per line)
function create_ipset( sourcefile_with_path)
  local is_ok = true
  local ipset_name = sourcefile_with_path:gsub( ".*%/?([^%.]+).*","%1")

  if ( fs_tools.is_existing( sourcefile_with_path)) then
    local command_create = string.format( "ipset create %s hash:net", ipset_name)
    local command_addfile = string.format( "ipset restore -! < " .. sourcefile_with_path)
    os.execute( command_create)
    os.execute( command_addfile)
    
  -- true/nil , exec, code sortie
  --[[
  local res, _, code = os.execute( "if [ $(iptables -L INPUT | grep blacklist | wc -l) -eq 0 ]; then iptables -I INPUT -m set --match-set banned_hosts src -j botoban; iptables -I INPUT -m set --match-set banned_nets src -j botoban; fi")
  local res, _, code = os.execute( "if [ $(iptables -L FORWARD | grep blacklist | wc -l) -eq 0 ]; then iptables -I FORWARD -m set --match-set banned_hosts src -j botoban; iptables -I FORWARD -m set --match-set banned_nets src -j botoban; fi")
  --]]

  else
    print(" ERROR file does not exist", sourcefile)
    is_ok = false
  end


  return is_ok
end


-- le principe est le même, que ce soit une whitelist ou une blacklist
function gen_whibla_list( config)
  local list = nil
  local list_file = exec_path .. config[2]
  local port = config[3]
  local chain = config[4]
  
  if ( fs_tools.is_existing( list_file)) then
    print("gen ip range for",list_file)
    local ip_range = ip_tools.gen_ip_range( list_file)
    -- ip_range: { (début (numérique),fin (numérique),netmask (ascii : slash suivi du masque)) }

    print("gen ip netmask")
    list = ip_tools.gen_netmask( ip_range)
    -- ip_range_netmask : liste indexée type avec value de type « 217.195.16.0/20 »

  else
    print ("ERROR ! [White/Black]list file does not exist:", list_file)
  end

  return list
end

function add_whitelist( config)
  local whitelist = gen_whibla_list( config)
  if whitelist then
    --local is_ok = create_ipset( whitelist_file)

  end
end

function parse_sources( sources, db_ip)
  local is_err, err_msg = false, "parse sources ok"
  if sources then
    for _,src in pairs(sources) do
      if src[1] == "dmesg" then
        parse_dmesg( src[2], db_ip)

      elseif src[1] == "whitelist" then
        add_whitelist( src)

      elseif src[1] == "blacklist" then
        print("TODO implementing blacklist")

      else -- assume it's journald log
        print("parsing unit", src[1])
        db_ip = parse_journald_logs( src[1],src[2],src[3] ,db_ip)
      end
    end

  else
    is_err = true
    err_msg = "No sources defined in configuration"
  end
  
  return is_err, err_msg, db_ip
end

function remove_no_match( existing_rules)
  if existing_rules then
    -- itérer depuis la fin, car iptables décale les lignes à
    -- chaque effacement d'une régle
    for i = #existing_rules,1,-1 do
      local infos_ip = existing_rules[i]
      if infos_ip.occurs == 0 then -- TODO :mettre une valeur de seuil plutôt que 0
        print( "removing no match IP", infos_ip.ip,"at line :", infos_ip.line)
        os.execute( "iptables -D INPUT " .. infos_ip.line)
      end
    end
  end
end


-- for speeding up treatment when looking if IP is already banned
function get_already_blocked()
  local ip_blocked = {}

  local extracdb_ips = [[ipset list | grep "^[0-9]"]]
  for ip in io.popen( extracdb_ips):lines() do
    table.insert( ip_blocked, ip)
  end
  
  return ip_blocked
end


function main()
  local is_err, err_msg, config = fs_tools.load_table(arg[1])
  local is_dryrun = arg[2]=="dryrun" and true or false

  if not is_err then

    -- load previously saved table of banned IPs.
    local db_ip = fs_tools.load_or_create_table( config.database or "base")
    is_err, err_msg, db_ip = parse_sources( config.sources, db_ip)
    
    if is_dryrun == false and is_err == false then
      drop_rascals( db_ip, get_already_blocked(), config)
      create_drop_chain()

      if config.remove_no_match == true then
        remove_no_match( existing_rules)
      end

      fs_tools.save_table( db_ip, config.database or "base")
    else
      if is_err then print(err_msg) end
      if dryrun then print(" *** dry run : no changes ***") end
    end

  else
    print( err_msg)
  end

end

main()

