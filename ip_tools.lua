#!/usr/bin/env lua
-- $$DATE$$ : jeu. 14 mai 2020 16:34:00

-- https://lite.ip2location.com/ip-address-ranges-by-country
-- https://lite.ip2location.com/france-ip-address-ranges
-- dumper avec lynx
-- sed '/^[\t\ ]*[0-9\t\ \.,]\+$/!d;s/[\t\ ]*\([0-9\.]\+\)[\t\ ]*\([0-9\.]\+\)[\t\ ]*\([0-9,]\+\)/\1;\2;\3/g;s/,//g' french_ip.dump >french_ip

-- plus simple (moins complet que ip2location.com) :
-- https://www.nirsoft.net/countryip/fr.html

range = require "range"


local function ip_to_integer( ip)
  local integer = 0
  local rank = { 2^24, 2^16, 2^8 , 1 }
  local i = 1

  for n in ip:gmatch( "[0-9]+") do
    integer = integer + tonumber(n) * rank[i]
    i=i+1
  end

  return integer
end

local function ip_to_string( ip)
  local to_string = {}
  for i = 24,0,-8 do

    local x = ip >> i & 0xff
    to_string[#to_string+1] = tostring(x)
  end

  return table.concat(to_string,".")
end


local netmask_cache = {}
local function get_netmask( nb_hosts)

  -- éviter de recalculer tout le temps le même masque réseau.
  local netmask = netmask_cache[nb_hosts]

  if not netmask then
    local i = nb_hosts
    netmask = 32
    i = i-1
    while i ~= 0 do
      netmask=netmask-1
      i = i >> 1
    end
    netmask = "/" .. netmask
    netmask_cache[nb_hosts] = netmask -- cache résultat pour future demande
  end
  return netmask
end


-- renvoi un tableau d'ip numériques avec le netmask sous format ascii (/xx)
-- entrée : ip début (ascii), ip fin (ascii) , nombre d'hotes
-- sortie : tableau de  { (début (numérique),fin (numérique),netmask (ascii : slash suivi du masque)) }
local function gen_ip_range( file)
  local t={}
  for l in io.lines( file) do
    -- format attendu: ip_start;ip_end
    local from,to,sum = l:match("([^;]+);([^;]+);(.*)")
    local t_from = ip_to_integer( from)
    local t_to = ip_to_integer( to)
    local netmask = get_netmask( sum)
    table.insert( t, { t_from, t_to, netmask })
  end

  return t
end

-- génère une table de netmask à partir de la table retournée par gen_ip_range
local function gen_netmask( t)
  local nets = {}

  for _,v in pairs( t) do
    nets[#nets+1] = ip_to_string(v[1]) .. v[3]
  end

  return nets
end


-- test (start)
local function main()
  -- recherche d'une ip dans la range
  local french_range = gen_ip_range( "french_ip")
  local check_ip = ip_to_integer("2.16.117.1")
  local res = range.search( check_ip, french_range)
  print("res",res)
  
  print(get_netmask(65536))

  local nets = gen_netmask( french_range)
  --for _,v in pairs(nets) do print(v) end
end
-- test (end)



if ... then 
  -- module
  return {
    gen_ip_range = gen_ip_range,
    gen_netmask = gen_netmask,
    ip_to_integer = ip_to_integer,
    ip_to_string = ip_to_string
  }
else
  -- test
  main()
end

