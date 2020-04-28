#!/usr/bin/env lua
-- $$DATE$$ : mar. 28 avril 2020 20:15:13

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

local function load_ip_range( file)
  local t={}
  for l in io.lines( file) do
    -- format attendu: ip_start;ip_end
    local from,to= l:match("([^;]+);(.*)")
    local t_from = ip_to_integer( from)
    local t_to = ip_to_integer( to)
    table.insert( t, { t_from, t_to })

  end

  return t
end

-- test (start)
local function main()
  local french_range = gen_ip_range( "ip_french.txt")
  local check_ip = ip_to_integer("2.16.117.1")
  local res = range.search( check_ip, french_range)
  print("res",res)
end
-- test (end)



if ... then 
  -- module
  return {
    load_ip_range = load_ip_range,
    ip_to_integer = ip_to_integer,
    ip_to_string = ip_to_string
  }
else
  -- test
  main()
end

