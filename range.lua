#!/usr/bin/env lua
-- $$DATE$$ : mar. 28 avril 2020 15:41:39
-- thanks to Rhodium Toad (#lua) for review & corrections.

-- for testing (start)
local range = {
  {10,20}, {25,27}, {30,40}, {50,70}, {80,85}, {92,97}
}

local function range_test(a,b)
  b = b or a
  for n = a,b do
    local res = search(n)
    print("res for "..n, res);
  end
end

function main()
  range_test(1,99)
end
-- for testing (end)

local function search_int( lo, hi, key, range)
  if hi < lo then
    return nil
  end
  local mid = lo + ( ( hi-lo) // 2)
  local mid_lbound, mid_ubound = range[mid][1], range[mid][2]

  if mid_lbound <= key then
    if mid_ubound >= key then
      return mid
    end
    lo = mid + 1
  else
    hi = mid - 1
  end
  return search_int( lo, hi, key, range)
end

function search( x, range)
  return search_int( 1, #range, x, range)
end

if ... then
  -- module
  return {
    search = search
  }
else
  -- test
 -- main()
  for i,v in pairs(package.loaded) do print(i,v) end
  print("runned")
end
