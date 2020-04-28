#!/usr/bin/env lua
-- $$DATE$$ : mar. 28 avril 2020 10:57:39
-- thanks to Rhodium Toad (#lua) for reviewing & corrections.

local range = {
  {10,20}, {25,27}, {30,40}, {50,70}, {80,85}, {92,97}
}

loacl function range_test(a,b)
  b = b or a
  for n = a,b do
    local res = search(n)
    print("res for "..n, res);
  end
end

function main()
  range_test(1,99)
end


local function search_int( lo, hi, key)
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
  return search_int( lo, hi, key)
end

function search( x)
  return search_int( 1, #range, x)
end

return {
  search = search
}


-- won't call main if loaded as a module
if not package.loaded["range"] then
  main()
end
