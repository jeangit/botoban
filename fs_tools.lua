#!/usr/bin/env lua
-- $$DATE$$ : mer. 13 mai 2020 14:27:30


local temp_f = {}
local function write_to_tempfile( txt, temp_filename)
  local handle = temp_f[temp_filename]
  if not handle then
    local tfn = "/tmp/" .. temp_filename
    handle = io.open( tfn, "w+")
    if not handle then print("error when creating ",tfn); os.exit(1) end
    temp_f[temp_filename] = handle
  end

  handle:write( txt)
end

local function close_tempfiles()
  for _,handle in pairs(temp_f) do
    handle:close()
  end
end


function save_table( t, t_filename)
  local dump_location = exec_path .. t_filename
  local hFile = io.open( dump_location, "w+")
  if hFile then
    local is_ok,err = hFile:write( "return ", tprint( t))
    if not is_ok then
      print( err)
    else
      print( "written :",dump_location)
    end
    hFile:close()
  else
    print( "something funny happened when attempting to create", t_filename)
  end
end



function is_existing( filename)
   local f = io.open( filename,"r")
   if f ~= nil then
     io.close(f) return true
   else
     return false
   end
end

-- if table does not exists, return a new one
local function load_or_create_table( t_filename)

  local res,t = pcall( require, t_filename)
  if not res then
    print( t_filename, "not found, will create a new one.")
    t = {}
  end

  return t
end

-- load a table by requiring it.
-- table filename must exist.
function load_table( t_filename)
  local is_err, err_msg = nil, "load table: ok"
  local t

  if arg[1] then
    t = require( t_filename)
    if not t then
      is_err = 1
      err_msg = "invalid table file", t_filename
    end
  else
    is_err = 1
    err_msg = "You must provide the table filename."
  end

  return is_err, err_msg, t
end




-- test (start)
local function main()
  print( "tests here")
end
-- test (end)



if ... then 
  -- module
  return {
    load_table = load_table,
    load_or_create_table = load_or_create_table,
    save_table = save_table,
    is_existing = is_existing,
    write_to_tempfile = write_to_tempfile,
    close_tempfiles = close_tempfiles
  }
else
  -- test
  main()
end

