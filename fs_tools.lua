#!/usr/bin/env lua
-- $$DATE$$ : lun. 18 mai 2020 16:58:59


-- note: handle is optional. If not provided, new temp file will be created
-- returns: handle
local function write_to_tempfile( buffer, handle)
  if handle == nil then
    handle = io.tmpfile()
  end

  handle:write( buffer)
  return handle
end

function file( filename, mode)

  local t = nil

  local hFile = io.open( filename, mode)
  if not hFile then
    print( "error opening",filename,mode)

  else
    t = {
      read_line = function()
        return hFile:read("*l")
      end
    }

    local mt = {
      __gc = function()
          hFile:close()
      end
    }

    setmetatable( t, mt)
  end

  return t
end

local function open_ro( filename)
  return file( filename, "r")
end

local function open_rw( filename)
  return file( filename, "rw")
end


local function save_table( t, t_filename)
  local dump_location = exec_path .. t_filename

  local hFile = open_rw( t_filename)
  if hFile then
    local is_ok,err = hFile:write( "return ", tprint( t))
    if not is_ok then
      print( err)
    else
      print( "written :",dump_location)
    end
  end
end



local function is_existing( filename)
   local is_ok = open_ro( filename)
   if is_ok then is_ok = true end
   return is_ok
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
local function load_table( t_filename)
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
    write_to_tempfile = write_to_tempfile
  }
else
  -- test
  main()
end

