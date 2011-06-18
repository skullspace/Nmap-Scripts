description = [[
Gathers information from a bitcoin client.
]]

-- TODO: add @output
-- @output

-- Version 0.1
-- Created 2011/06/18 - v0.1 - created by Andrew Orr

author = "Andrew Orr"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
-- TODO: update categories
categories = {"discovery", "safe"}

-- TODO: check all these if they are needed
require 'shortport'
require 'stdnse'
require 'bit'

portrule = shortport.portnumber(8333, "tcp")

action = function(host, port)

  local socket = nmap.new_socket()
  local status
  local result = {}
  local temp
  
  -- set a reasonable timeout value
  socket:set_timeout(5000)
  
  -- do some exception handling / cleanup
  local catch = function()
    socket:close()
  end
  
  local try = nmap.new_try(catch)

  try( socket:connect(host, port) )

  -- get our data
  
  -- output the server flags nicely
  table.insert(result, string.format("| Server Flags: 0x%04x", response.flags.raw))
  table.insert(result, string.format("|   Super Client: %s", response.flags.SuperClient and "Yes" or "No"))
  table.insert(result, string.format("|_  Copy File: %s", response.flags.CopyFile and "Yes" or "No")) 

  -- other info
  table.insert(result, string.format("Server Name: %s", response.server_name))
  table.insert(result, string.format("Machine Type: %s", response.machine_type))
  
  return stdnse.format_output(true, result)
end
