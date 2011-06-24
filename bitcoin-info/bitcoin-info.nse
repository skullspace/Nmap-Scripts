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

-- magic values that determine which network messages are for
MAGIC = {
  MainNet = "D9B4BEF9",
  TestNet = "DAB5BFFA",
}

-- commands are strings null padded to 12 characters
COMMAND = {
	Version = "76657273696f6e0000000000", -- "version"
}

VERSIONPACKET = bin.pack("H", "f9beb4d976657273696f6e0000000000550000002c7e000001000000000000000eef034e00000000010000000000000000000000000000000000ffff62f7061f208d010000000000000000000000000000000000ffffc0a8006a208d7a7371ba6a0d0ef9007a7d0000")

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

  -- construct a version request packet
  packet = bin.pack("H", MAGIC.MainNet)
  packet = packet .. bin.pack("H", COMMAND.Version)
  packet = packet .. bin.pack("H", "00000000")
  
  -- version packet is 85 length payload
  --packer = packet .. bin.pack( =
  
  --packet = VERSIONPACKET
  
  -- send it
  socket:send(packet)
  
  -- recieve a version reply packet
  local status
  local pos
  local magic = ""
  local command
  local length
  local checksum
  -- header
  status, header = socket:receive_bytes(4)

  pos, magic = bin.unpack("<I", header)
  --pos, command = bin.unpack("<A12", header, pos)
  --pos, length = bin.unpack("<I", header, pos)
  --pos, checksum = bin.unpack("<H4", header, pos)
stdnse.print_debug(0, "magic: %X", magic)  
  -- process it
  
  
  -- output it
  
  -- output the server flags nicely
  --able.insert(result, string.format("| Server Flags: 0x%04x", response.flags.raw))
  --table.insert(result, string.format("|   Super Client: %s", response.flags.SuperClient and "Yes" or "No"))
  --table.insert(result, string.format("|_  Copy File: %s", response.flags.CopyFile and "Yes" or "No")) 

  -- other info
  --table.insert(result, string.format("Server Name: %s", response.server_name))
  --table.insert(result, string.format("Machine Type: %s", response.machine_type))
  
  table.insert(result, string.format("result"))
  return stdnse.format_output(true, result)
end
