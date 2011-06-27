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
require 'openssl'

portrule = shortport.portnumber(8333, "tcp")

-- magic values that determine which network messages are for
MAGIC = {
  MainNet = "D9B4BEF9",
  TestNet = "DAB5BFFA",
}

-- commands
COMMAND = {
	Version = "version", 
	VerACK  = "verack",
	GetAddr = "getaddr"
}

-- versions
VERSION = {
	Default = 31415
}

-- services
SERVICES = {
	Default = 1 -- NODE_NETWORK only
}

local function create_bitcoin_network_address(ip, port)
	local IPV4_MAPPED_IPV6_HEADER = "00000000000000000000FFFF"

	addr = bin.pack("<L", SERVICES.Default)
	addr = addr .. bin.pack("H", IPV4_MAPPED_IPV6_HEADER)
	addr = addr .. bin.pack("I", ip)
	addr = addr .. bin.pack("S", port)
	return addr
end

local function decode_bitcoin_packet (packet)
	local command
	local payload
	local pos
	local length

	_, command = bin.unpack(packet, "<A12", 4)
	_, length = bin.unpack(packet, "<I", 16)

	-- chop off any nulls at the end
	while string.byte(command,string.len(command)) == 0 do
		command = string.sub(command, 0, -1)
	end

	-- parse out payload
	payload = ""
	pos = 24
	repeat
		pos, temp = bin.unpack("C", pos)
		payload = payload .. temp
	until (pos - 24) == length

	return command, payload
end

local function decode_version_payload(payload)
	local version
	local services
	local timestamp
	local addr_me
	local addr_you
	local nonce
	local sub_version_num
	local start_height

	pos, version = bin.unpack("<I", payload, 0)
	pos, services = bin.unpack("<L", payload, pos)
	pos, timestamp = bin.unpack("<L", payload, pos)
	pos, addr_me = bin.unpack("A26", payload, pos)
	if version >= 106 then
		pos, addr_you = bin.unpack("A26", payload, pos)
		pos, nonce = bin.unpack("<L", payload, pos)
		pos, sub_version_num = bin.unpack("p", payload, pos)
		if version >= 209 then
			pos, start_height = bin.unpack("<I", payload, pos)
		end
	end

	return 
end

local function create_bitcoin_packet (command, payload)
	local header
	local SHA256 = "sha256"

	-- pad command with nulls to length 12
	-- in lua, nulls don't terminate strings
	repeat
		command = commmand .. string.char(00)
	until string.len(command) == 12

	-- header starts out with a 4 byte magic value that tells bitcoin to use the main network (as opposed to the test network)
	header = bin.pack("<H", MAGIC.NetMain)

	-- next we have the command itself
	header = header .. bin.pack("<A", command)

	-- and the length of the payload
	header = header .. bin.pack("<I", string.len(payload))

	-- TODO: add graceful failing if openssl isn't available as per http://nmap.org/nsedoc/lib/openssl.html
	-- and the checksum of the payload
	-- this is first 4 bytes of sha256(sha256(payload))
	header = header .. bin.pack("<I", openssl.digest(SHA256, openssl.digest(SHA256, payload)))
	
	-- header is done, return it together with the payload, which makes up a single bitcoin packet
	return header .. payload
end

local function create_version_payload(addr_you)
	local payload
	local timestamp = os.time()
	local addr_me
	local nonce
	local start_height

	-- TODO: format IP addresses properly
	-- TODO: generate nonce
	-- TODO: set start_height

	payload = bin.pack("<I", VERSION.Default)
	payload = payload .. bin.pack("<L", SERVICES.Default)
	payload = payload .. bin.pack("<L", timestamp)
	payload = payload .. bin.pack("<S", addr_me)
	payload = payload .. bin.pack("<S", addr_you)
	payload = payload .. bin.pack("<L", nonce)
	payload = payload .. bin.pack("<I", start_height)

	return payload
end



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
