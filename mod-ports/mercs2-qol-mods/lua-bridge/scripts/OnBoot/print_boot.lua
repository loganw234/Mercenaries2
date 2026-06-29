-- print_boot.lua
-- Fired during early captured Lua VM initialization
Tcp.Send("127.0.0.1", 27051, "SET BootStatus Loaded\n")
