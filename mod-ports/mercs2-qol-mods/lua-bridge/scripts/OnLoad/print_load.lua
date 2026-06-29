-- print_load.lua
-- Fired once the player character has spawned into the game world
Tcp.Send("127.0.0.1", 27051, "SET GameWorld Spawned\n")
