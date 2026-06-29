local KEYVAL = "insert"
-- test_key.lua
-- Fired when the insert key is pressed
Tcp.Send("127.0.0.1", 27051, "SET DevMenu Active\n")
Cheat.DisplayOptions()