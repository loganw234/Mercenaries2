# Merc2Reborn

A revival project for **Mercenaries 2: World in Flames** (2008, Pandemic
Studios / Electronic Arts). Restores online services and exposes the
game's statically-linked Lua 5.1.2 runtime for modding.

The game's official online services were permanently shut down. This
project re-implements the matchmaking handshake (FESL / Theater / GameSpy
emulation) so the multiplayer mode works again, and adds an ASI bridge
that lets you execute arbitrary Lua against the live engine — including
opening the dev cheat menu the original developers left in the binary.

## Project status

| Phase | Status |
|------|--------|
| **Phase 1 — Multiplayer revival** (FESL emulation) | ✅ Working |
| **Phase 2 — Lua bridge / cheat menu** | ✅ Working |
| **Phase 3 — Engine API mapping & mod tooling** | 🚧 In progress |

The cheat menu has been opened in-game via `Cheat.DisplayOptions()`. The
engine surface is being mapped — see [tools/engine_api.md](tools/engine_api.md)
for the verified-signature reference and
[tools/agent_handoff.md](tools/agent_handoff.md) for the methodology.

## Repository layout

```
Merc2Reborn/
├── Merc2Fix/              C++ ASI bridge — DNS spoof, FESL CA key patch,
│   ├── dllmain.cpp        time spoof, Lua hooks + REPL server (port 27050).
│   ├── src/               MinHook (BSD 2-Clause, bundled) + buffer/hook code.
│   └── include/MinHook.h
├── server.py              FESL + Theater + GameSpy server emulator
│                          (Python 2.7, SSLv3 + RC4 for the legacy handshake).
├── tools/                 Python REPL, Lua probes, engine API docs.
│   ├── lua_repl.py        Localhost TCP client for the in-game bridge.
│   ├── walk_globals.lua   Runtime _G enumerator (produces globals_ingame.txt).
│   ├── probe_*.lua        Targeted probes per namespace (Player, Object, Vehicle, ...).
│   ├── extract_repl_result.py   Strips REPL framing from raw chunk output.
│   ├── engine_api.md      The verified Lua API reference.
│   ├── lua_api_findings.md      Static-analysis notes (RVAs, packing).
│   ├── agent_handoff.md   Methodology brief for continuing the mapping.
│   ├── find_lua_print.py  PE parser / luaL_Reg scanner (run against game .exe).
│   └── resolve_lua_api.py Capstone-based call-graph walker.
└── out/                   Runtime dumps — globals walks + probe outputs.
```

## How it works

### Multiplayer revival (Phase 1)

- DNS hooks (`gethostbyname`, `getaddrinfo`, `GetAddrInfoW`) redirect
  `*.ea.com` / `*.gamespy.com` / `fesl` traffic to a local or remote
  server emulator.
- `WinVerifyTrust` is intercepted for network cert blobs and forced
  to `ERROR_SUCCESS` so the local-server's self-signed cert is accepted.
- System time is spoofed to 2012-06-15 (inside the served cert's validity
  window). Both Windows time APIs and the CRT `time` family are hooked
  to cover OpenSSL too.
- The MLoader's FESL CA pubkey patch is replayed at a known RVA in
  `Mercenaries2.exe`'s `.rdata`.

### Lua bridge (Phase 2)

- `Merc2Fix.asi` is loaded by `dxwrapper`. It hooks Pandemic's
  `luaL_register` and intercepts the basic-library registration to
  patch `print` / `next` / `tostring` entries with our own pump
  functions — every time a script calls one of these, queued chunks
  drain.
- A small TCP server on `127.0.0.1:27050` accepts Lua chunks, queues
  them, and pumps results back. Pandemic's Lua build packs `TValue`
  to 8 bytes (`lua_Number = float`); the executor accounts for that
  plus a non-stock `luaB_pcall`. See
  [tools/lua_api_findings.md](tools/lua_api_findings.md) for the
  reverse-engineering details.

## Build / run

### Prerequisites
- Visual Studio 2022 (or any toolchain that opens `Merc2Reborn.slnx`).
- A legitimate retail install of Mercenaries 2: World in Flames.
- [dxwrapper](https://github.com/elishacloud/dxwrapper) deployed to
  the game folder (it's what loads `*.asi` plugins).
- Python 3 for `tools/lua_repl.py` and the static analyzers.
  Python 2.7 if you want to run `server.py` standalone.

### Build the ASI
1. Open `Merc2Reborn.slnx` in Visual Studio.
2. Build `Merc2Fix` (Release | Win32). The post-build event copies
   the output as `Merc2Fix.asi` into the game install folder.
   - The xcopy step's destination is hard-coded to
     `C:\Games\Mercenaries 2 World in Flames\`. Adjust in
     [Merc2Fix/Merc2Fix.vcxproj](Merc2Fix/Merc2Fix.vcxproj) if your
     game lives elsewhere.
3. Make sure the game is **closed** when building — the xcopy fails
   silently when the running game holds the file lock.

### Run the game with the bridge
1. Launch the game via the launcher / dxwrapper.
2. Tail `Merc2Debug.log` in the game folder; look for
   `[*] LuaBridge: listening on 127.0.0.1:27050`.
3. From the project folder:
   ```sh
   py tools/lua_repl.py
   lua> return 1 + 1
   lua>
   ```
4. To pipe a probe in:
   ```sh
   py tools/lua_repl.py < tools/probe_player_full.lua > out/probe_player_full.txt
   py tools/extract_repl_result.py out/probe_player_full.txt
   ```

### Run the FESL server emulator
```sh
python2 server.py
```
Hosts FESL on `:18710` (SSLv3 + RC4), Theater on `:18715` (plaintext
TCP), GameSpy availability on UDP `:27900`.

## Modding entry points

Once the bridge is up, useful starting calls:

```lua
-- Open the dev cheat menu
Cheat.DisplayOptions()

-- Player handle + state
local char = Player.GetLocalCharacter()
local x, y, z = Object.GetPosition(char)
Player.AddCash(1000)
Player.SetFuel(300)

-- Equipment loadout
for _, w in ipairs(Object.GetAttachedObjects(char)) do
  local max = Weapon.GetMaxClipAmmo(w)
  if max then Weapon.SetClipAmmo(w, max) end
end

-- Render text on screen
-- Hud.ClassyText supports localized hash strings:  "[0xb7f587a3]"
```

See [tools/engine_api.md](tools/engine_api.md) for the full
VERIFIED reference covering Player, Object, Vehicle, AI, Pda, Hud,
and Localization.

## Acknowledgements

- **u/Kunster_** on r/MercenariesGames for the
  [post](https://www.reddit.com/r/MercenariesGames/) describing the
  Lua registration-table patch technique — pointing this project at
  hooking `luaL_register` to intercept `print` is what made Phase 2
  possible.
- **MinHook** by Tsuda Kageyu (BSD 2-Clause) — bundled in
  [Merc2Fix/include](Merc2Fix/include) and
  [Merc2Fix/src](Merc2Fix/src).
- **dxwrapper** by elishacloud — the ASI loader this project plugs into.
- **r/MercenariesGames** for keeping the modding community alive long
  past the official servers' shutdown.

## License

[MIT](LICENSE). This project ships no game assets or binaries; you must
own a legitimate copy of Mercenaries 2: World in Flames to use it.
