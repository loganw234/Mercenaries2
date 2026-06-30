# Merc2Reborn

> [!WARNING]
> **This repository has been restructured and active mod development has moved to new locations:**
> * **Experimental Mods**: For the mods developed during this phase of the project, visit [Merc2-Mods-Exp](https://github.com/loganw234/Merc2-Mods-Exp).
> * **Community Modkit**: For the community Modkit/Mod Manager that all further mods will be built around, visit [mercs2-modkit](https://github.com/Mercenaries-Fan-Build/mercs2-modkit).


A revival project for **Mercenaries 2: World in Flames** (2008, Pandemic
Studios / Electronic Arts). Restores online services and exposes the
game's statically-linked Lua 5.1.2 runtime for modding.

The game's official online services were permanently shut down. This
project re-implements the matchmaking handshake (FESL / Theater / GameSpy
emulation) so the multiplayer mode works again, and adds an ASI bridge
that lets you execute arbitrary Lua against the live engine — including
opening the dev cheat menu the original developers left in the binary.

<p align="center">
  <img src="img/cheat_menu_in_game.png" alt="The dev cheat menu rendered in-game via Cheat.DisplayOptions()" width="380"><br>
  <em>The dev cheat menu, opened in-game via a single Lua call to <code>Cheat.DisplayOptions()</code>.</em>
</p>

## Heads-up: this is iterative reverse-engineering, not polished code

A lot of what's here is leftover from earlier attempts and experiments.
Things that worked stayed in; things that turned out to be unnecessary
sometimes also stayed in because removing them risks breaking the
combination that *does* work, and nobody's gone back to clean up yet.

A concrete example: the C++ side spoofs the system clock to 2012-06-15
because the very first attempt at getting the FESL TLS handshake to
succeed used cert-validity-window tricks. Other fixes layered on top
later (the FESL CA key replay, the `WinVerifyTrust` blindfold) probably
make the time spoof redundant now — but it hasn't been tested without
it, so it's still there. The whole codebase has pockets like that.

If you see something that looks vestigial or weirdly specific, it
probably is. Pull requests welcome. Just expect rough edges.

## Project status

| Phase | Status |
|------|--------|
| **Phase 1 — Multiplayer revival** (FESL emulation + UDP relay) | ✅ Working (no port forwarding required — see [Multiplayer hosting](#multiplayer-hosting)) |
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
   py tools/lua_repl.py < tools/probe_player_full.lua > out/runs/probe_player_full.txt
   py tools/extract_repl_result.py out/runs/probe_player_full.txt
   ```

### Run the FESL server emulator

**Most people don't need to do this.** The public server at `refesl.live`
already handles matchmaking for everyone — the client-side fix
(`Merc2Fix.asi`) routes you there automatically. Only read on if you
want to host your own FESL backend.

```sh
python2 server.py
```

Hosts FESL on `:18710` (SSLv3 + RC4), Theater on `:18715` (plaintext
TCP), GameSpy availability on UDP `:27900`.

**Standing this up is not trivial.** The original game's handshake
requires **SSLv3 with an RC4 cipher** — both have been removed from
essentially every modern OS, language runtime, and OpenSSL build in
the last decade because they're cryptographically broken (BEAST, POODLE,
the RC4 biases). You can't just `pip install` your way past this.

What actually works in production right now:
- An **Ubuntu 14.04 VM** (or similar vintage) that still ships an
  OpenSSL old enough to negotiate SSLv3+RC4.
- **Python 2.7** linked against that OpenSSL.
- The VM kept network-isolated except for the game ports, because
  exposing legacy TLS to the open internet on a host that also does
  anything else is a bad idea.

Modern Python 3 + modern OpenSSL will refuse to even compile in the
needed ciphers. Newer Ubuntu / Debian / RHEL ship OpenSSL builds with
SSLv3 disabled at the build level. If you go this route, plan on
running it in a sandboxed VM and don't co-locate it with anything else
you care about.

If you just want to play the game, use `refesl.live` — no server work
needed.

### Multiplayer hosting

**No port forwarding required.** The original game used direct P2P
for the actual game traffic, which historically meant the host had to
open UDP `10000` on their router. The server now runs a UDP relay
that proxies player↔player traffic on its own IP: each match gets a
port from a pool (UDP `10000`–`10100`), Theater hands the relay
IP+port to both clients, and both sides connect outbound. NAT and
firewalls on either end shouldn't matter for a normal home setup.

The relay is live and in light testing. If something breaks for you,
please post logs — early reports help shake out edge cases.

**Troubleshooting**: if you can sign into your account and see the
lobby list but **can't actually connect to a game** (the lobby
appears but you never land in-session, or you join and immediately
get dropped), the relay path may not be reaching you cleanly. As a
fallback the original direct-P2P path still works — the host can
forward **UDP 10000** on their network and try again. That's the
single most useful diagnostic step: if the game then works with
forwarding enabled, it confirms the relay is the layer to look at
rather than anything client-side.

## Modding entry points

### The Lua console

The friendliest way to drive the bridge is [`tools/lua_console.py`](tools/lua_console.py)
— a single-file tkinter IDE (stdlib only, no `pip install` needed)
with tabs, Lua syntax highlighting, line numbers, persistent output
history, save/open `.lua` files, and a bridge-status indicator that
turns green when the game is running with the ASI loaded. The
**full release zip ships a PyInstaller-frozen `lua_console.exe`**
alongside the ASI so end users don't need Python installed — just
double-click. A `tools.json` companion manifest is included as a
proposal for any mod manager that wants to surface a "Launch Tool"
button on this mod's page (intended for future
[mercs2-modkit](https://github.com/Mercenaries-Fan-Build/mercs2-modkit)
integration).

<p align="center">
  <img src="img/lua_console.png" alt="lua_console.py — tabbed editor with Lua syntax highlighting, output panel, bridge status indicator" width="780"><br>
  <em>Editor on top, output panel below, bridge status (green dot, bottom right) shows the ASI is listening. The script shown is the default starter, not the cheat-menu opener.</em>
</p>

Run with `py tools/lua_console.py`. `Ctrl+Enter` or `F5` to execute,
`Ctrl+T` for a new tab, `Ctrl+S` to save. For one-shot piping or
headless use the bare-bones [`tools/lua_repl.py`](tools/lua_repl.py)
is still there.

### Useful starting calls

Once the bridge is up:

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

- **u/Kunster_** on r/MercenariesGames for [Mercenaries 2 PC Cheat
  Menu](https://www.reddit.com/r/MercenariesGames/comments/1ufm2d1/mercenaries_2_pc_cheat_menu/),
  describing the Lua registration-table patch technique — pointing
  this project at hooking `luaL_register` to intercept `print` is
  what made Phase 2 possible.
- **Claude** (Anthropic) and **Gemini** (Google) — substantial AI
  assistance throughout the project: reverse-engineering the Lua
  bridge, debugging the executor and the non-stock `luaB_pcall`,
  mapping the engine API surface, and authoring large parts of the
  probe scripts and documentation under [tools/](tools/).
- **MinHook** by Tsuda Kageyu (BSD 2-Clause) — bundled in
  [Merc2Fix/include](Merc2Fix/include) and
  [Merc2Fix/src](Merc2Fix/src).
- **dxwrapper** by elishacloud — the ASI loader this project plugs into.
- **r/MercenariesGames** for keeping the modding community alive long
  past the official servers' shutdown.

## License

[MIT](LICENSE). This project ships no game assets or binaries; you must
own a legitimate copy of Mercenaries 2: World in Flames to use it.
