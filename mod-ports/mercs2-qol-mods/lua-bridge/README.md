# lua-bridge (mercs2-qol-mods port)

Exposes Mercenaries 2's statically-linked Lua 5.1.2 runtime via a localhost TCP REPL on `127.0.0.1:27050`, allowing arbitrary Lua chunks to be executed against the live engine state. It also features a thread-optimized Lua script loader supporting boot-time, level-load, and hotkey-triggered scripts.

Ported from [loganw234/Mercenaries2](https://github.com/loganw234/Mercenaries2) to the [mercs2-qol-mods SDK](https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).

> [!NOTE]
> Tested and verified working against **`v0.2.0` of the `pmc_bb.dll` loader** (the Mercenaries Fan Build loader).

---

## Features

### 1. The REPL Socket Server
Exposes a localhost socket interface. When a client connects to `127.0.0.1:27050` and sends a Lua chunk terminated with the line `<<<RUN>>>`, the chunk is queued and executed on the next game engine frame, returning the results back over the socket followed by `<<<END>>>`.

### 2. Global `Tcp.Send` Telemetry
Registers a global `Tcp` namespace containing `Tcp.Send(host, port, msg)`.
*   **ABI Hijack:** Implemented the custom calling convention of the game's `luaL_register` (`ECX = L`, `EAX = libname`, `[esp+4] = table`, caller cleans 4 bytes) using inline GCC assembly.
*   **Localhost Security Restriction:** Enforces loopback-only connections (`127.0.0.0/8` IP space). Attempts to communicate with external hosts are blocked for security.

### 3. Native Script Loader
Recursively scans for and runs scripts dropped into three folders under `<game>/scripts/`:

#### 📁 `scripts/OnBoot/`
*   Executed immediately on the main thread when a valid Lua state (`L`) is first captured.
*   Ideal for early-stage memory overrides, variable initialization, or library overrides.

#### 📁 `scripts/OnLoad/`
*   Executed on the main thread as soon as the level loader completes (milestone `"GlobalExit - Complete"`), signaling control has returned to the player.
*   Safe for hud modifications, spawning entities, or starting telemetry loops.

#### 📁 `scripts/OnKey/`
*   **Background Thread Polling:** Spawns a dedicated native background thread (`LoaderKeyThread`) that polls hotkeys at 30Hz using `GetAsyncKeyState`.
*   **I/O Offloading:** The background thread opens and reads `.lua` scripts into memory, offloading slow disk reads from the game's main thread to prevent frame stutters.
*   **Multiple Script Bindings:** Hotkeys are resolved per-script (using `was_down` edge tracking), allowing multiple scripts to be bound to the same key.
*   **Metadata Declared Bindings:** Scripts can declare their default hotkey by specifying `local KEYVAL = "keyname"` on the first 10 lines.

---

## Configuration

### Mod Configuration (`lua_bridge.ini`)
Configures the REPL server bindings and the loader switches:
```ini
[repl]
host = 127.0.0.1       ; bind address (localhost only for security)
port = 27050           ; REPL server port

[loader]
loader_enabled = 1     ; master script loader switch
loader_onboot = 1      ; enable OnBoot script directory
loader_onload = 1      ; enable OnLoad script directory
loader_delay_ms = 50   ; delay (ms) between consecutive script loads
```

### Script Loader Bindings (`lua_loader.ini`)
Auto-generated in `<game>/scripts/` on first run. Lists the execution priority order and hotkeys:
```ini
; lua_loader.ini — Lua Script Loader Configuration
; Define execution order for [OnBoot] and [OnLoad] (lowest numbers load first)
; Define hotkey triggers under [OnKey] (e.g. script.lua = F1 or script.lua = insert)
;
; Virtual Key codes reference: https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes
; Common keys: insert, delete, home, end, pageup, pagedown, space, enter, escape, F1..F12, A..Z, 0..9

[OnBoot]
print_boot.lua = 10

[OnLoad]
print_load.lua = 10

[OnKey]
test_key.lua = insert
```

---

## Install

1. Drop the built `lua_bridge.asi` and `lua_bridge.ini` into your game's `scripts/` folder.
2. Launch the game using `pmc_bb.dll` (or any compatible ASI loader).
3. Connect with a console client (e.g. `py tools/lua_console.py`).

## Build

```sh
cd mods/lua-bridge
make STRIP_MINGW=strip
```

Output: `lua_bridge.asi`.

---

## Acknowledgements

- **u/Kunster_** on r/MercenariesGames for describing the Lua registration-table patch technique.
- The **mercs2-qol-mods** authors for the SDK this mod plugs into.
- **Tsuda Kageyu** for MinHook (vendored by the SDK, BSD-2-Clause).

## License

MIT
