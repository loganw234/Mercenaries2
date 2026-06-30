# debug-overlay (mercs2-qol-mods port)

An in-game debug HUD that draws a labeled key/value list as a D3D9
overlay, controlled remotely via simple text commands over TCP.

Any other mod (C, Lua, or external tool) can send `SET key value`
commands to update what the overlay displays — without ever touching
D3D themselves. Companion to `multiplayer-restore/` and `lua-bridge/`
in this directory.

> [!NOTE]
> Tested and verified working against **`v0.2.0` of the `pmc_bb.dll` loader** (the Mercenaries Fan Build loader).

## Screenshots

![Default Layout](../../../img/debug_overlay_1.png)
*Run 1: Default layout showing typical in-game variables.*

![Grid Layout](../../../img/debug_overlay_2.png)
*Run 2: Top-center grid layout showing compact numeric variables.*

![Diagnostics Dashboard](../../../img/debug_overlay_3.png)
*Run 3: Large diagnostics dashboard showing custom colors, custom Courier New font, and a custom position.*

## What it does

- Hooks `IDirect3DDevice9::EndScene` (via `Direct3DCreate9` →
  `IDirect3D9::CreateDevice` → vtable chain) and renders a labeled
  key/value list on top of the game's frame.
- Listens on TCP `127.0.0.1:27051` for a tiny line-based command
  protocol.
- Auto-sizes the background box to fit current content. Supports 1–4
  column grid layout.
- All position / size / colors / fonts configurable via
  `debug_overlay.ini`.

## Install

1. Drop `debug_overlay.asi` and `debug_overlay.ini` into your
   Mercenaries 2 install folder.
2. Launch the game with any ASI loader (`pmc_bb.dll`, dxwrapper, …).
3. Send commands over TCP from any source. Quickest smoke test:
   ```sh
   echo "SET fps 60" | nc 127.0.0.1 27051
   echo "SET cash 1141700" | nc 127.0.0.1 27051
   ```
   The overlay updates immediately.

## Command protocol

Line-based, plaintext TCP. One command per `\n`-terminated line. The
server doesn't reply to most commands (fire-and-forget), so connections
are cheap.

| Command | Effect |
|---|---|
| `SET <key> <value...>` | Set or update a label. Value is everything after `SET <key> ` — may contain spaces, may not contain `\n`. Re-`SET`ting an existing key updates its value in place; insertion order is preserved. |
| `CLEAR <key>` | Remove one label. |
| `CLEAR_ALL` | Remove every label. |
| `SHOW` | Enable rendering (default state on load). |
| `HIDE` | Pause rendering. TCP commands still process; labels just don't draw. |
| `COLOR <key> <RRGGBB>` | Per-label text color override. 6-digit hex. |
| `CONFIG <key> <value>` | Globally override an INI configuration parameter in memory (e.g. `CONFIG columns 3` or `CONFIG font_size 18`). The original `.ini` file on disk remains untouched. |
| `RESET` | Reloads configuration from the original `.ini` file on disk and resets visibility to `SHOW`. |
| `PING` | Server replies `PONG\n`. Connection-liveness check. |

Unknown commands are logged and ignored.

## Configuration (`debug_overlay.ini`)

See the bundled file for inline comments. Key knobs:

| Section | Key | Default | Notes |
|---|---|---|---|
| `[overlay]` | `enabled` | `1` | Master on/off |
| | `columns` | `1` | Grid columns, 1–4. Row-major fill |
| | `font_name` | `Consolas` | Any installed Windows font face |
| | `font_size` | `14` | Pixels |
| | `padding` | `8` | Internal padding around content |
| | `col_spacing` | `24` | Extra px between columns |
| | `line_spacing` | `4` | Extra px between rows |
| | `bg_color` | `000000` | Hex RRGGBB |
| | `bg_alpha` | `0.65` | 0.0–1.0 |
| | `text_color` | `FFFFFF` | Default per-label color |
| `[anchor]` | `position` | `top-left` | One of `top-left` / `top-right` / `bottom-left` / `bottom-right` / `custom` |
| | `x` / `y` | `16` | Offset from anchor in px (absolute for `custom`) |
| `[server]` | `host` | `127.0.0.1` | Bind address |
| | `port` | `27051` | TCP port |

## Build

If this directory lives under `mercs2-qol-mods/mods/`:

```sh
cd mods/debug-overlay
mingw32-make STRIP_MINGW=strip
```

Out-of-tree:

```sh
mingw32-make SDK_DIR=/path/to/mercs2-qol-mods/sdk STRIP_MINGW=strip
```

Output: `debug_overlay.asi` (~77 KB stripped).

## How other mods talk to it

**External tools / scripts:**

Any TCP client works. From PowerShell, Python, netcat, etc.:

```python
import socket
def overlay_set(k, v, host="127.0.0.1", port=27051):
    with socket.create_connection((host, port)) as s:
        s.sendall(f"SET {k} {v}\n".encode())
```

**C mods (against this SDK):**

A small `m2_overlay.h` helper is planned that wraps the TCP send
behind `m2_overlay_set(key, value)` / `m2_overlay_clear(key)`. Until
then, drop a few lines into your mod to open a socket and `send()`
formatted lines manually. Helper file is small (~80 lines); shipping
it would be a one-PR follow-up.

**Lua scripts via the lua-bridge mod:**

Exposes `Tcp.Send(host, port, msg)` globally inside the Lua runtime out-of-the-box. Lua scripts can send commands to the overlay directly:

```lua
local x, y, z = Object.GetPosition(Player.GetLocalCharacter())
Tcp.Send("127.0.0.1", 27051,
         string.format("SET player_pos %.1f,%.1f,%.1f", x, y, z))
```

*Note: For player security, the `lua-bridge` mod restricts `Tcp.Send` connections exclusively to the localhost loopback space (`127.0.0.0/8`).*

## Status

**Fully verified and tested.** Builds cleanly using MinGW (`i686-w64-mingw32-gcc`) and has been fully runtime-tested and verified working on a real game session loaded with `pmc_bb.dll` (v0.2.0). 

Architecture details:
- Vtable hooking against `IDirect3D9::CreateDevice` (slot 16) and
  `IDirect3DDevice9::EndScene` (slot 42) + `Reset` (slot 16). Standard
  D3D9 slot numbers — well-documented.
- Device-lost / `Reset` cycle handled via `ID3DXFont::OnLostDevice`
  and `OnResetDevice`. Standard D3DX9 lifecycle.
- Render path wrapped in an `IDirect3DStateBlock9` so the game's
  pipeline state is captured and restored — won't disturb subsequent
  draws.
- Same MinGW compatibility shim as `lua-bridge/` (SEH compiled out
  on GCC builds; `MOD_THREAD` for TLS; `_snprintf_s` → `snprintf`).
- Coexists with `windowed-mode` (both hook `CreateDevice` via
  MinHook; chained hooks are MinHook's normal case).

## Known limitations

- Snapshot cap of 128 labels per frame (free pre-allocated buffer; no
  realloc on the render thread). 128 is far above what any realistic
  debug HUD would display; the cap exists to keep the render-path
  bounded.
- No stale-detection / fading yet — labels persist until explicitly
  `CLEAR`ed. The `last_updated_ms` field is captured per label, ready
  for a future "grey out stale" feature; not wired into the renderer
  yet.
- Render thread snapshots the list under the lock then drops it
  before D3D calls. Means a `SET` racing with the render won't
  appear until the next frame — correct semantics, just calling out
  the cycle.

## Acknowledgements

- **windowed-mode** (also in this repo) for the `CreateDevice` hook
  precedent — confirms the approach is compatible with this game.
- **MinHook** by Tsuda Kageyu, vendored by the SDK.

## License

MIT — same as the upstream Merc2Reborn project.
