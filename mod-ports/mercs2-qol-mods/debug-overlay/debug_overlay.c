/* debug_overlay.c — in-game debug HUD with a TCP command interface.
 *
 * Hooks D3D9 EndScene to draw a labeled key/value list as an overlay
 * on top of the game's render output. Listens on TCP for
 * SET/CLEAR/COLOR/SHOW/HIDE/PING commands from any mod or external
 * tool, so consumers never have to touch D3D themselves.
 *
 * Companion to multiplayer-restore and lua-bridge in the same
 * mod-ports/ directory. Independent — works with or without either.
 *
 * Protocol (line-based, plaintext TCP on g_cfg.server_port):
 *
 *   SET <key> <value...>     set/update label; value is rest of line
 *   CLEAR <key>              remove one label
 *   CLEAR_ALL                wipe all labels
 *   SHOW                     enable rendering (default)
 *   HIDE                     pause rendering (still receives commands)
 *   COLOR <key> <RRGGBB>     per-label text color
 *   PING                     server replies "PONG\n"
 *
 * The label list is ordered by insertion (first SET appears top-left,
 * subsequent SETs append). Updates preserve position. Re-SETting an
 * existing key is the same as updating it — no churn.
 *
 * Layout: configurable 1..4 column grid. Background auto-grows to fit
 * content. All sizes / positions / colors live in debug_overlay.ini.
 *
 * Author: loganw234 — see https://github.com/loganw234/Mercenaries2
 */

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <d3d9.h>
#include <d3dx9.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "m2_log.h"
#include "m2_hook.h"
#include "m2_ini.h"

/* ------------------------------------------------------------------------ *
 * Compatibility shim — same pattern used by lua_bridge.c. Makes the
 * source compile under both MinGW (no SEH, no MSVC safe-strings, GCC
 * TLS) and MSVC (native everything).
 * ------------------------------------------------------------------------ */
#ifdef _MSC_VER
  #define MOD_THREAD __declspec(thread)
#else
  #define _snprintf_s(buf, sz, _trunc, ...) snprintf((buf), (sz), __VA_ARGS__)
  #define strncpy_s(dst, dst_sz, src, count) \
      (strncpy((dst), (src), (count)), (dst)[(dst_sz) - 1] = 0, 0)
  #define MOD_THREAD __thread
#endif

/* d3dx9.lib and d3d9.lib link via the Makefile's LDFLAGS. */

/* ======================================================================== *
 * Config (loaded from debug_overlay.ini)
 * ======================================================================== */
typedef struct OverlayConfig {
    /* rendering */
    int   enabled;        /* master on/off */
    int   columns;        /* 1..4 */
    int   font_size;      /* px height */
    int   padding;        /* px around content */
    int   col_spacing;    /* extra px between columns */
    int   line_spacing;   /* extra px between rows */
    DWORD bg_color;       /* 0xRRGGBB (alpha applied separately) */
    float bg_alpha;       /* 0.0 (clear) .. 1.0 (opaque) */
    DWORD text_color;     /* default 0xRRGGBB if a label has no COLOR */
    char  font_name[64];

    /* position */
    char  anchor[16];     /* top-left / top-right / bottom-left / bottom-right / custom */
    int   pos_x;          /* offset from anchor (for non-custom) or absolute (for custom) */
    int   pos_y;

    /* server */
    char  server_host[64];
    int   server_port;
} OverlayConfig;

static OverlayConfig g_cfg;

static void cfg_set_defaults(void) {
    g_cfg.enabled      = 1;
    g_cfg.columns      = 1;
    g_cfg.font_size    = 14;
    g_cfg.padding      = 8;
    g_cfg.col_spacing  = 24;
    g_cfg.line_spacing = 4;
    g_cfg.bg_color     = 0x000000;
    g_cfg.bg_alpha     = 0.65f;
    g_cfg.text_color   = 0xFFFFFF;
    strcpy(g_cfg.font_name, "Consolas");
    strcpy(g_cfg.anchor, "top-left");
    g_cfg.pos_x = 16;
    g_cfg.pos_y = 16;
    strcpy(g_cfg.server_host, "127.0.0.1");
    g_cfg.server_port = 27051;
}

/* Parse "RRGGBB" hex into a DWORD 0x00RRGGBB. Returns 1 on success. */
static int parse_hex_color(const char* s, DWORD* out) {
    DWORD v = 0;
    int i;
    if (!s) return 0;
    for (i = 0; i < 6; i++) {
        char c = s[i];
        int d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        v = (v << 4) | (DWORD)d;
    }
    if (s[6] != 0 && s[6] != '\n' && s[6] != '\r' && s[6] != ' ') return 0;
    *out = v & 0xFFFFFF;
    return 1;
}

static void OnIniKV(void* ud, const char* key, const char* value) {
    (void)ud;
    if (!key || !value) return;
    if      (_stricmp(key, "enabled")      == 0) g_cfg.enabled      = m2_ini_bool(value);
    else if (_stricmp(key, "columns")      == 0) {
        int c = atoi(value);
        g_cfg.columns = (c >= 1 && c <= 4) ? c : 1;
    }
    else if (_stricmp(key, "font_size")    == 0) g_cfg.font_size    = atoi(value);
    else if (_stricmp(key, "padding")      == 0) g_cfg.padding      = atoi(value);
    else if (_stricmp(key, "col_spacing")  == 0) g_cfg.col_spacing  = atoi(value);
    else if (_stricmp(key, "line_spacing") == 0) g_cfg.line_spacing = atoi(value);
    else if (_stricmp(key, "bg_alpha")     == 0) g_cfg.bg_alpha     = (float)atof(value);
    else if (_stricmp(key, "bg_color")     == 0) parse_hex_color(value, &g_cfg.bg_color);
    else if (_stricmp(key, "text_color")   == 0) parse_hex_color(value, &g_cfg.text_color);
    else if (_stricmp(key, "font_name")    == 0) {
        strncpy(g_cfg.font_name, value, sizeof(g_cfg.font_name) - 1);
        g_cfg.font_name[sizeof(g_cfg.font_name) - 1] = 0;
    }
    else if (_stricmp(key, "position")     == 0 || _stricmp(key, "anchor") == 0) {
        strncpy(g_cfg.anchor, value, sizeof(g_cfg.anchor) - 1);
        g_cfg.anchor[sizeof(g_cfg.anchor) - 1] = 0;
    }
    else if (_stricmp(key, "x") == 0 || _stricmp(key, "pos_x") == 0) g_cfg.pos_x = atoi(value);
    else if (_stricmp(key, "y") == 0 || _stricmp(key, "pos_y") == 0) g_cfg.pos_y = atoi(value);
    else if (_stricmp(key, "host") == 0) {
        strncpy(g_cfg.server_host, value, sizeof(g_cfg.server_host) - 1);
        g_cfg.server_host[sizeof(g_cfg.server_host) - 1] = 0;
    }
    else if (_stricmp(key, "port") == 0) {
        int p = atoi(value);
        if (p > 0 && p <= 65535) g_cfg.server_port = p;
    }
}

/* ======================================================================== *
 * Label state — linked list, insertion-ordered.
 * ======================================================================== */
typedef struct OverlayLabel {
    char  key[64];
    char  value[256];
    DWORD color;            /* 0xRRGGBB; 0xFFFFFFFF = use g_cfg.text_color */
    DWORD last_updated_ms;  /* GetTickCount at last SET — for future stale-detect */
    struct OverlayLabel* next;
} OverlayLabel;

static CRITICAL_SECTION g_state_mtx;
static OverlayLabel* g_labels_head = NULL;
static OverlayLabel* g_labels_tail = NULL;
static int g_label_count = 0;
static BOOL g_visible = TRUE;

#define UNSET_COLOR 0xFFFFFFFFu

static OverlayLabel* label_find(const char* key) {
    OverlayLabel* p;
    for (p = g_labels_head; p; p = p->next) {
        if (_stricmp(p->key, key) == 0) return p;
    }
    return NULL;
}

/* Updates if present, appends if new. Always under g_state_mtx. */
static void label_set(const char* key, const char* value) {
    OverlayLabel* lbl = label_find(key);
    if (lbl) {
        strncpy(lbl->value, value, sizeof(lbl->value) - 1);
        lbl->value[sizeof(lbl->value) - 1] = 0;
        lbl->last_updated_ms = GetTickCount();
        return;
    }
    lbl = (OverlayLabel*)calloc(1, sizeof(OverlayLabel));
    if (!lbl) return;
    strncpy(lbl->key, key, sizeof(lbl->key) - 1);
    strncpy(lbl->value, value, sizeof(lbl->value) - 1);
    lbl->color = UNSET_COLOR;
    lbl->last_updated_ms = GetTickCount();
    if (g_labels_tail) g_labels_tail->next = lbl;
    else               g_labels_head = lbl;
    g_labels_tail = lbl;
    g_label_count++;
}

static void label_clear(const char* key) {
    OverlayLabel **pp = &g_labels_head, *prev = NULL;
    while (*pp) {
        if (_stricmp((*pp)->key, key) == 0) {
            OverlayLabel* doomed = *pp;
            *pp = doomed->next;
            if (g_labels_tail == doomed) g_labels_tail = prev;
            free(doomed);
            g_label_count--;
            return;
        }
        prev = *pp;
        pp = &(*pp)->next;
    }
}

static void label_clear_all(void) {
    OverlayLabel* p = g_labels_head;
    while (p) { OverlayLabel* n = p->next; free(p); p = n; }
    g_labels_head = g_labels_tail = NULL;
    g_label_count = 0;
}

static void label_set_color(const char* key, DWORD color) {
    OverlayLabel* lbl = label_find(key);
    if (lbl) lbl->color = color & 0xFFFFFF;
}

/* ======================================================================== *
 * TCP command server
 * ======================================================================== */
static SOCKET g_listen_sock = INVALID_SOCKET;

static void handle_command_line(const char* line, SOCKET client) {
    /* Skip leading whitespace. */
    while (*line == ' ' || *line == '\t') line++;
    if (!*line) return;

    if (strncmp(line, "SET ", 4) == 0) {
        const char* p = line + 4;
        const char* sp = strchr(p, ' ');
        if (!sp) return;
        char key[64];
        size_t klen = (size_t)(sp - p);
        if (klen >= sizeof(key)) klen = sizeof(key) - 1;
        memcpy(key, p, klen); key[klen] = 0;
        const char* value = sp + 1;
        EnterCriticalSection(&g_state_mtx);
        label_set(key, value);
        LeaveCriticalSection(&g_state_mtx);
    } else if (strncmp(line, "CLEAR_ALL", 9) == 0) {
        EnterCriticalSection(&g_state_mtx);
        label_clear_all();
        LeaveCriticalSection(&g_state_mtx);
    } else if (strncmp(line, "CLEAR ", 6) == 0) {
        const char* key = line + 6;
        EnterCriticalSection(&g_state_mtx);
        label_clear(key);
        LeaveCriticalSection(&g_state_mtx);
    } else if (strcmp(line, "SHOW") == 0) {
        g_visible = TRUE;
    } else if (strcmp(line, "HIDE") == 0) {
        g_visible = FALSE;
    } else if (strncmp(line, "COLOR ", 6) == 0) {
        const char* p = line + 6;
        const char* sp = strchr(p, ' ');
        if (!sp) return;
        char key[64];
        size_t klen = (size_t)(sp - p);
        if (klen >= sizeof(key)) klen = sizeof(key) - 1;
        memcpy(key, p, klen); key[klen] = 0;
        DWORD c;
        if (parse_hex_color(sp + 1, &c)) {
            EnterCriticalSection(&g_state_mtx);
            label_set_color(key, c);
            LeaveCriticalSection(&g_state_mtx);
        }
    } else if (strcmp(line, "PING") == 0) {
        if (client != INVALID_SOCKET) send(client, "PONG\n", 5, 0);
    } else {
        m2_logf("[debug-overlay] unknown command: %.40s", line);
    }
}

static DWORD WINAPI ServerThread(LPVOID arg) {
    WSADATA w;
    struct sockaddr_in addr;
    BOOL reuse = TRUE;
    (void)arg;

    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        m2_logf("[debug-overlay] WSAStartup failed");
        return 1;
    }
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock == INVALID_SOCKET) {
        m2_logf("[debug-overlay] socket() failed: %lu", (unsigned long)WSAGetLastError());
        return 1;
    }
    setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)g_cfg.server_port);
    inet_pton(AF_INET, g_cfg.server_host, &addr.sin_addr);
    if (bind(g_listen_sock, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(g_listen_sock, 4) != 0) {
        m2_logf("[debug-overlay] bind/listen %s:%d failed: %lu",
                g_cfg.server_host, g_cfg.server_port,
                (unsigned long)WSAGetLastError());
        closesocket(g_listen_sock);
        return 1;
    }
    m2_logf("[debug-overlay] listening on %s:%d", g_cfg.server_host, g_cfg.server_port);

    for (;;) {
        SOCKET c = accept(g_listen_sock, NULL, NULL);
        if (c == INVALID_SOCKET) continue;
        /* Per-client: read lines until close. Simple synchronous loop;
         * we don't expect many concurrent clients. */
        char rx[2048];
        size_t rxlen = 0;
        for (;;) {
            int n = recv(c, rx + rxlen, (int)(sizeof(rx) - rxlen - 1), 0);
            if (n <= 0) break;
            rxlen += (size_t)n;
            rx[rxlen] = 0;
            /* Process all complete lines. */
            const char* p = rx;
            const char* nl;
            while ((nl = (const char*)memchr(p, '\n', rx + rxlen - p)) != NULL) {
                size_t line_len = (size_t)(nl - p);
                if (line_len > 0 && p[line_len - 1] == '\r') line_len--;
                char line[2048];
                if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
                memcpy(line, p, line_len);
                line[line_len] = 0;
                handle_command_line(line, c);
                p = nl + 1;
            }
            size_t consumed = (size_t)(p - rx);
            if (consumed > 0 && consumed < rxlen) memmove(rx, rx + consumed, rxlen - consumed);
            rxlen -= consumed;
        }
        closesocket(c);
    }
}

/* ======================================================================== *
 * D3D9 hook scaffolding
 *
 * Chain: Direct3DCreate9 (exported) → IDirect3D9::CreateDevice (vtable 16)
 *        → IDirect3DDevice9::EndScene (vtable 42) + Reset (vtable 16).
 *
 * Each hook is installed exactly once on the first call that reveals
 * the next vtable. Subsequent calls just trampoline through.
 * ======================================================================== */
typedef HRESULT (WINAPI* CreateDevice_t)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD,
                                         D3DPRESENT_PARAMETERS*, IDirect3DDevice9**);
typedef HRESULT (WINAPI* EndScene_t)(IDirect3DDevice9*);
typedef HRESULT (WINAPI* Reset_t)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);

static CreateDevice_t    orig_CreateDevice    = NULL;
static EndScene_t        orig_EndScene        = NULL;
static Reset_t           orig_Reset           = NULL;

static IDirect3DDevice9* g_device   = NULL;
static ID3DXFont*        g_font     = NULL;
static int               g_screen_w = 1280;
static int               g_screen_h = 720;
static BOOL              g_device_lost = FALSE;
static BOOL              g_endscene_hooked     = FALSE;
static BOOL              g_createdevice_hooked = FALSE;

/* Create / re-create the D3DXFont after a (re-)Reset. */
static void create_font(void) {
    if (!g_device) return;
    if (g_font) return;
    HRESULT hr = D3DXCreateFontA(
        g_device,
        g_cfg.font_size,
        0,
        FW_NORMAL,
        1,
        FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        DEFAULT_QUALITY,
        FIXED_PITCH | FF_MODERN,
        g_cfg.font_name,
        &g_font);
    if (FAILED(hr)) {
        m2_logf("[debug-overlay] D3DXCreateFontA failed: 0x%08lX face='%s' size=%d",
                (unsigned long)hr, g_cfg.font_name, g_cfg.font_size);
        g_font = NULL;
    } else {
        m2_logf("[debug-overlay] D3DXCreateFontA OK: face='%s' size=%d ptr=%p",
                g_cfg.font_name, g_cfg.font_size, (void*)g_font);
    }
}

static void destroy_font(void) {
    if (g_font) {
        IUnknown_Release(g_font);
        g_font = NULL;
    }
}

/* Untextured-quad helper for the background. Saves render state via
 * an IDirect3DStateBlock9 so the game's pipeline isn't disturbed. */
static void draw_quad(IDirect3DDevice9* dev, int x, int y, int w, int h, DWORD argb) {
    struct TLVERTEX { float x, y, z, rhw; DWORD color; };
    struct TLVERTEX verts[4];
    verts[0].x = (float)x;     verts[0].y = (float)y;     verts[0].z = 0.0f; verts[0].rhw = 1.0f; verts[0].color = argb;
    verts[1].x = (float)(x+w); verts[1].y = (float)y;     verts[1].z = 0.0f; verts[1].rhw = 1.0f; verts[1].color = argb;
    verts[2].x = (float)x;     verts[2].y = (float)(y+h); verts[2].z = 0.0f; verts[2].rhw = 1.0f; verts[2].color = argb;
    verts[3].x = (float)(x+w); verts[3].y = (float)(y+h); verts[3].z = 0.0f; verts[3].rhw = 1.0f; verts[3].color = argb;

    IDirect3DDevice9_SetTexture(dev, 0, NULL);
    IDirect3DDevice9_SetFVF(dev, D3DFVF_XYZRHW | D3DFVF_DIFFUSE);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ALPHABLENDENABLE, TRUE);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_SRCBLEND,  D3DBLEND_SRCALPHA);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_LIGHTING, FALSE);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_ZENABLE,  FALSE);
    IDirect3DDevice9_SetRenderState(dev, D3DRS_CULLMODE, D3DCULL_NONE);
    IDirect3DDevice9_DrawPrimitiveUP(dev, D3DPT_TRIANGLESTRIP, 2, verts, sizeof(struct TLVERTEX));
}

/* Compose "key: value" once for measurement + rendering. */
static int compose_label(char* buf, size_t cap, const OverlayLabel* lbl) {
    return _snprintf_s(buf, cap, _TRUNCATE, "%s: %s", lbl->key, lbl->value);
}

/* Per-frame draw. Called from the EndScene hook with the game's
 * own device. Safe-state via an IDirect3DStateBlock9 so the
 * game's pipeline configuration is restored on exit. */
static void render_overlay(IDirect3DDevice9* dev) {
    if (!g_visible || !g_cfg.enabled || g_device_lost) return;

    EnterCriticalSection(&g_state_mtx);
    if (g_label_count == 0) { LeaveCriticalSection(&g_state_mtx); return; }

    /* Snapshot the label list (we want to release the lock before
     * D3D calls in case of bugs / reentry). Fixed-size snapshot
     * buffer; ignore overflow beyond N entries. */
    enum { MAX_SNAPSHOT = 128 };
    struct { char text[400]; DWORD color; } snap[MAX_SNAPSHOT];
    int snap_n = 0;
    OverlayLabel* p;
    for (p = g_labels_head; p && snap_n < MAX_SNAPSHOT; p = p->next) {
        compose_label(snap[snap_n].text, sizeof(snap[snap_n].text), p);
        snap[snap_n].color = (p->color == UNSET_COLOR) ? g_cfg.text_color : p->color;
        snap_n++;
    }
    LeaveCriticalSection(&g_state_mtx);
    if (snap_n == 0) return;
    if (!g_font) return;

    /* Layout: row-major into <cols> columns. Per-column width is the
     * widest item that lands in that column. */
    int cols = g_cfg.columns < 1 ? 1 : (g_cfg.columns > 4 ? 4 : g_cfg.columns);
    int rows = (snap_n + cols - 1) / cols;
    int col_widths[4] = {0, 0, 0, 0};
    int i;
    for (i = 0; i < snap_n; i++) {
        RECT r = {0, 0, 0, 0};
        ID3DXFont_DrawTextA(g_font, NULL, snap[i].text, -1, &r,
                            DT_CALCRECT | DT_NOCLIP | DT_LEFT | DT_TOP, 0);
        int w = r.right - r.left;
        int c = i % cols;
        if (w > col_widths[c]) col_widths[c] = w;
    }

    int line_h = g_cfg.font_size + g_cfg.line_spacing;
    int total_w = g_cfg.padding * 2;
    int c;
    for (c = 0; c < cols; c++) total_w += col_widths[c];
    if (cols > 1) total_w += (cols - 1) * g_cfg.col_spacing;
    int total_h = g_cfg.padding * 2 + rows * line_h;

    /* Anchor → top-left corner of the box. */
    int x0, y0;
    if (_stricmp(g_cfg.anchor, "top-right") == 0) {
        x0 = g_screen_w - g_cfg.pos_x - total_w; y0 = g_cfg.pos_y;
    } else if (_stricmp(g_cfg.anchor, "bottom-left") == 0) {
        x0 = g_cfg.pos_x; y0 = g_screen_h - g_cfg.pos_y - total_h;
    } else if (_stricmp(g_cfg.anchor, "bottom-right") == 0) {
        x0 = g_screen_w - g_cfg.pos_x - total_w;
        y0 = g_screen_h - g_cfg.pos_y - total_h;
    } else if (_stricmp(g_cfg.anchor, "custom") == 0) {
        x0 = g_cfg.pos_x; y0 = g_cfg.pos_y;
    } else { /* top-left (default) */
        x0 = g_cfg.pos_x; y0 = g_cfg.pos_y;
    }

    /* Wrap our draws in a state block to preserve the game's pipeline. */
    IDirect3DStateBlock9* sb = NULL;
    HRESULT hr_sb = IDirect3DDevice9_CreateStateBlock(dev, D3DSBT_ALL, &sb);
    if (FAILED(hr_sb)) {
        static BOOL logged_sb = FALSE;
        if (!logged_sb) {
            m2_logf("[debug-overlay] CreateStateBlock failed: 0x%08lX", (unsigned long)hr_sb);
            logged_sb = TRUE;
        }
        return;
    }

    /* One-shot diagnostic on first draw — confirms we got past every
     * guard and are actually issuing GPU commands. */
    static BOOL logged_first_draw = FALSE;
    if (!logged_first_draw) {
        m2_logf("[debug-overlay] first render: %d labels, %dx%d screen, box %dx%d at (%d,%d), font=%p",
                snap_n, g_screen_w, g_screen_h, total_w, total_h, x0, y0, (void*)g_font);
        logged_first_draw = TRUE;
    }

    DWORD bg_argb = ((DWORD)(g_cfg.bg_alpha * 255.0f) << 24) | (g_cfg.bg_color & 0xFFFFFF);
    draw_quad(dev, x0, y0, total_w, total_h, bg_argb);

    int x_base = x0 + g_cfg.padding;
    int y_base = y0 + g_cfg.padding;
    int x_col[4]; x_col[0] = x_base;
    for (c = 1; c < cols; c++) x_col[c] = x_col[c - 1] + col_widths[c - 1] + g_cfg.col_spacing;

    for (i = 0; i < snap_n; i++) {
        int row = i / cols;
        int col = i % cols;
        RECT r;
        INT drew;
        r.left   = x_col[col];
        r.top    = y_base + row * line_h;
        r.right  = r.left + col_widths[col];
        r.bottom = r.top  + line_h;
        DWORD argb = 0xFF000000 | (snap[i].color & 0xFFFFFF);
        drew = ID3DXFont_DrawTextA(g_font, NULL, snap[i].text, -1, &r,
                                   DT_LEFT | DT_TOP | DT_NOCLIP, argb);
        /* One-shot: log the first DrawText so we know it ran and what it returned. */
        if (i == 0) {
            static BOOL logged_dt = FALSE;
            if (!logged_dt) {
                m2_logf("[debug-overlay] first DrawTextA returned %d for '%s' at (%ld,%ld,%ld,%ld) color=0x%08lX",
                        drew, snap[0].text,
                        (long)r.left, (long)r.top, (long)r.right, (long)r.bottom,
                        (unsigned long)argb);
                logged_dt = TRUE;
            }
        }
    }

    IDirect3DStateBlock9_Apply(sb);
    IDirect3DStateBlock9_Release(sb);
}

/* ----- the actual hooks ----- */

/* Lazy device capture: if CreateDevice's hook never fired (wrapper
 * bypassed it), we still get a valid IDirect3DDevice9* as arg0 of
 * EndScene on every frame. Grab it the first time we see it. */
static void on_device_captured_lazy(IDirect3DDevice9* dev) {
    if (g_device) return;
    g_device = dev;

    /* Pull screen size from the back-buffer description. */
    IDirect3DSurface9* bb = NULL;
    if (SUCCEEDED(IDirect3DDevice9_GetBackBuffer(dev, 0, 0, D3DBACKBUFFER_TYPE_MONO, &bb)) && bb) {
        D3DSURFACE_DESC desc;
        if (SUCCEEDED(IDirect3DSurface9_GetDesc(bb, &desc))) {
            g_screen_w = (int)desc.Width;
            g_screen_h = (int)desc.Height;
        }
        IDirect3DSurface9_Release(bb);
    }
    m2_logf("[debug-overlay] device captured (lazy from EndScene): %p, %dx%d",
            (void*)dev, g_screen_w, g_screen_h);
    create_font();
}

static HRESULT WINAPI hook_EndScene(IDirect3DDevice9* dev) {
    /* One-shot diagnostic: confirm the hook is actually being called
     * by the game's render loop. If this never appears in the log,
     * something is wrapping d3d9 below us and our hook doesn't sit
     * on the hot path. */
    static BOOL logged_first = FALSE;
    if (!logged_first) {
        m2_logf("[debug-overlay] hook_EndScene: first fire (dev=%p, font=%p, visible=%d, labels=%d)",
                (void*)dev, (void*)g_font, (int)g_visible, g_label_count);
        logged_first = TRUE;
    }
    if (!g_device) on_device_captured_lazy(dev);
    if (!g_device_lost) render_overlay(dev);
    return orig_EndScene(dev);
}

static HRESULT WINAPI hook_Reset(IDirect3DDevice9* dev, D3DPRESENT_PARAMETERS* pp) {
    /* D3DX9 objects must be told before/after the reset. */
    if (g_font) ID3DXFont_OnLostDevice(g_font);
    g_device_lost = TRUE;
    HRESULT hr = orig_Reset(dev, pp);
    if (SUCCEEDED(hr)) {
        g_device_lost = FALSE;
        if (g_font) ID3DXFont_OnResetDevice(g_font);
        if (pp) {
            if (pp->BackBufferWidth)  g_screen_w = (int)pp->BackBufferWidth;
            if (pp->BackBufferHeight) g_screen_h = (int)pp->BackBufferHeight;
        }
    }
    return hr;
}

static void hook_device_vtable(IDirect3DDevice9* dev) {
    if (g_endscene_hooked) return;
    void** vtbl = *(void***)dev;
    /* EndScene = vtable slot 42, Reset = vtable slot 16 in IDirect3DDevice9. */
    int es_ok = m2_hook_attach(vtbl[42], (void*)hook_EndScene, (void**)&orig_EndScene);
    int rs_ok = m2_hook_attach(vtbl[16], (void*)hook_Reset,    (void**)&orig_Reset);
    g_endscene_hooked = TRUE;
    m2_logf("[debug-overlay] hooked IDirect3DDevice9::EndScene=%s Reset=%s (vtable=%p)",
            es_ok ? "OK" : "FAIL", rs_ok ? "OK" : "FAIL", (void*)vtbl);
}

/* Walk top-level windows owned by the current process; return the
 * largest visible one (a reasonable proxy for "the game's window").
 * Returns NULL if nothing matches. */
typedef struct WndSearch { DWORD pid; HWND best; int best_area; } WndSearch;
static BOOL CALLBACK enum_window_cb(HWND h, LPARAM lp) {
    WndSearch* ws = (WndSearch*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != ws->pid) return TRUE;
    if (!IsWindowVisible(h)) return TRUE;
    RECT r;
    if (!GetWindowRect(h, &r)) return TRUE;
    int area = (r.right - r.left) * (r.bottom - r.top);
    if (area > ws->best_area) { ws->best_area = area; ws->best = h; }
    return TRUE;
}
static HWND find_game_window(void) {
    WndSearch ws; ws.pid = GetCurrentProcessId(); ws.best = NULL; ws.best_area = 0;
    EnumWindows(enum_window_cb, (LPARAM)&ws);
    return ws.best;
}

/* Attempt to create a throwaway IDirect3DDevice9, patch the EndScene
 * + Reset slots in its (shared) vtable, and release.
 *
 * Rationale: some d3d9 wrappers (dxwrapper / dgVoodoo / proxy d3d9.dll
 * shims) hand the game a cached IDirect3DDevice9 without routing the
 * call through IDirect3D9::CreateDevice's vtable slot we patched.
 * Patching the device vtable directly gets us on the hot path
 * regardless of whether the game's CreateDevice ever fires our hook.
 *
 * Returns 1 on success, 0 on failure. Logs the HRESULT on failure so
 * the caller can decide whether to retry. */
static int try_patch_device_vtable_via_temp(IDirect3D9* d3d, HWND hwnd_override) {
    HWND hwnd = hwnd_override;
    BOOL hwnd_is_ours = FALSE;
    if (!hwnd) {
        hwnd = CreateWindowExA(0, "STATIC", "_dbg_overlay_tmp", WS_POPUP,
                               0, 0, 1, 1, NULL, NULL,
                               GetModuleHandleA(NULL), NULL);
        if (!hwnd) {
            m2_logf("[debug-overlay] temp window create failed: GLE=%lu",
                    (unsigned long)GetLastError());
            return 0;
        }
        hwnd_is_ours = TRUE;
    }

    D3DPRESENT_PARAMETERS pp;
    memset(&pp, 0, sizeof(pp));
    pp.BackBufferWidth        = 1;
    pp.BackBufferHeight       = 1;
    pp.BackBufferFormat       = D3DFMT_UNKNOWN;
    pp.BackBufferCount        = 1;
    pp.SwapEffect             = D3DSWAPEFFECT_DISCARD;
    pp.Windowed               = TRUE;
    pp.hDeviceWindow          = hwnd;
    pp.PresentationInterval   = D3DPRESENT_INTERVAL_IMMEDIATE;

    IDirect3DDevice9* tmp_dev = NULL;
    HRESULT hr = IDirect3D9_CreateDevice(
        d3d, D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING | D3DCREATE_DISABLE_DRIVER_MANAGEMENT |
        D3DCREATE_FPU_PRESERVE | D3DCREATE_NOWINDOWCHANGES,
        &pp, &tmp_dev);
    if (FAILED(hr) || !tmp_dev) {
        m2_logf("[debug-overlay] temp device CreateDevice failed: 0x%08lX (hwnd=%p%s)",
                (unsigned long)hr, (void*)hwnd, hwnd_is_ours ? " ours" : " game's");
        if (hwnd_is_ours) DestroyWindow(hwnd);
        return 0;
    }

    hook_device_vtable(tmp_dev);
    IDirect3DDevice9_Release(tmp_dev);
    if (hwnd_is_ours) DestroyWindow(hwnd);
    return 1;
}

/* Retry the temp-device patch in the background. The game often holds
 * the GPU in a state that rejects CreateDevice from any other caller
 * during the first ~seconds of its own init (D3DERR_DEVICELOST). Once
 * the game settles into its steady-state render loop, our temp device
 * usually succeeds. We poll every 2s for up to 60s. */
typedef struct RetryArgs { IDirect3D9* d3d; } RetryArgs;
static DWORD WINAPI device_vtable_retry_thread(LPVOID arg) {
    RetryArgs* args = (RetryArgs*)arg;
    int i;
    for (i = 0; i < 30; ++i) {
        Sleep(2000);
        if (g_endscene_hooked || g_device) {
            /* Some other path beat us to it (CreateDevice hook fired,
             * or lazy EndScene capture). Nothing left to do. */
            m2_logf("[debug-overlay] device vtable retry: another path already captured (attempt %d)", i);
            break;
        }
        HWND hwnd = find_game_window();
        if (try_patch_device_vtable_via_temp(args->d3d, hwnd)) {
            m2_logf("[debug-overlay] device vtable retry: succeeded on attempt %d (%s)",
                    i, hwnd ? "game's window" : "our temp window");
            break;
        }
    }
    if (!g_endscene_hooked) {
        m2_logf("[debug-overlay] device vtable retry: GAVE UP after 60s. "
                "If the overlay never draws, the wrapper is probably routing "
                "around all the d3d9 hook points we can reach.");
    }
    IDirect3D9_Release(args->d3d);
    free(args);
    return 0;
}

static HRESULT WINAPI hook_CreateDevice(IDirect3D9* self, UINT adapter, D3DDEVTYPE devtype,
                                        HWND focus, DWORD flags,
                                        D3DPRESENT_PARAMETERS* pp,
                                        IDirect3DDevice9** out_dev) {
    HRESULT hr = orig_CreateDevice(self, adapter, devtype, focus, flags, pp, out_dev);
    if (SUCCEEDED(hr) && out_dev && *out_dev) {
        /* Patch the device vtable. Idempotent — guarded by
         * g_endscene_hooked. We do NOT capture g_device here:
         *
         *   1. The very first CreateDevice that fires our hook is
         *      our OWN throwaway temp device (1x1, used solely for
         *      vtable patching, immediately released). Capturing it
         *      as g_device would orphan the font texture once the
         *      temp device is released.
         *
         *   2. The lazy EndScene capture grabs g_device on the first
         *      frame render, which is guaranteed to be the actual
         *      live device that's actually drawing. That's the one
         *      the font needs to be created against.
         */
        hook_device_vtable(*out_dev);
    }
    return hr;
}

static void hook_d3d9_vtable(IDirect3D9* d3d) {
    if (g_createdevice_hooked) return;
    void** vtbl = *(void***)d3d;
    /* CreateDevice = vtable slot 16 in IDirect3D9. The vtable is
     * shared across every IDirect3D9 instance in the process — so
     * patching it via this one temp instance also affects whatever
     * instance the game already has (or creates later). */
    void* target = vtbl[16];
    int ok = m2_hook_attach(target, (void*)hook_CreateDevice, (void**)&orig_CreateDevice);
    if (ok) {
        g_createdevice_hooked = TRUE;
        m2_logf("[debug-overlay] hooked IDirect3D9::CreateDevice at %p (vtable=%p slot 16)",
                target, (void*)vtbl);
    } else {
        m2_logf("[debug-overlay] m2_hook_attach FAILED for IDirect3D9::CreateDevice at %p", target);
    }
}

static void hook_d3d9ex_vtable(IDirect3D9Ex* d3d_ex) {
    /* IDirect3D9Ex inherits IDirect3D9. Vtable layout:
     *   slots 0..18 = IDirect3D9 (CreateDevice at 16)
     *   slot 19     = GetAdapterModeCountEx
     *   slot 20     = EnumAdapterModesEx
     *   slot 21     = GetAdapterDisplayModeEx
     *   slot 22     = CreateDeviceEx
     * Some games use the Ex path — patch that slot too so we capture
     * either way. The CreateDevice slot is the same address as in the
     * plain IDirect3D9 vtable, so we don't need to re-hook it here. */
    void** vtbl = *(void***)d3d_ex;
    void* target = vtbl[22];
    if (m2_hook_attach(target, (void*)hook_CreateDevice, (void**)&orig_CreateDevice)) {
        m2_logf("[debug-overlay] hooked IDirect3D9Ex::CreateDeviceEx at %p (vtable=%p slot 22)",
                target, (void*)vtbl);
    } else {
        m2_logf("[debug-overlay] m2_hook_attach FAILED for IDirect3D9Ex::CreateDeviceEx at %p", target);
    }
}

/* ======================================================================== *
 * Init
 * ======================================================================== */
static HMODULE g_hModule = NULL;

static void LoadConfig(void) {
    char ini_path[MAX_PATH];
    m2_module_path(g_hModule, "debug_overlay.ini", ini_path, sizeof(ini_path));
    cfg_set_defaults();
    m2_ini_parse(ini_path, OnIniKV, NULL);
}

static DWORD WINAPI WorkerThread(LPVOID arg) {
    (void)arg;

    LoadConfig();
    InitializeCriticalSection(&g_state_mtx);
    m2_hook_init();

    /* Patch IDirect3D9::CreateDevice in the shared vtable.
     *
     * We don't hook the exported `Direct3DCreate9` itself — by the
     * time our ASI loads, the game has likely already called it and
     * cached the IDirect3D9 instance, so a hook here would miss the
     * boat. Instead we call Direct3DCreate9 OURSELVES to obtain any
     * IDirect3D9 instance, then patch slot 16 (CreateDevice) of its
     * vtable. Because all IDirect3D9 instances in a process share
     * the same vtable, the patch retroactively applies to whatever
     * instance the game is already holding — its next CreateDevice
     * call lands in our hook. We immediately Release our temp
     * instance; the vtable patch persists. Same pattern as the
     * windowed-mode mod, which is known to work on this game.
     */
    HMODULE d3d9_mod = GetModuleHandleA("d3d9.dll");
    if (!d3d9_mod) d3d9_mod = LoadLibraryA("d3d9.dll");
    if (!d3d9_mod) {
        m2_logf("[debug-overlay] d3d9.dll not loadable; aborting");
        return 1;
    }
    typedef IDirect3D9* (WINAPI *Direct3DCreate9_t)(UINT);
    Direct3DCreate9_t pDirect3DCreate9 =
        (Direct3DCreate9_t)GetProcAddress(d3d9_mod, "Direct3DCreate9");
    if (!pDirect3DCreate9) {
        m2_logf("[debug-overlay] Direct3DCreate9 not found in d3d9.dll");
        return 1;
    }
    IDirect3D9* tmp_d3d = pDirect3DCreate9(D3D_SDK_VERSION);
    if (!tmp_d3d) {
        m2_logf("[debug-overlay] Direct3DCreate9 returned NULL");
        return 1;
    }
    hook_d3d9_vtable(tmp_d3d);

    /* Try the device-vtable patch synchronously first. If the GPU is
     * locked in D3DERR_DEVICELOST during the game's init, this will
     * fail — that's expected for ~the first few seconds. We then
     * hand the IDirect3D9* to a background retry thread that keeps
     * trying every 2s, both with our throwaway window and with the
     * game's window once we can find one. */
    int sync_ok = try_patch_device_vtable_via_temp(tmp_d3d, NULL);
    if (sync_ok) {
        IDirect3D9_Release(tmp_d3d);
    } else {
        /* Hand off ownership of tmp_d3d to the retry thread; it'll
         * Release when done. */
        IDirect3D9_AddRef(tmp_d3d);  /* extra ref so our Release here is safe */
        IDirect3D9_Release(tmp_d3d); /* drop the original */
        RetryArgs* ra = (RetryArgs*)malloc(sizeof(RetryArgs));
        if (ra) {
            ra->d3d = tmp_d3d;
            CreateThread(NULL, 0, device_vtable_retry_thread, ra, 0, NULL);
            m2_logf("[debug-overlay] temp device unavailable at init; "
                    "background retry thread started (every 2s up to 60s).");
        } else {
            IDirect3D9_Release(tmp_d3d);
        }
    }

    /* Also cover the Ex path. Some games (or wrappers like dgVoodoo
     * presenting itself as D3D9Ex) call Direct3DCreate9Ex to obtain
     * an IDirect3D9Ex instance, whose CreateDeviceEx lives at vtable
     * slot 22. dgVoodoo, dxwrapper, etc. that proxy d3d9.dll
     * typically forward this entry point too. Skip if we already
     * succeeded at the device-vtable patch above — no need. */
    if (!g_endscene_hooked) {
        typedef HRESULT (WINAPI *Direct3DCreate9Ex_t)(UINT, IDirect3D9Ex**);
        Direct3DCreate9Ex_t pDirect3DCreate9Ex =
            (Direct3DCreate9Ex_t)GetProcAddress(d3d9_mod, "Direct3DCreate9Ex");
        if (pDirect3DCreate9Ex) {
            IDirect3D9Ex* tmp_ex = NULL;
            HRESULT hr_ex = pDirect3DCreate9Ex(D3D_SDK_VERSION, &tmp_ex);
            if (SUCCEEDED(hr_ex) && tmp_ex) {
                hook_d3d9ex_vtable(tmp_ex);
                IDirect3D9Ex_Release(tmp_ex);
            } else {
                m2_logf("[debug-overlay] Direct3DCreate9Ex returned 0x%08lX — skipping Ex path",
                        (unsigned long)hr_ex);
            }
        } else {
            m2_logf("[debug-overlay] Direct3DCreate9Ex not exported by d3d9.dll — skipping Ex path");
        }
    }

    /* TCP listener runs in its own thread. */
    CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)h;
        DisableThreadLibraryCalls(h);
        m2_log_init(g_hModule);
        m2_logf("==========================================");
        m2_logf("[*] debug_overlay loading");
        m2_logf("==========================================");
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
