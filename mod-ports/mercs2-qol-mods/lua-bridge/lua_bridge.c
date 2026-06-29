/* lua_bridge.c — exposes Mercenaries 2's statically-linked Lua 5.1.2
 * runtime via a localhost TCP REPL, allowing arbitrary Lua chunks to
 * be executed against the live engine state.
 *
 * Ported from Merc2Reborn's Merc2Fix (https://github.com/loganw234/Mercenaries2)
 * to the mercs2-qol-mods SDK
 * (https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).
 *
 * Pairs with the companion `multiplayer-restore/` mod in this same
 * repo, but is independent: enable one or both via the modkit.
 *
 * What it does:
 *   * Detects which Mercenaries2.exe build is running (canonical retail
 *     vs the mercs2-securom-bypass-patched form) via an FNV-1a
 *     fingerprint, and selects the matching per-binary RVA table.
 *   * MinHook-detours: the shared no-op stub, luaB_type, and
 *     CreateTextWidget. These together capture the live lua_State on
 *     any Lua dispatch and serve as pump sources for queued chunks.
 *   * Hijacks `_G.print` / `_G.next` / `_G.tostring` at registration
 *     time by patching the engine's luaL_Reg table BEFORE the real
 *     luaL_register sees it. The hijacked functions drain the chunk
 *     queue whenever scripts call them — gives high-frequency pump
 *     sources without needing more MinHook detours.
 *   * Phase 3 executor: pushes a hand-crafted TString onto the engine's
 *     Lua stack, calls luaB_loadstring + luaB_pcall directly to
 *     compile + run a chunk, formats the return values, ships them
 *     back over the REPL socket.
 *
 * Listens on 127.0.0.1:27050 by default. Configurable via lua_bridge.ini.
 * Use tools/lua_repl.py or tools/lua_console.py from the parent project
 * for a client.
 *
 * Reverse-engineering notes — verified gotchas baked into this code:
 *   * TValue is 8 bytes here (Pandemic built with lua_Number = float),
 *     not the stock 16. Layout: Value at +0, int tt at +4.
 *   * lua_State packs CommonHeader tightly: L->top at +0x08, L->base
 *     at +0x0C (vs stock +0x0C and +0x10).
 *   * Lua's debug library is stripped; no lua_sethook. Pump from the
 *     captured dispatch sites instead.
 *   * luaB_pcall is non-stock: returns stack-shaped junk at slot 0
 *     instead of a clean bool status. Display-layer handles this.
 *   * The "noop stub" is shared across ~60 names (print, SendEvent_*,
 *     music stubs, _SummonEd, ...). Hooking it captures L from any of
 *     them. C++ engine code also routes through here with `this` in
 *     arg0 — LooksLikeLuaState filters those out.
 *
 * Full background, design rationale, and incident history:
 *   https://github.com/loganw234/Mercenaries2/blob/main/Merc2Fix/dllmain.cpp
 *   https://github.com/loganw234/Mercenaries2/blob/main/tools/lua_api_findings.md
 *   https://github.com/loganw234/Mercenaries2/blob/main/tools/engine_api.md
 */

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "m2.h"

/* Compatibility shim: the upstream Merc2Fix uses MSVC's safe-string
 * extensions (_snprintf_s with _TRUNCATE, strncpy_s, strcpy_s).
 * MinGW doesn't ship those; map them to POSIX snprintf / strncpy
 * with manual NUL-termination so the same source compiles under both
 * toolchains. Link with -lws2_32 (see Makefile). */
#ifdef _MSC_VER
  /* MSVC: native safe-string, SEH, and TLS extensions. */
  #define SEH_TRY            __try {
  #define SEH_CATCH_AV(rv)   } __except (EXCEPTION_EXECUTE_HANDLER) { return (rv); }
  #define MOD_THREAD         __declspec(thread)
#else
  /* MinGW: substitute POSIX where possible, skip SEH (no support on
   * GCC x86 — if SafeCallLuaCFunction's target AVs, the game crashes
   * instead of being caught here). _TRUNCATE is already defined by
   * MinGW's _mingw.h as ((size_t)-1); reuse it. */
  #define _snprintf_s(buf, sz, _trunc, ...) snprintf((buf), (sz), __VA_ARGS__)
  #define strncpy_s(dst, dst_sz, src, count) \
      (strncpy((dst), (src), (count)), (dst)[(dst_sz) - 1] = 0, 0)
  #define strcpy_s(dst, dst_sz, src) \
      (strncpy((dst), (src), (dst_sz) - 1), (dst)[(dst_sz) - 1] = 0, 0)
  #define SEH_TRY            do {
  #define SEH_CATCH_AV(rv)   } while (0)
  #define MOD_THREAD         __thread
#endif

/* ======================================================================== *
 * Status: PROOF OF CONCEPT — this port has NOT been built or test-run
 * against the mercs2-qol-mods framework. Drafted without the SDK build
 * environment set up locally. See README.md for what is and isn't
 * validated.
 *
 * The architecture is proven: the upstream Merc2Fix.asi runs cleanly
 * against a mercs2-securom-bypass-patched binary loaded by pmc_bb.dll,
 * with the bridge fully operational. So the surface area below is
 * known-correct; what's untested is the per-SDK-helper mapping
 * (m2_logf vs Log, m2_hook_attach vs MH_CreateHook, m2_ini_parse vs
 * a custom parser) — likely needs adjustments to match this SDK's
 * exact signatures.
 *
 * ONE KNOWN COMPLICATION: the luaL_register hijack requires a "naked"
 * detour to preserve a non-standard register-arg ABI (ECX=L, EAX=libname,
 * stack=table). On MSVC this is a one-paragraph __declspec(naked)
 * function. On the GCC/MinGW toolchain the SDK uses, x86 doesn't
 * support __attribute__((naked)), so this needs to live in a separate
 * .S file with global assembly. The DetourLuaLRegister section below
 * has the MSVC source as a comment block plus the GCC translation
 * sketch. Without this hook the bridge still works — we lose the
 * print/next/tostring hijack and the registration-table dump, but
 * the executor + the other detours keep functioning. Easier to ship
 * v1 without it and add later.
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * Per-binary RVA tables and fingerprint-based selection.
 *
 * The Mercenaries 2 binary ships in multiple flavors. The Lua bridge
 * needs per-binary addresses for the C functions it hooks. We compute
 * an FNV-1a fingerprint over a 4 KB region of .text at startup and
 * select the matching table.
 *
 * To add a new binary: run the static analyzers from the upstream repo
 * (tools/find_lua_print.py, tools/resolve_lua_api.py) against the new
 * exe to derive RVAs; compute the FNV-1a hash of 4 KB at RVA 0x11000
 * to get the fingerprint; add another LuaRvaSet and switch case below.
 * ------------------------------------------------------------------------ */

typedef struct LuaRvaSet {
    const char* label;
    DWORD noop_stub;         /* shared no-op stub: print, SendEvent_*, music, etc. */
    DWORD luaB_type;
    DWORD luaB_loadstring;
    DWORD luaB_pcall;
    DWORD CreateTextWidget;
    DWORD luaL_register;
} LuaRvaSet;

static const LuaRvaSet kRvas_v1_1 = {
    "v1.1 (archive.org English retail)",
    0x002AEF90, /* noop_stub        VA 0x006AEF90 */
    0x00460E90, /* luaB_type        VA 0x00860E90 */
    0x004611E0, /* luaB_loadstring  VA 0x008611E0 (real __cdecl) */
    0x00461810, /* luaB_pcall       VA 0x00861810 (real __cdecl) */
    0x001B7D30, /* CreateTextWidget VA 0x005B7D30 (__fastcall engine binding) */
    0x0045F720, /* luaL_register    VA 0x0085F720 (custom register ABI) */
};

static const LuaRvaSet kRvas_v1_1_bypass = {
    "v1.1 + mercs2-securom-bypass (cracked retail)",
    0x002D5640, /* noop_stub        (moved +0x266B0 vs v1.1) */
    0x00460C70, /* luaB_type        (shifted -0x220) */
    0x00460FC0, /* luaB_loadstring  (shifted -0x220) */
    0x004615F0, /* luaB_pcall       (shifted -0x220) */
    0x001B7D40, /* CreateTextWidget (shifted +0x10) */
    0x0045F500, /* luaL_register    (shifted -0x220) */
};

static const LuaRvaSet* g_rvas = &kRvas_v1_1;

/* FNV-1a 64-bit. Hashes are stable, deterministic, no crypto deps. */
static uint64_t Fnv1a64(const void* data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint8_t* b = (const uint8_t*)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= b[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

/* ------------------------------------------------------------------------ *
 * Memory-safety helpers
 * ------------------------------------------------------------------------ */
static BOOL SafeProbe(const void* p, size_t bytes) {
    const char* addr;
    const char* end;
    const DWORD readable =
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const DWORD unreadable = PAGE_NOACCESS | PAGE_GUARD;
    MEMORY_BASIC_INFORMATION mbi;

    if (!p || (uintptr_t)p < 0x10000) return FALSE;
    addr = (const char*)p;
    end  = addr + bytes;
    while (addr < end) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return FALSE;
        if (mbi.State != MEM_COMMIT) return FALSE;
        if (mbi.Protect & unreadable) return FALSE;
        if (!(mbi.Protect & readable)) return FALSE;
        addr = (const char*)mbi.BaseAddress + mbi.RegionSize;
    }
    return TRUE;
}

/* ------------------------------------------------------------------------ *
 * Layout constants — verified against the engine
 * ------------------------------------------------------------------------ */
#define LUA_OFF_TOP       0x08
#define LUA_OFF_BASE      0x0C
#define TVALUE_SIZE       0x08
#define TVALUE_TT_OFFSET  0x04

#define LUA_TNIL          0
#define LUA_TBOOLEAN      1
#define LUA_TNUMBER       3
#define LUA_TSTRING       4
#define LUA_TTABLE        5
#define LUA_TFUNCTION     6
#define LUA_TTHREAD       8

/* Identifies a lua_State by tt-byte at +4 (LUA_TTHREAD = 8) plus
 * structural checks. Filters out C++ this-pointers that the shared
 * noop stub gets called with from engine code. */
static BOOL LooksLikeLuaState(void* L) {
    uint8_t L_tt;
    void *top, *base, *l_G;
    uintptr_t t, b;

    if (!SafeProbe(L, 0x18)) return FALSE;
    L_tt = *(uint8_t*)((char*)L + 4);
    if (L_tt != LUA_TTHREAD) return FALSE;

    top  = *(void**)((char*)L + LUA_OFF_TOP);
    base = *(void**)((char*)L + LUA_OFF_BASE);
    l_G  = *(void**)((char*)L + 0x10);

    if (!SafeProbe(base, 16) || !SafeProbe(top, 4) || !SafeProbe(l_G, 4)) return FALSE;
    t = (uintptr_t)top;
    b = (uintptr_t)base;
    if ((t | b) & 0x3) return FALSE;
    if (t < b) return FALSE;
    if (t - b > 0x10000) return FALSE;
    return TRUE;
}

/* ------------------------------------------------------------------------ *
 * Fingerprint + RVA selection
 * ------------------------------------------------------------------------ */
static const LuaRvaSet* SelectRvas(HMODULE mod) {
    BYTE* base = (BYTE*)mod;
    uint64_t fp;

    if (!SafeProbe(base + 0x11000, 0x1000)) {
        m2_logf("[!] lua_bridge: SelectRvas: 4KB at RVA 0x11000 unreadable; default v1.1");
        return &kRvas_v1_1;
    }
    fp = Fnv1a64(base + 0x11000, 0x1000);
    m2_logf("[*] lua_bridge: binary fingerprint = 0x%016llX", fp);

    switch (fp) {
        case 0xB79E4DD22A4BFCB3ULL:
            m2_logf("[*] lua_bridge: matched %s", kRvas_v1_1.label);
            return &kRvas_v1_1;
        case 0x1942B494FF9F4DB3ULL:
            m2_logf("[*] lua_bridge: matched %s", kRvas_v1_1_bypass.label);
            return &kRvas_v1_1_bypass;
        default:
            m2_logf("[!] lua_bridge: unknown binary (fp=0x%016llX); defaulting to v1.1 + relying on prologue validator", fp);
            return &kRvas_v1_1;
    }
}

/* ------------------------------------------------------------------------ *
 * Hook-target validator — refuses to install a hook if the bytes at the
 * target don't look right for the kind of code we expect. Prevents CTDs
 * when our RVA table doesn't match this binary.
 * ------------------------------------------------------------------------ */
typedef enum HookKind { HOOK_NOOP_STUB, HOOK_NORMAL_FUNC } HookKind;

static BOOL ValidateHookTarget(const void* p, HookKind kind) {
    const uint8_t* b;
    if (!SafeProbe(p, 8)) return FALSE;
    b = (const uint8_t*)p;
    if (kind == HOOK_NOOP_STUB) {
        return b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0xC3;  /* xor eax,eax; ret */
    }
    /* HOOK_NORMAL_FUNC: any common x86 prologue */
    if (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) return TRUE;
    if (b[0] == 0x53) return TRUE;
    if (b[0] == 0x56) return TRUE;
    if (b[0] == 0x57) return TRUE;
    if (b[0] == 0x83 && b[1] == 0xEC) return TRUE;
    if (b[0] == 0x81 && b[1] == 0xEC) return TRUE;
    if (b[0] == 0x6A) return TRUE;
    if (b[0] == 0x68) return TRUE;
    if (b[0] == 0x8B && b[1] == 0xFF) return TRUE;
    if (b[0] == 0x8B && (b[1] & 0xC0) == 0xC0) return TRUE;
    return FALSE;
}

/* ------------------------------------------------------------------------ *
 * Calling-convention typedefs
 * ------------------------------------------------------------------------ */
typedef int  (__cdecl*   lua_CFunction_t)(void* L);
typedef int  (__fastcall* pandemic_CFunction_t)(void* L, void* edx);

/* ------------------------------------------------------------------------ *
 * Crafted TString for pushing arbitrary source onto the Lua stack.
 *
 * Layout matches stock Lua 5.1.2 TString (verified — Pandemic packed
 * TValue but NOT TString). FIXEDBIT in `marked` tells the GC to leave
 * us alone.
 * ------------------------------------------------------------------------ */
#pragma pack(push, 4)
typedef struct FixedTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[1048576];  /* 1 MB — sized to absorb any realistic chunk */
} FixedTString;
#pragma pack(pop)
static FixedTString g_chunkSource;

static void InitChunkSource(void) {
    memset(&g_chunkSource, 0, sizeof(g_chunkSource));
    g_chunkSource.tt     = (uint8_t)LUA_TSTRING;
    g_chunkSource.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_chunkSource.hash   = 0xDEADBEEF;
}

/* ------------------------------------------------------------------------ *
 * Globals
 * ------------------------------------------------------------------------ */
static HMODULE g_hModule = NULL;

/* Resolved RVAs (set in WorkerThread): */
static lua_CFunction_t      fpOriginal_NoopStub          = NULL;
static lua_CFunction_t      fpOriginal_luaB_type         = NULL;
static pandemic_CFunction_t fpOriginal_CreateTextWidget  = NULL;
static lua_CFunction_t      p_luaB_loadstring            = NULL;
static lua_CFunction_t      p_luaB_pcall                 = NULL;

/* Captured engine lua_State, set by the detours: */
static void* volatile g_LuaState = NULL;

/* Output buffer — accumulates execution results before the next TCP flush. */
static CRITICAL_SECTION g_outMtx;
static char*  g_outBuf       = NULL;
static size_t g_outBuf_len   = 0;
static size_t g_outBuf_cap   = 0;

/* Input queue — pending chunks waiting for a pump source to fire. */
typedef struct ChunkNode {
    char*  code;
    size_t len;
    struct ChunkNode* next;
} ChunkNode;
static CRITICAL_SECTION g_inMtx;
static ChunkNode* g_inQueue_head = NULL;
static ChunkNode* g_inQueue_tail = NULL;
static volatile LONG g_PendingScripts = 0;

/* Per-thread re-entry guard — prevents the executor from recursing
 * into itself if a capture detour fires mid-LuaDoString. */
static MOD_THREAD BOOL t_inBridgeExec = FALSE;

/* Configuration (loaded from lua_bridge.ini). */
static char  g_repl_host[64] = "127.0.0.1";
static int   g_repl_port     = 27050;
static int   g_loader_enabled  = 1;
static int   g_loader_onboot   = 1;
static int   g_loader_onload   = 1;
static int   g_loader_delay_ms = 50;

/* ------------------------------------------------------------------------ *
 * Output-buffer helpers
 * ------------------------------------------------------------------------ */
static void OutAppend(const char* s, size_t s_len) {
    EnterCriticalSection(&g_outMtx);
    {
        size_t needed = g_outBuf_len + s_len + 2;
        if (needed > g_outBuf_cap) {
            size_t newcap = g_outBuf_cap ? g_outBuf_cap * 2 : 4096;
            char*  newbuf;
            while (newcap < needed) newcap *= 2;
            newbuf = (char*)realloc(g_outBuf, newcap);
            if (newbuf) { g_outBuf = newbuf; g_outBuf_cap = newcap; }
            else { LeaveCriticalSection(&g_outMtx); return; }
        }
        memcpy(g_outBuf + g_outBuf_len, s, s_len);
        g_outBuf_len += s_len;
        g_outBuf[g_outBuf_len++] = '\n';
        g_outBuf[g_outBuf_len]   = '\0';
    }
    LeaveCriticalSection(&g_outMtx);
}

/* ------------------------------------------------------------------------ *
 * Input-queue helpers
 * ------------------------------------------------------------------------ */
static void InQueuePush(const char* code, size_t len) {
    ChunkNode* node = (ChunkNode*)malloc(sizeof(ChunkNode));
    if (!node) return;
    node->code = (char*)malloc(len + 1);
    if (!node->code) { free(node); return; }
    memcpy(node->code, code, len);
    node->code[len] = '\0';
    node->len  = len;
    node->next = NULL;

    EnterCriticalSection(&g_inMtx);
    if (g_inQueue_tail) g_inQueue_tail->next = node;
    else                g_inQueue_head       = node;
    g_inQueue_tail = node;
    LeaveCriticalSection(&g_inMtx);

    InterlockedIncrement(&g_PendingScripts);
}

static ChunkNode* InQueuePop(void) {
    ChunkNode* node;
    EnterCriticalSection(&g_inMtx);
    node = g_inQueue_head;
    if (node) {
        g_inQueue_head = node->next;
        if (!g_inQueue_head) g_inQueue_tail = NULL;
        InterlockedDecrement(&g_PendingScripts);
    }
    LeaveCriticalSection(&g_inMtx);
    return node;
}

static void ChunkNodeFree(ChunkNode* n) {
    if (!n) return;
    free(n->code);
    free(n);
}

/* ------------------------------------------------------------------------ *
 * Result-formatting + executor
 * ------------------------------------------------------------------------ */
static int SafeCallLuaCFunction(lua_CFunction_t fn, void* L) {
#ifdef _MSC_VER
    __try {
        return fn(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
#else
    /* MinGW x86 doesn't support MSVC SEH; call unguarded. If the
     * target AVs, the game crashes. Documented trade-off. */
    return fn(L);
#endif
}

/* Append "<value>" (or "nil" / "true" / a number) representing one
 * TValue slot to `out`. `out_cap` is the buffer's total capacity,
 * `*out_len` is updated. Caller ensures room. */
static void FormatTValue(const char* slot, char* out, size_t out_cap, size_t* out_len) {
    int tt = *(const int*)(slot + TVALUE_TT_OFFSET);
    char tmp[128];
    int n = 0;
    switch (tt) {
        case LUA_TNIL:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "nil");
            break;
        case LUA_TBOOLEAN:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                            *(const int*)slot ? "true" : "false");
            break;
        case LUA_TNUMBER: {
            float f = *(const float*)slot;  /* lua_Number = float in this build */
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "%g", (double)f);
            break;
        }
        case LUA_TSTRING: {
            void* gc = *(void* const*)slot;
            uint32_t slen;
            const char* sdata;
            if (!SafeProbe(gc, 0x14)) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<string: gc unreadable>");
                break;
            }
            slen = *(uint32_t*)((char*)gc + 0x0C);
            if (slen > 16u * 1024u * 1024u) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                                "<string: implausible len=%u>", slen);
                break;
            }
            sdata = (const char*)gc + 0x10;
            if (!SafeProbe(sdata, slen + 1)) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<string: data unreadable>");
                break;
            }
            /* Bypass the tmp buffer for string content — copy straight to out. */
            if (*out_len + slen + 3 < out_cap) {
                out[(*out_len)++] = '"';
                memcpy(out + *out_len, sdata, slen);
                *out_len += slen;
                out[(*out_len)++] = '"';
                out[*out_len] = '\0';
            }
            return;
        }
        case LUA_TTABLE:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<table>");
            break;
        case LUA_TFUNCTION:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<function>");
            break;
        default: {
            void* v = *(void* const*)slot;
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                            "<tt=%d val=%p>", tt, v);
            break;
        }
    }
    if (n > 0 && (size_t)n + *out_len + 1 < out_cap) {
        memcpy(out + *out_len, tmp, n);
        *out_len += n;
        out[*out_len] = '\0';
    }
}

/* Phase 3 executor. Builds a NEW Lua frame on top of the engine's
 * active frame (does NOT clobber base) and runs the chunk via
 * luaB_loadstring + luaB_pcall. Result formatted into `out`.
 *
 * Must be called from inside a real lua_CFunction detour with a
 * verified-valid L (i.e. after LooksLikeLuaState). */
static void LuaDoString(void* L, const char* code, size_t code_len,
                        char* out, size_t out_cap) {
    char *Lc, *new_base, *top_slot;
    void **top_ptr, **base_ptr;
    void *saved_top, *saved_base;
    int load_n, pcall_n, compiled_tt;
    size_t out_len = 0;
    ptrdiff_t after_exec;
    int result_slots, i;
    int succeeded = 0;
    int have_status = 0;
    int first_result;

    if (!L) { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] no L"); return; }
    if (!LooksLikeLuaState(L)) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] L failed validation");
        return;
    }
    if (!p_luaB_loadstring || !p_luaB_pcall) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] executor fn pointers not resolved");
        return;
    }
    if (code_len == 0)                          { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] empty chunk"); return; }
    if (code_len >= sizeof(g_chunkSource.data)) { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] chunk too large"); return; }

    Lc       = (char*)L;
    top_ptr  = (void**)(Lc + LUA_OFF_TOP);
    base_ptr = (void**)(Lc + LUA_OFF_BASE);
    saved_top  = *top_ptr;
    saved_base = *base_ptr;
    new_base   = (char*)saved_top;

    if (!SafeProbe(new_base, 3 * TVALUE_SIZE)) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] L->top + scratch unwritable");
        return;
    }

    memcpy(g_chunkSource.data, code, code_len);
    g_chunkSource.data[code_len] = '\0';
    g_chunkSource.len = (uint32_t)code_len;

    *(void**)new_base                            = &g_chunkSource;
    *(int*)(new_base + TVALUE_TT_OFFSET)         = LUA_TSTRING;
    *base_ptr = new_base;
    *top_ptr  = new_base + TVALUE_SIZE;

    load_n = SafeCallLuaCFunction(p_luaB_loadstring, L);
    if (load_n < 0) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] luaB_loadstring crashed");
        return;
    }
    if (load_n == 2) {
        char* err_slot = new_base + 2 * TVALUE_SIZE;
        out_len = 0;
        out_len += _snprintf_s(out, out_cap, _TRUNCATE, "[compile] ");
        FormatTValue(err_slot, out, out_cap, &out_len);
        *top_ptr = saved_top; *base_ptr = saved_base;
        return;
    }
    if (load_n != 1) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] loadstring returned %d", load_n);
        return;
    }

    /* Success: stack is [chunk, fn] at new_base. Slide fn down to new_base[0]
     * so pcall reads it at index 1. */
    top_slot = (char*)*top_ptr - TVALUE_SIZE;
    compiled_tt = *(int*)(top_slot + TVALUE_TT_OFFSET);
    if (compiled_tt != LUA_TFUNCTION) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE,
                    "[bridge] loadstring result not a function (tt=%d)", compiled_tt);
        return;
    }
    if (top_slot != new_base) memcpy(new_base, top_slot, TVALUE_SIZE);
    *top_ptr = new_base + TVALUE_SIZE;

    pcall_n = SafeCallLuaCFunction(p_luaB_pcall, L);
    if (pcall_n < 0) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] luaB_pcall crashed");
        return;
    }

    after_exec = (char*)*top_ptr - new_base;
    result_slots = (int)(after_exec / TVALUE_SIZE);
    if (result_slots > 16) result_slots = 16;

    /* Detect status: accept either bool (stock) or number (Pandemic's variant). */
    if (result_slots >= 1) {
        int tt0 = *(int*)(new_base + TVALUE_TT_OFFSET);
        if (tt0 == LUA_TBOOLEAN) {
            have_status = 1;
            succeeded   = (*(int*)new_base != 0);
        } else if (tt0 == LUA_TNUMBER) {
            have_status = 1;
            succeeded   = (*(const float*)new_base != 0.0f);
        }
    }
    first_result = have_status ? 1 : 0;

    out_len = 0;
    out_len += _snprintf_s(out, out_cap, _TRUNCATE, "%s", succeeded ? "[ok]" : "[runtime]");
    for (i = first_result; i < result_slots; ++i) {
        char* rslot = new_base + i * TVALUE_SIZE;
        if (out_len + 2 < out_cap) {
            out[out_len++] = succeeded ? '\t' : ' ';
            out[out_len]   = '\0';
        }
        FormatTValue(rslot, out, out_cap, &out_len);
    }

    *top_ptr = saved_top;
    *base_ptr = saved_base;
}

/* ------------------------------------------------------------------------ *
 * Pump — drain the input queue against a verified-valid L
 * ------------------------------------------------------------------------ */
static void PumpQueue(void* L_for_exec) {
    char result_buf[16384];

    if (g_PendingScripts <= 0) return;
    if (t_inBridgeExec) return;

    for (;;) {
        ChunkNode* node = InQueuePop();
        if (!node) return;

        t_inBridgeExec = TRUE;
        if (L_for_exec && LooksLikeLuaState(L_for_exec)) {
            LuaDoString(L_for_exec, node->code, node->len, result_buf, sizeof(result_buf));
        } else {
            _snprintf_s(result_buf, sizeof(result_buf), _TRUNCATE,
                        "[bridge] pump fired without a valid L — chunk dropped");
        }
        t_inBridgeExec = FALSE;

        m2_logf("[+] lua_bridge: Script executed. Result: %s", result_buf);
        OutAppend(result_buf, strlen(result_buf));
        OutAppend("<<<END>>>", 9);
        ChunkNodeFree(node);
    }
}

static volatile LONG g_OnLoadTriggered = 0;
static volatile LONG g_OnLoadExecuted = 0;

static void RegisterTcpLib(void* L);
static void ExecuteLuaFolder(void* L, const char* folder_name);
static void InitializeKeyScripts(void);

static __inline void GatedPump(void* L_arg0) {
    if (g_loader_enabled && g_loader_onload && g_OnLoadTriggered && !g_OnLoadExecuted) {
        if (LooksLikeLuaState(L_arg0)) {
            g_OnLoadExecuted = 1;
            ExecuteLuaFolder(L_arg0, "OnLoad");
        }
    }

    if (g_PendingScripts <= 0) return;
    if (t_inBridgeExec)        return;
    if (!LooksLikeLuaState(L_arg0)) return;
    PumpQueue(L_arg0);
}

static void CaptureL(void* L, const char* via) {
    /* Fast path: same L as last capture — return without logging or
     * touching the seen-set. This is the common case (every detour
     * fire on the same VM). */
    if (!L || L == g_LuaState) return;
    if (!LooksLikeLuaState(L)) return;
    g_LuaState = L;

    /* Dedupe log spam: the engine flips between multiple Lua VMs
     * (frontend + gameplay + occasional coroutines) on the same
     * main thread, so g_LuaState legitimately changes many times
     * per second. Log only the first time we observe each distinct
     * L. 8 slots is enough for any realistic game state. */
    static void* seen[8] = {0};
    int i;
    for (i = 0; i < 8; ++i) {
        if (seen[i] == L) return;            /* already logged */
        if (seen[i] == NULL) {
            seen[i] = L;
            m2_logf("[+] lua_bridge: Lua VM captured via %s: L=%p", via, L);
            RegisterTcpLib(L);

            if (g_loader_enabled) {
                static int key_loader_initialized = 0;
                if (!key_loader_initialized) {
                    key_loader_initialized = 1;
                    InitializeKeyScripts();
                }
            }

            if (g_loader_enabled && g_loader_onboot) {
                static int onboot_executed = 0;
                if (!onboot_executed) {
                    onboot_executed = 1;
                    ExecuteLuaFolder(L, "OnBoot");
                }
            }
            return;
        }
    }
    /* seen[] full — silently update without logging. */
}

/* ------------------------------------------------------------------------ *
 * Detours
 * ------------------------------------------------------------------------ */
static int __cdecl DetourNoopStub(void* L) {
    if (g_loader_enabled && g_loader_onload && !g_OnLoadTriggered) {
        char msg[512];
        if (m2_lua_join_strings(L, msg, sizeof(msg)) >= 1) {
            if (strstr(msg, "GlobalExit - Complete")) {
                m2_logf("[*] lua_bridge: OnLoad milestone reached (GlobalExit - Complete). Queuing OnLoad scripts.");
                InterlockedExchange(&g_OnLoadTriggered, 1);
            }
        }
    }
    GatedPump(L);
    return fpOriginal_NoopStub ? fpOriginal_NoopStub(L) : 0;
}

static int __cdecl DetourLuaType(void* L) {
    CaptureL(L, "type");
    GatedPump(L);
    return fpOriginal_luaB_type ? fpOriginal_luaB_type(L) : 0;
}

static int __fastcall DetourCreateTextWidget(void* L, void* edx) {
    GatedPump(L);
    return fpOriginal_CreateTextWidget ? fpOriginal_CreateTextWidget(L, edx) : 0;
}

/* ------------------------------------------------------------------------ *
 * Print/Next/ToString hijack — see commented-out luaL_register section
 * below. Without that hook these hijacks never get installed, so the
 * functions below are unused in this draft. Left in place so they're
 * ready when the naked-detour question is resolved.
 * ------------------------------------------------------------------------ */
static lua_CFunction_t fpOriginalPrint    = NULL;
static lua_CFunction_t fpOriginalNext     = NULL;
static lua_CFunction_t fpOriginalToString = NULL;

static int __cdecl HijackedPrint(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalPrint ? fpOriginalPrint(L) : 0;
}
static int __cdecl HijackedNext(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalNext ? fpOriginalNext(L) : 0;
}
static int __cdecl HijackedToString(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalToString ? fpOriginalToString(L) : 0;
}

/* ======================================================================== *
 * luaL_register hijack — DEFERRED
 *
 * Mercenaries 2's luaL_register uses a custom register-arg ABI:
 *   ECX = lua_State* L
 *   EAX = const char* libname
 *   [esp+4] = const luaL_Reg* table
 * Caller cleans the 4-byte stack arg.
 *
 * On MSVC, hooking this needs a __declspec(naked) detour that
 * preserves the registers and forwards. The MSVC source is below as
 * a comment, since GCC/MinGW on x86 doesn't support
 * __attribute__((naked)) and this SDK's Makefiles use MinGW.
 *
 * Three reasonable resolutions:
 *
 *   1) Translate to a global assembly file (lua_bridge_asm.S). The
 *      contents are essentially the same instructions GCC's inline
 *      asm would emit. Add to the Makefile as an additional source.
 *
 *   2) Compile with MSVC instead. The SDK's helpers should work fine
 *      either way; only the build glue would need to change.
 *
 *   3) Skip this hook. The bridge degrades gracefully without it: the
 *      noop_stub / luaB_type / CreateTextWidget detours still capture
 *      L, the executor still runs chunks. We lose the print/next/
 *      tostring hijack (a high-frequency pump source) and the
 *      registration-table dump (a discovery convenience), but core
 *      functionality is intact. This is what the draft below opts for.
 *
 * MSVC reference implementation:
 *
 *   __declspec(naked) static void DetourLuaLRegister(void) {
 *       __asm {
 *           push edx
 *           push eax
 *           push ecx
 *           push dword ptr [esp + 0x10]   ; table
 *           push dword ptr [esp + 0x08]   ; libname
 *           push dword ptr [esp + 0x08]   ; L
 *           call OnLuaRegisterCalled
 *           add esp, 12
 *           pop ecx
 *           pop eax
 *           pop edx
 *           jmp dword ptr [fpOriginal_luaL_register]
 *       }
 *   }
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * Expose Tcp.Send to Lua
 * ------------------------------------------------------------------------ */
typedef struct luaL_Reg {
    const char *name;
    int (__cdecl *func)(void* L);
} luaL_Reg;

static int LuaTcpSend(void* L) {
    char host[128];
    char msg[2048];
    int port;

    if (m2_lua_nargs(L) < 3) return 0;
    if (m2_lua_arg_string(L, 0, host, sizeof(host)) == 0) return 0;
    
    // Port is standard Lua float, extract from stack base:
    char* base = *(char**)((char*)L + 0x0C); // L->base
    if (!base) return 0;
    float port_val = *(float*)(base + 8);    // First stack slot (8 bytes per TValue)
    port = (int)port_val;

    if (m2_lua_arg_string(L, 2, msg, sizeof(msg)) == 0) return 0;

    unsigned long ip = inet_addr(host);
    if (ip == INADDR_NONE) return 0;

    /*
     * SECURITY RESTRICTION:
     * Only allow connections to loopback/localhost (127.0.0.0/8).
     * This decision was made for player security, preventing malicious or
     * untrusted Lua scripts from performing port scans on the player's
     * local network or exfiltrating data to external servers on the internet.
     *
     * NOTE: If this restriction is removed, it could potentially allow
     * secondary out-of-band communication between coop players to sync
     * mod status over the network without needing to integrate directly
     * with the game's built-in P2P networking core.
     */
    unsigned long ip_host = ntohl(ip);
    if ((ip_host & 0xFF000000) != 0x7F000000) {
        return 0; // Block non-localhost destinations
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = ip;

        DWORD timeout = 500;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            send(s, msg, (int)strlen(msg), 0);
        }
        closesocket(s);
    }
    return 0;
}

static const luaL_Reg tcp_lib[] = {
    {"Send", LuaTcpSend},
    {NULL, NULL}
};

/* ------------------------------------------------------------------------ *
 * Native Lua Script Loader
 * ------------------------------------------------------------------------ */
#define MAX_SCRIPTS 128

typedef struct {
    char path[MAX_PATH];
    char rel_path[MAX_PATH];
    int load_order;
} LuaScriptFile;

static int CompareAlphabetical(const void* a, const void* b) {
    return _stricmp(((const LuaScriptFile*)a)->rel_path, ((const LuaScriptFile*)b)->rel_path);
}

static int CompareLoadOrder(const void* a, const void* b) {
    int diff = ((const LuaScriptFile*)a)->load_order - ((const LuaScriptFile*)b)->load_order;
    if (diff != 0) return diff;
    return _stricmp(((const LuaScriptFile*)a)->rel_path, ((const LuaScriptFile*)b)->rel_path);
}

static void EnsureLoaderDirectories(void) {
    char exe_dir[MAX_PATH];
    char path[MAX_PATH];
    char* slash;

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(path, sizeof(path), "%sscripts", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnBoot", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnLoad", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnKey", exe_dir);
    CreateDirectoryA(path, NULL);
}

static void CollectScriptsRecursive(const char* base_path, const char* sub_path, LuaScriptFile* list, int* count, int max_count) {
    char search_path[MAX_PATH];
    WIN32_FIND_DATAA ffd;
    HANDLE hFind;

    snprintf(search_path, sizeof(search_path), "%s%s*", base_path, sub_path);
    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) {
            continue;
        }

        char relative_path[MAX_PATH];
        if (sub_path[0] == '\0') {
            snprintf(relative_path, sizeof(relative_path), "%s", ffd.cFileName);
        } else {
            snprintf(relative_path, sizeof(relative_path), "%s%s", sub_path, ffd.cFileName);
        }

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            char next_sub[MAX_PATH];
            snprintf(next_sub, sizeof(next_sub), "%s\\", relative_path);
            CollectScriptsRecursive(base_path, next_sub, list, count, max_count);
        } else {
            size_t len = strlen(ffd.cFileName);
            if (len > 4 && _stricmp(ffd.cFileName + len - 4, ".lua") == 0) {
                if (*count < max_count) {
                    snprintf(list[*count].path, sizeof(list[*count].path), "%s%s", base_path, relative_path);
                    
                    strncpy(list[*count].rel_path, relative_path, sizeof(list[*count].rel_path) - 1);
                    list[*count].rel_path[sizeof(list[*count].rel_path) - 1] = '\0';
                    
                    list[*count].load_order = -1;
                    (*count)++;
                }
            }
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
}

static void EnsureLoaderIniHeader(const char* path) {
    FILE* f = fopen(path, "r");
    if (f) {
        fclose(f);
        return; // File already exists
    }
    
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "; lua_loader.ini — Lua Script Loader Configuration\n");
        fprintf(f, "; Define execution order for [OnBoot] and [OnLoad] (lowest numbers load first)\n");
        fprintf(f, "; Define hotkey triggers under [OnKey] (e.g. script.lua = F1 or script.lua = insert)\n");
        fprintf(f, ";\n");
        fprintf(f, "; Virtual Key codes reference: https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes\n");
        fprintf(f, "; Common keys: insert, delete, home, end, pageup, pagedown, space, enter, escape, F1..F12, A..Z, 0..9\n\n");
        fclose(f);
    }
}

static void ExtractDefaultKey(const char* file_path, char* out_key, size_t out_max) {
    strncpy(out_key, "unassigned", out_max);
    FILE* f = fopen(file_path, "r");
    if (!f) return;
    
    char line[256];
    int i;
    for (i = 0; i < 10; ++i) {
        if (!fgets(line, sizeof(line), f)) break;
        char* p = strstr(line, "KEYVAL");
        if (p) {
            char* eq = strchr(p, '=');
            if (eq) {
                char* q1 = strchr(eq, '"');
                if (!q1) q1 = strchr(eq, '\'');
                if (q1) {
                    q1++;
                    char* q2 = strchr(q1, '"');
                    if (!q2) q2 = strchr(q1, '\'');
                    if (q2 && (size_t)(q2 - q1) < out_max) {
                        size_t len = q2 - q1;
                        memcpy(out_key, q1, len);
                        out_key[len] = '\0';
                        break;
                    }
                }
            }
        }
    }
    fclose(f);
}

static int ResolveKeyName(const char* name) {
    if (!name) return 0;
    if (_stricmp(name, "unassigned") == 0) return 0;

    if (name[0] != '\0' && name[1] == '\0') {
        char c = name[0];
        if (c >= 'a' && c <= 'z') return 0x41 + (c - 'a');
        if (c >= 'A' && c <= 'Z') return 0x41 + (c - 'A');
        if (c >= '0' && c <= '9') return 0x30 + (c - '0');
    }

    if ((name[0] == 'f' || name[0] == 'F') && name[1] >= '1' && name[1] <= '9') {
        int num = atoi(name + 1);
        if (num >= 1 && num <= 12) return 0x70 + (num - 1);
    }

    if (_stricmp(name, "insert") == 0) return VK_INSERT;
    if (_stricmp(name, "delete") == 0) return VK_DELETE;
    if (_stricmp(name, "home") == 0) return VK_HOME;
    if (_stricmp(name, "end") == 0) return VK_END;
    if (_stricmp(name, "pageup") == 0) return VK_PRIOR;
    if (_stricmp(name, "pagedown") == 0) return VK_NEXT;
    if (_stricmp(name, "space") == 0) return VK_SPACE;
    if (_stricmp(name, "enter") == 0 || _stricmp(name, "return") == 0) return VK_RETURN;
    if (_stricmp(name, "escape") == 0 || _stricmp(name, "esc") == 0) return VK_ESCAPE;
    if (_stricmp(name, "backspace") == 0) return VK_BACK;
    if (_stricmp(name, "tab") == 0) return VK_TAB;
    if (_stricmp(name, "shift") == 0) return VK_SHIFT;
    if (_stricmp(name, "ctrl") == 0 || _stricmp(name, "control") == 0) return VK_CONTROL;
    if (_stricmp(name, "alt") == 0) return VK_MENU;
    if (_stricmp(name, "left") == 0) return VK_LEFT;
    if (_stricmp(name, "up") == 0) return VK_UP;
    if (_stricmp(name, "right") == 0) return VK_RIGHT;
    if (_stricmp(name, "down") == 0) return VK_DOWN;

    return 0;
}

static void ExecuteLuaFolder(void* L, const char* folder_name) {
    char exe_dir[MAX_PATH];
    char folder_path[MAX_PATH];
    char loader_ini_path[MAX_PATH];
    char* slash;
    LuaScriptFile scripts[MAX_SCRIPTS];
    int script_count = 0;
    int i;

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(folder_path, sizeof(folder_path), "%sscripts\\%s\\", exe_dir, folder_name);
    m2_module_path(g_hModule, "lua_loader.ini", loader_ini_path, sizeof(loader_ini_path));
    EnsureLoaderIniHeader(loader_ini_path);

    CollectScriptsRecursive(folder_path, "", scripts, &script_count, MAX_SCRIPTS);

    if (script_count == 0) {
        m2_logf("[*] lua_bridge: No scripts found in scripts/%s/", folder_name);
        return;
    }

    qsort(scripts, script_count, sizeof(LuaScriptFile), CompareAlphabetical);

    for (i = 0; i < script_count; ++i) {
        int order = GetPrivateProfileIntA(folder_name, scripts[i].rel_path, -1, loader_ini_path);
        if (order == -1) {
            order = (i + 1) * 10;
            char order_str[32];
            snprintf(order_str, sizeof(order_str), "%d", order);
            WritePrivateProfileStringA(folder_name, scripts[i].rel_path, order_str, loader_ini_path);
        }
        scripts[i].load_order = order;
    }

    qsort(scripts, script_count, sizeof(LuaScriptFile), CompareLoadOrder);

    for (i = 0; i < script_count; ++i) {
        FILE* f = fopen(scripts[i].path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);

            if (sz > 0 && sz < 1024 * 1024) { // Max 1MB
                char* buf = (char*)malloc(sz + 1);
                if (buf) {
                    size_t read_bytes = fread(buf, 1, sz, f);
                    buf[read_bytes] = '\0';

                    m2_logf("[*] lua_bridge: Loading script (%s): %s (%ld bytes)", folder_name, scripts[i].rel_path, sz);
                    
                    char result_buf[4096];
                    t_inBridgeExec = TRUE;
                    LuaDoString(L, buf, read_bytes, result_buf, sizeof(result_buf));
                    t_inBridgeExec = FALSE;
                    
                    m2_logf("[+] lua_bridge: Script result: %s", result_buf);

                    free(buf);
                }
            }
            fclose(f);
        } else {
            m2_logf("[!] lua_bridge: Failed to open script: %s", scripts[i].path);
        }

        if (g_loader_delay_ms > 0 && i < script_count - 1) {
            Sleep(g_loader_delay_ms);
        }
    }
}

typedef struct {
    char path[MAX_PATH];
    char rel_path[MAX_PATH];
    char key_name[64];
    int vk_code;
    int was_down;
} LuaKeyScript;

static LuaKeyScript g_KeyScripts[MAX_SCRIPTS];
static int g_KeyScriptCount = 0;

static DWORD WINAPI LoaderKeyThread(LPVOID param) {
    (void)param;
    for (;;) {
        int i;
        for (i = 0; i < g_KeyScriptCount; ++i) {
            int vk = g_KeyScripts[i].vk_code;
            if (vk > 0 && vk < 256) {
                int is_down = (GetAsyncKeyState(vk) & 0x8000) != 0;
                if (is_down) {
                    if (!g_KeyScripts[i].was_down) {
                        g_KeyScripts[i].was_down = 1;
                        
                        // Load script file and queue it
                        FILE* f = fopen(g_KeyScripts[i].path, "rb");
                        if (f) {
                            fseek(f, 0, SEEK_END);
                            long sz = ftell(f);
                            fseek(f, 0, SEEK_SET);
                            
                            if (sz > 0 && sz < 1024 * 1024) {
                                char* buf = (char*)malloc(sz + 1);
                                if (buf) {
                                    size_t read_bytes = fread(buf, 1, sz, f);
                                    buf[read_bytes] = '\0';
                                    
                                    m2_logf("[*] lua_bridge: OnKey hotkey '%s' pressed. Queuing script %s", 
                                            g_KeyScripts[i].key_name, g_KeyScripts[i].rel_path);
                                    InQueuePush(buf, read_bytes);
                                    
                                    free(buf);
                                }
                            }
                            fclose(f);
                        }
                    }
                } else {
                    g_KeyScripts[i].was_down = 0;
                }
            }
        }
        Sleep(33); // 30Hz polling rate
    }
    return 0;
}

static void InitializeKeyScripts(void) {
    char exe_dir[MAX_PATH];
    char folder_path[MAX_PATH];
    char loader_ini_path[MAX_PATH];
    char* slash;
    int i;
    
    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(folder_path, sizeof(folder_path), "%sscripts\\OnKey\\", exe_dir);
    m2_module_path(g_hModule, "lua_loader.ini", loader_ini_path, sizeof(loader_ini_path));
    EnsureLoaderIniHeader(loader_ini_path);

    LuaScriptFile temp_files[MAX_SCRIPTS];
    int file_count = 0;
    CollectScriptsRecursive(folder_path, "", temp_files, &file_count, MAX_SCRIPTS);

    g_KeyScriptCount = 0;

    if (file_count == 0) {
        m2_logf("[*] lua_bridge: No scripts found in scripts/OnKey/");
        return;
    }

    qsort(temp_files, file_count, sizeof(LuaScriptFile), CompareAlphabetical);

    for (i = 0; i < file_count && g_KeyScriptCount < MAX_SCRIPTS; ++i) {
        char key_name[64];
        
        GetPrivateProfileStringA("OnKey", temp_files[i].rel_path, "", key_name, sizeof(key_name), loader_ini_path);
        
        if (key_name[0] == '\0') {
            ExtractDefaultKey(temp_files[i].path, key_name, sizeof(key_name));
            WritePrivateProfileStringA("OnKey", temp_files[i].rel_path, key_name, loader_ini_path);
        }

        strncpy(g_KeyScripts[g_KeyScriptCount].path, temp_files[i].path, sizeof(g_KeyScripts[g_KeyScriptCount].path) - 1);
        g_KeyScripts[g_KeyScriptCount].path[sizeof(g_KeyScripts[g_KeyScriptCount].path) - 1] = '\0';

        strncpy(g_KeyScripts[g_KeyScriptCount].rel_path, temp_files[i].rel_path, sizeof(g_KeyScripts[g_KeyScriptCount].rel_path) - 1);
        g_KeyScripts[g_KeyScriptCount].rel_path[sizeof(g_KeyScripts[g_KeyScriptCount].rel_path) - 1] = '\0';

        strncpy(g_KeyScripts[g_KeyScriptCount].key_name, key_name, sizeof(g_KeyScripts[g_KeyScriptCount].key_name) - 1);
        g_KeyScripts[g_KeyScriptCount].key_name[sizeof(g_KeyScripts[g_KeyScriptCount].key_name) - 1] = '\0';

        g_KeyScripts[g_KeyScriptCount].vk_code = ResolveKeyName(key_name);
        g_KeyScripts[g_KeyScriptCount].was_down = 0;

        m2_logf("[*] lua_bridge: Registered OnKey script: scripts/OnKey/%s bound to '%s' (VK 0x%X)", 
                temp_files[i].rel_path, key_name, g_KeyScripts[g_KeyScriptCount].vk_code);

        g_KeyScriptCount++;
    }

    CreateThread(NULL, 0, LoaderKeyThread, NULL, 0, NULL);
    m2_logf("[*] lua_bridge: Spawning background hotkey polling thread");
}

static void RegisterTcpLib(void* L) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD func_addr = (DWORD)base + g_rvas->luaL_register;
    const char* libname = "Tcp";
    const luaL_Reg* table = tcp_lib;

    __asm__ volatile (
        "push %2\n\t"        // Push table pointer (stack arg)
        "call *%3\n\t"       // Call luaL_register
        "add $4, %%esp\n\t"  // Clean stack (4 bytes)
        :
        : "c"(L), "a"(libname), "r"(table), "r"(func_addr)
        : "edx", "memory"
    );
    m2_logf("[*] lua_bridge: Registered Tcp.Send globally");
}

/* ------------------------------------------------------------------------ *
 * TCP REPL server
 *
 * Protocol (matches tools/lua_repl.py and tools/lua_console.py in the
 * upstream Merc2Reborn project):
 *   - Client connects to g_repl_host:g_repl_port.
 *   - Client sends one or more lines, terminated by a line containing
 *     literal "<<<RUN>>>". The lines preceding the marker form the
 *     chunk to execute.
 *   - Server queues the chunk and replies "[queued]" immediately.
 *   - Whenever a pump source fires, the queued chunk runs against the
 *     captured L. The result is written back as one or more lines,
 *     followed by a line containing "<<<END>>>".
 * ------------------------------------------------------------------------ */
#define BRIDGE_SENTINEL   "<<<RUN>>>"
#define BRIDGE_END_MARKER "<<<END>>>"

static DWORD WINAPI BridgeServerThread(LPVOID arg) {
    WSADATA w;
    SOCKET srv, c;
    struct sockaddr_in addr;
    BOOL reuse = TRUE;
    (void)arg;

    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        m2_logf("[!] lua_bridge: WSAStartup failed");
        return 1;
    }
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) {
        m2_logf("[!] lua_bridge: socket() failed GLE=%lu", (unsigned long)WSAGetLastError());
        return 1;
    }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)g_repl_port);
    inet_pton(AF_INET, g_repl_host, &addr.sin_addr);
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(srv, 1) != 0) {
        m2_logf("[!] lua_bridge: bind/listen on %s:%d failed GLE=%lu",
                g_repl_host, g_repl_port, (unsigned long)WSAGetLastError());
        closesocket(srv);
        return 1;
    }
    m2_logf("[*] lua_bridge: listening on %s:%d", g_repl_host, g_repl_port);

    for (;;) {
        char rx[4096];
        char chunk_buf[1048576];  /* 1 MB — matches FixedTString.data */
        size_t chunk_len = 0;
        fd_set fds;
        struct timeval tv;
        int r;
        const char* nl;
        const char* p;
        size_t rx_len = 0;

        c = accept(srv, NULL, NULL);
        if (c == INVALID_SOCKET) continue;

        for (;;) {
            /* Flush pending output */
            EnterCriticalSection(&g_outMtx);
            if (g_outBuf_len > 0) {
                size_t off = 0;
                int send_failed = 0;
                while (off < g_outBuf_len) {
                    int sent = send(c, g_outBuf + off, (int)(g_outBuf_len - off), 0);
                    if (sent <= 0) { send_failed = 1; break; }
                    off += (size_t)sent;
                }
                g_outBuf_len = 0;
                if (g_outBuf) g_outBuf[0] = '\0';
                if (send_failed) { LeaveCriticalSection(&g_outMtx); break; }
            }
            LeaveCriticalSection(&g_outMtx);

            FD_ZERO(&fds);
            FD_SET(c, &fds);
            tv.tv_sec = 0; tv.tv_usec = 50000;
            r = select(0, &fds, NULL, NULL, &tv);
            if (r < 0) break;
            if (r == 0) continue;

            {
                int n = recv(c, rx + rx_len, (int)(sizeof(rx) - rx_len - 1), 0);
                if (n <= 0) break;
                rx_len += (size_t)n;
                rx[rx_len] = '\0';
            }

            /* Process complete lines */
            p = rx;
            while ((nl = (const char*)memchr(p, '\n', rx + rx_len - p)) != NULL) {
                size_t line_len = (size_t)(nl - p);
                /* Strip trailing \r if present */
                if (line_len > 0 && p[line_len - 1] == '\r') line_len--;
                if (line_len == sizeof(BRIDGE_SENTINEL) - 1 &&
                    memcmp(p, BRIDGE_SENTINEL, line_len) == 0) {
                    /* Submit accumulated chunk */
                    if (chunk_len > 0) {
                        m2_logf("[+] lua_bridge: queued chunk (%zu bytes)", chunk_len);
                        InQueuePush(chunk_buf, chunk_len);
                        OutAppend("[queued]", 8);
                    }
                    chunk_len = 0;
                } else {
                    /* Append line + newline to chunk */
                    if (chunk_len + line_len + 1 < sizeof(chunk_buf)) {
                        memcpy(chunk_buf + chunk_len, p, line_len);
                        chunk_len += line_len;
                        chunk_buf[chunk_len++] = '\n';
                    }
                }
                p = nl + 1;
            }
            /* Shift unconsumed bytes to front */
            {
                size_t consumed = (size_t)(p - rx);
                if (consumed > 0 && consumed < rx_len) {
                    memmove(rx, rx + consumed, rx_len - consumed);
                }
                rx_len -= consumed;
                rx[rx_len] = '\0';
            }
        }

        closesocket(c);
    }
}

/* ------------------------------------------------------------------------ *
 * INI config
 * ------------------------------------------------------------------------ */
/* m2_ini_parse's callback signature is (ud, key, value) — the parser
 * strips section headers internally and never surfaces them, so we
 * dispatch on the key name alone. Our two keys (`host` and `port`)
 * are unique across the INI's sections so this is fine. */
static void OnIniKV(void* ud, const char* key, const char* value) {
    (void)ud;
    if (!key || !value) return;
    if (_stricmp(key, "host") == 0) {
        strncpy(g_repl_host, value, sizeof(g_repl_host) - 1);
        g_repl_host[sizeof(g_repl_host) - 1] = 0;
    } else if (_stricmp(key, "port") == 0) {
        g_repl_port = atoi(value);
        if (g_repl_port <= 0 || g_repl_port > 65535) g_repl_port = 27050;
    } else if (_stricmp(key, "loader_enabled") == 0) {
        g_loader_enabled = atoi(value);
    } else if (_stricmp(key, "loader_onboot") == 0) {
        g_loader_onboot = atoi(value);
    } else if (_stricmp(key, "loader_onload") == 0) {
        g_loader_onload = atoi(value);
    } else if (_stricmp(key, "loader_delay_ms") == 0) {
        g_loader_delay_ms = atoi(value);
        if (g_loader_delay_ms < 0) g_loader_delay_ms = 0;
    }
}

static void LoadConfig(void) {
    char ini_path[MAX_PATH];
    m2_module_path(g_hModule, "lua_bridge.ini", ini_path, sizeof(ini_path));
    m2_ini_parse(ini_path, OnIniKV, NULL);
}

/* ------------------------------------------------------------------------ *
 * Init
 * ------------------------------------------------------------------------ */
static DWORD WINAPI WorkerThread(LPVOID arg) {
    HMODULE mod;
    BYTE* base;
    int hooks_armed = 0;
    int t;

    typedef struct HookSpec {
        DWORD     rva;
        LPVOID    detour;
        LPVOID*   orig;
        const char* name;
        HookKind  kind;
    } HookSpec;
    HookSpec specs[3];

    (void)arg;

    LoadConfig();
    if (g_loader_enabled) {
        EnsureLoaderDirectories();
    }
    InitializeCriticalSection(&g_inMtx);
    InitializeCriticalSection(&g_outMtx);
    InitChunkSource();

    mod = GetModuleHandleA(NULL);
    if (!mod) {
        m2_logf("[!] lua_bridge: GetModuleHandle(NULL) returned NULL");
        return 1;
    }
    base = (BYTE*)mod;

    g_rvas = SelectRvas(mod);

    /* Same SecuROM-unpack-wait pattern Merc2Fix uses on the noop stub. */
    {
        BYTE* probe = base + g_rvas->noop_stub;
        for (t = 0; t < 400; t++) {
            int nz = 0, i;
            for (i = 0; i < 8; i++) if (probe[i]) { nz = 1; break; }
            if (nz) break;
            Sleep(25);
        }
    }

    p_luaB_loadstring = (lua_CFunction_t)(base + g_rvas->luaB_loadstring);
    p_luaB_pcall      = (lua_CFunction_t)(base + g_rvas->luaB_pcall);
    m2_logf("[*] lua_bridge: executor armed (loadstring=%p, pcall=%p)",
            p_luaB_loadstring, p_luaB_pcall);

    specs[0].rva = g_rvas->noop_stub;
    specs[0].detour = (LPVOID)&DetourNoopStub;
    specs[0].orig = (LPVOID*)&fpOriginal_NoopStub;
    specs[0].name = "noop-stub (print/SendEvent_*/...)";
    specs[0].kind = HOOK_NOOP_STUB;

    specs[1].rva = g_rvas->luaB_type;
    specs[1].detour = (LPVOID)&DetourLuaType;
    specs[1].orig = (LPVOID*)&fpOriginal_luaB_type;
    specs[1].name = "luaB_type";
    specs[1].kind = HOOK_NORMAL_FUNC;

    specs[2].rva = g_rvas->CreateTextWidget;
    specs[2].detour = (LPVOID)&DetourCreateTextWidget;
    specs[2].orig = (LPVOID*)&fpOriginal_CreateTextWidget;
    specs[2].name = "CreateTextWidget";
    specs[2].kind = HOOK_NORMAL_FUNC;

    /* NOTE: luaL_register hook intentionally omitted — see commented
     * block above. Bridge works without it; we just lose the
     * print/next/tostring hijack and the registration-table dump. */

    for (t = 0; t < (int)(sizeof(specs)/sizeof(specs[0])); ++t) {
        LPVOID target = (LPVOID)(base + specs[t].rva);
        if (!ValidateHookTarget(target, specs[t].kind)) {
            m2_logf("[!] lua_bridge: RVA 0x%X (%s) failed prologue validation — skipping",
                    specs[t].rva, specs[t].name);
            continue;
        }
        if (!m2_hook_attach(target, specs[t].detour, specs[t].orig)) {
            m2_logf("[!] lua_bridge: m2_hook_attach(%s) failed", specs[t].name);
            continue;
        }
        m2_logf("[*] lua_bridge: hook armed on %s (RVA 0x%X -> %p)",
                specs[t].name, specs[t].rva, target);
        hooks_armed++;
    }

    if (hooks_armed == 0) {
        m2_logf("[!] lua_bridge: 0 hooks armed — bridge disabled for this binary. "
                "REPL will NOT be started.");
        return 0;
    }

    CreateThread(NULL, 0, BridgeServerThread, NULL, 0, NULL);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)h;
        DisableThreadLibraryCalls(h);
        m2_log_init(g_hModule);
        m2_logf("==========================================");
        m2_logf("[*] lua_bridge loading");
        m2_logf("==========================================");
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
