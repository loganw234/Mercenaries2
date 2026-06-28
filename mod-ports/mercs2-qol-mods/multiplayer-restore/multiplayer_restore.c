/* multiplayer_restore.c — restores Mercenaries 2 online multiplayer.
 *
 * Ported from Merc2Reborn's Merc2Fix ASI to the mercs2-qol-mods SDK
 * (https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).
 *
 * What it does:
 *
 *   1. DNS redirect — intercepts ws2_32 gethostbyname / getaddrinfo /
 *      GetAddrInfoW and routes *.ea.com / *.gamespy.com / fesl* to
 *      the configured private server (default refesl.live, resolved
 *      at startup).
 *
 *   2. Cert blob blindfold — intercepts wintrust WinVerifyTrust and
 *      returns ERROR_SUCCESS for WTD_CHOICE_BLOB so the private
 *      server's self-signed cert is accepted. Local file/catalog
 *      cert validation (the SecuROM boot path) is left untouched.
 *
 *   3. Time spoof — pins the system clock returned by both Win32
 *      (kernel32 GetSystemTime/GetLocalTime/GetSystemTimeAsFileTime)
 *      and the C runtime (msvcrt time/_time32/_time64) to a date
 *      inside the served cert's validity window (default 2012-06-15).
 *      This is belt-and-braces with the WinVerifyTrust blindfold; in
 *      principle redundant after the cert is accepted, but cheap and
 *      keeps OpenSSL's CRT-side expiry check happy. Toggle off via
 *      INI if you want to test without it.
 *
 *   4. FESL CA pubkey patch — single 128-byte write into the game's
 *      .rdata at FESL_CA_KEY_RVA, replaying the MLoader patch so the
 *      game's SSL stack accepts the private server's cert chain. The
 *      write is gated on a poll loop that waits for SecuROM to
 *      finish unpacking that section, mirroring what MLoader does.
 *      THIS IS THE ONE LIKELY-FRAGILE STEP on the cracked binary —
 *      see the status block immediately below.
 *
 * What it does NOT do:
 *
 *   - No Lua bridge / executor / REPL. That tier lives in Merc2Fix
 *     proper and is intentionally out of scope for this port.
 *   - No UDP relay client. The relay runs server-side; the client
 *     just routes its packets to whatever IP/port Theater hands
 *     back, which the DNS redirect already takes care of.
 *
 * Most users will not need to forward any ports.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wintrust.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#include "m2_log.h"
#include "m2_hook.h"
#include "m2_ini.h"

/* Link with -lws2_32 -lwintrust (see Makefile). On MSVC builds, the
 * old `#pragma comment(lib, ...)` would do this automatically; we
 * pass them on the link command line instead so MinGW agrees. */

/* ======================================================================== *
 * Status: PROOF-OF-CONCEPT — this port has NOT been built or test-run
 * against the mercs2-qol-mods framework. The author drafted it without
 * the SDK build environment (MinGW, pmc_bb.dll runtime, etc.) set up
 * locally. The underlying *approach* is validated:
 *
 *   * The standalone Merc2Fix.asi (which this is ported from) was run
 *     against a mercs2-securom-bypass-patched Mercenaries2.exe. All
 *     five hooks armed, multiplayer worked end-to-end, no anti-tamper
 *     trips. (The companion Lua bridge correctly aborted itself via
 *     its RVA prologue check, as expected — that side is out of scope
 *     for this multiplayer-only port.)
 *
 * What that means: the hooking model, time-spoof strategy, and CA
 * key patch all behave on the bypass target. The architecture is
 * sound. Bugs from here are most likely going to be SDK-integration
 * mistakes (wrong helper signature assumed, missing init step,
 * style mismatches) rather than fundamental design issues.
 *
 * Remaining open question:
 *
 *   FESL_CA_KEY_RVA below (0x768378) was extracted from MLoader's
 *   dump against the archive.org English retail build. The bypass
 *   tool swaps the import table cruise.dll -> pmc_bb.dll (same name
 *   length, no shift) and edits .text to strip the DRM validation;
 *   it most likely does not resize .rdata, so the offset should be
 *   stable on the bypass target — but please verify before shipping.
 *   30-second check: dump the first 16 bytes at this RVA in your
 *   live process and confirm they look like a 128-byte placeholder
 *   (mostly zeros or a single repeated pattern), not real engine
 *   data. If real data is there, the offset moved.
 *
 * Notes that aren't blockers:
 *
 *   * The SDK's m2_hook.h warning about .rdata anti-tamper writes
 *     does not appear to apply to the bypass target (SecuROM is
 *     stripped, pmc_bb.dll explicitly doesn't do integrity checks).
 *     Our PatchFeslCAKey still keeps a short unpack-wait poll as a
 *     no-op safety net for users running this on a different (e.g.
 *     archive.org or MLoader-cracked) binary — exits on the first
 *     iteration when bytes are already in plaintext.
 *
 *   * msvcr80.dll / msvcr90.dll may or may not be loaded depending
 *     on the toolset; GetProcAddress returns NULL on the missing
 *     ones and we skip those CRT time hooks quietly (passed
 *     required=0 in HookApi).
 * ======================================================================== */

#define FESL_CA_KEY_RVA  0x768378u
static const BYTE kFeslCAKeyPayload[128] = {
    0xDA, 0x02, 0xD3, 0x80, 0xD0, 0xAB, 0x67, 0x88,
    0x6D, 0x2B, 0x11, 0x17, 0x7E, 0xFF, 0x4F, 0x1F,
    0xBA, 0x80, 0xA3, 0x07, 0x0E, 0x8F, 0x03, 0x6D,
    0xEE, 0x9D, 0xC0, 0xF3, 0x0B, 0xF8, 0xB8, 0x05,
    0x16, 0x16, 0x4D, 0xC0, 0xD4, 0x82, 0x7F, 0x47,
    0xA4, 0x8A, 0x3B, 0xCA, 0x12, 0x9D, 0xD2, 0x9D,
    0x19, 0x61, 0xD8, 0x56, 0x61, 0x47, 0xA5, 0x88,
    0xDC, 0x24, 0x8F, 0x90, 0xC9, 0xA4, 0x1C, 0xBF,
    0xF8, 0x57, 0xE0, 0x2F, 0x47, 0x78, 0x2E, 0xAE,
    0x5A, 0x70, 0xE5, 0x55, 0xBA, 0xDD, 0x36, 0xE1,
    0x6C, 0x17, 0x93, 0x31, 0xE4, 0xF9, 0x22, 0x03,
    0x81, 0x69, 0x98, 0xC8, 0x2E, 0xDF, 0xBE, 0x0E,
    0x33, 0x9D, 0xC3, 0xE0, 0xC0, 0x20, 0x85, 0x52,
    0xCD, 0x3F, 0x05, 0xF5, 0xCB, 0x41, 0x2F, 0x67,
    0x10, 0x91, 0x6A, 0xD1, 0x59, 0xDA, 0xC1, 0x23,
    0x3E, 0x71, 0x08, 0x9F, 0x20, 0xD4, 0x3D, 0x6D,
};

#define SPOOF_YEAR   2012
#define SPOOF_MONTH  6
#define SPOOF_DAY    15

static char g_server_ip[64]  = "refesl.live";  /* overridden by INI */
static int  g_spoof_clock    = 1;              /* overridden by INI */
static int  g_hook_dns       = 1;              /* overridden by INI */
static int  g_hook_cert      = 1;              /* overridden by INI */
static int  g_patch_ca       = 1;              /* overridden by INI */
static HMODULE g_hModule     = NULL;

/* ------------------------------------------------------------------------ *
 * INI config — server IP + clock spoof + hook toggles.
 * ------------------------------------------------------------------------ */

/* m2_ini_parse's callback signature is (ud, key, value) — the parser
 * strips section headers internally and never surfaces them, so we
 * dispatch on the key name alone. */
static void OnIniKV(void* ud, const char* key, const char* value) {
    (void)ud;
    if (!key || !value) return;
    if (_stricmp(key, "ip") == 0) {
        strncpy(g_server_ip, value, sizeof(g_server_ip) - 1);
        g_server_ip[sizeof(g_server_ip) - 1] = 0;
    } else if (_stricmp(key, "spoof_clock") == 0 || _stricmp(key, "hook_time") == 0) {
        g_spoof_clock = m2_ini_bool(value);
    } else if (_stricmp(key, "hook_dns") == 0) {
        g_hook_dns = m2_ini_bool(value);
    } else if (_stricmp(key, "hook_cert") == 0) {
        g_hook_cert = m2_ini_bool(value);
    } else if (_stricmp(key, "patch_ca") == 0) {
        g_patch_ca = m2_ini_bool(value);
    }
}

static void LoadConfig(void) {
    char ini_path[MAX_PATH];
    m2_module_path(g_hModule, "multiplayer_restore.ini", ini_path, sizeof(ini_path));
    m2_ini_parse(ini_path, OnIniKV, NULL);
}

/* ------------------------------------------------------------------------ *
 * DNS — resolve the configured server address once at startup so we don't
 * recursively call the hooked resolvers later.
 * ------------------------------------------------------------------------ */

static char g_resolved_ip[64] = "127.0.0.1";  /* updated by ResolveServer */

static void ResolveServer(void) {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        m2_logf("[!] WSAStartup failed; falling back to %s", g_resolved_ip);
        return;
    }
    /* If the INI value already looks like a dotted-quad, skip DNS. */
    struct in_addr probe;
    if (inet_pton(AF_INET, g_server_ip, &probe) == 1) {
        strncpy(g_resolved_ip, g_server_ip, sizeof(g_resolved_ip) - 1); g_resolved_ip[sizeof(g_resolved_ip) - 1] = 0;
        m2_logf("[*] Using server IP from config: %s", g_resolved_ip);
        WSACleanup();
        return;
    }
    struct addrinfo hints = { 0 }, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_server_ip, NULL, &hints, &res) == 0 && res) {
        struct sockaddr_in* a = (struct sockaddr_in*)res->ai_addr;
        const char* dotted = inet_ntoa(a->sin_addr);
        if (dotted) { strncpy(g_resolved_ip, dotted, sizeof(g_resolved_ip) - 1); g_resolved_ip[sizeof(g_resolved_ip) - 1] = 0; }
        freeaddrinfo(res);
        m2_logf("[+] Resolved %s -> %s", g_server_ip, g_resolved_ip);
    } else {
        m2_logf("[!] Failed to resolve %s; falling back to %s",
                g_server_ip, g_resolved_ip);
    }
    WSACleanup();
}

static int IsTargetHost(const char* host) {
    if (!host) return 0;
    return strstr(host, "ea.com")      != NULL
        || strstr(host, "gamespy.com") != NULL
        || strstr(host, "fesl")        != NULL;
}

static void NarrowFromWide(const wchar_t* w, char* out, size_t out_max) {
    size_t i = 0;
    if (!w || !out || out_max == 0) return;
    for (; w[i] && i + 1 < out_max; ++i) out[i] = (char)(w[i] & 0xFF);
    out[i] = 0;
}

/* ------------------------------------------------------------------------ *
 * Detours
 * ------------------------------------------------------------------------ */

typedef struct hostent* (WINAPI* GETHOSTBYNAME_FN)(const char*);
typedef int (WSAAPI* GETADDRINFO_FN)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef int (WSAAPI* GETADDRINFOW_FN)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef LONG (WINAPI* WINVERIFYTRUST_FN)(HWND, GUID*, LPVOID);
typedef VOID (WINAPI* GETSYSTEMTIME_FN)(LPSYSTEMTIME);
typedef VOID (WINAPI* GETLOCALTIME_FN)(LPSYSTEMTIME);
typedef VOID (WINAPI* GETSYSTEMTIMEASFILETIME_FN)(LPFILETIME);
typedef time_t      (__cdecl* TIME_FN)(time_t*);
typedef __time32_t  (__cdecl* TIME32_FN)(__time32_t*);
typedef __time64_t  (__cdecl* TIME64_FN)(__time64_t*);

static GETHOSTBYNAME_FN            o_gethostbyname        = NULL;
static GETADDRINFO_FN              o_getaddrinfo          = NULL;
static GETADDRINFOW_FN             o_getaddrinfow         = NULL;
static WINVERIFYTRUST_FN           o_winverifytrust       = NULL;
static GETSYSTEMTIME_FN            o_GetSystemTime        = NULL;
static GETLOCALTIME_FN             o_GetLocalTime         = NULL;
static GETSYSTEMTIMEASFILETIME_FN  o_GetSystemTimeAsFileTime = NULL;

static struct hostent* WINAPI d_gethostbyname(const char* name) {
    if (name && IsTargetHost(name)) {
        m2_logf("[+] (gethostbyname) %s -> %s", name, g_resolved_ip);
        return o_gethostbyname(g_resolved_ip);
    }
    return o_gethostbyname(name);
}

static int WSAAPI d_getaddrinfo(PCSTR node, PCSTR svc,
                                const ADDRINFOA* hints, PADDRINFOA* res) {
    if (node && IsTargetHost(node)) {
        m2_logf("[+] (getaddrinfo) %s -> %s", node, g_resolved_ip);
        return o_getaddrinfo(g_resolved_ip, svc, hints, res);
    }
    return o_getaddrinfo(node, svc, hints, res);
}

static int WSAAPI d_getaddrinfow(PCWSTR node, PCWSTR svc,
                                 const ADDRINFOW* hints, PADDRINFOW* res) {
    if (node) {
        char nn[256]; NarrowFromWide(node, nn, sizeof(nn));
        if (IsTargetHost(nn)) {
            wchar_t wip[64];
            for (size_t i = 0; i < sizeof(g_resolved_ip) && g_resolved_ip[i]; ++i) {
                wip[i] = (wchar_t)g_resolved_ip[i];
                wip[i+1] = 0;
            }
            m2_logf("[+] (GetAddrInfoW) %s -> %s", nn, g_resolved_ip);
            return o_getaddrinfow(wip, svc, hints, res);
        }
    }
    return o_getaddrinfow(node, svc, hints, res);
}

static LONG WINAPI d_winverifytrust(HWND hwnd, GUID* action, LPVOID data) {
    if (data) {
        WINTRUST_DATA* d = (WINTRUST_DATA*)data;
        if (d->dwUnionChoice == WTD_CHOICE_BLOB) {
            m2_logf("[+] WinVerifyTrust(BLOB) -> ERROR_SUCCESS");
            return ERROR_SUCCESS;
        }
    }
    return o_winverifytrust(hwnd, action, data);
}

static void ApplySpoof(LPSYSTEMTIME st) {
    if (!st) return;
    st->wYear  = SPOOF_YEAR;
    st->wMonth = SPOOF_MONTH;
    st->wDay   = SPOOF_DAY;
}

static VOID WINAPI d_GetSystemTime(LPSYSTEMTIME st) {
    o_GetSystemTime(st); ApplySpoof(st);
}
static VOID WINAPI d_GetLocalTime(LPSYSTEMTIME st) {
    o_GetLocalTime(st); ApplySpoof(st);
}
static VOID WINAPI d_GetSystemTimeAsFileTime(LPFILETIME ft) {
    SYSTEMTIME st;
    o_GetSystemTime(&st);
    ApplySpoof(&st);
    SystemTimeToFileTime(&st, ft);
}

/* CRT time hooks — OpenSSL's cert-expiry check uses these, NOT the
 * kernel32 ones. msvcr80/msvcr90 may or may not be loaded; if not we
 * skip the hook in WorkerThread. */
static time_t __cdecl d_time(time_t* t) {
    FILETIME ft; d_GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u; u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    time_t sec = (time_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
    if (t) *t = sec;
    return sec;
}
static __time32_t __cdecl d_time32(__time32_t* t) {
    __time32_t s = (__time32_t)d_time(NULL);
    if (t) *t = s;
    return s;
}
static __time64_t __cdecl d_time64(__time64_t* t) {
    __time64_t s = (__time64_t)d_time(NULL);
    if (t) *t = s;
    return s;
}

/* ------------------------------------------------------------------------ *
 * FESL CA key patch — the single .rdata write
 * ------------------------------------------------------------------------ */

static int PatchFeslCAKey(void) {
    HMODULE mod = GetModuleHandleA(NULL);
    if (!mod) {
        m2_logf("[!] PatchFeslCAKey: Host module not loaded");
        return 0;
    }
    BYTE* target = (BYTE*)mod + FESL_CA_KEY_RVA;

    /* Wait up to ~5 s for SecuROM to unpack .rdata. The check is
     * "first 16 bytes are non-zero" — same heuristic MLoader uses. */
    for (int tries = 0; tries < 200; tries++) {
        int nonzero = 0;
        for (int i = 0; i < 16; i++) {
            if (target[i] != 0) { nonzero = 1; break; }
        }
        if (nonzero) break;
        Sleep(25);
    }

    if (memcmp(target, kFeslCAKeyPayload, sizeof(kFeslCAKeyPayload)) == 0) {
        m2_logf("[*] FESL CA key already matches payload (MLoader present?) — skipped");
        return 1;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, sizeof(kFeslCAKeyPayload),
                        PAGE_READWRITE, &oldProtect)) {
        m2_logf("[!] PatchFeslCAKey: VirtualProtect failed, GLE=%lu", GetLastError());
        return 0;
    }
    memcpy(target, kFeslCAKeyPayload, sizeof(kFeslCAKeyPayload));
    DWORD tmp = 0;
    VirtualProtect(target, sizeof(kFeslCAKeyPayload), oldProtect, &tmp);

    m2_logf("[+] FESL CA key patched at RVA 0x%X (%u bytes)",
            FESL_CA_KEY_RVA, (unsigned)sizeof(kFeslCAKeyPayload));
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Hook arming
 * ------------------------------------------------------------------------ */

static int HookApi(const char* module, const char* fn,
                   void* detour, void** orig, int required) {
    HMODULE m = GetModuleHandleA(module);
    if (!m) m = LoadLibraryA(module);
    if (!m) {
        if (required) m2_logf("[!] HookApi: module %s not loadable", module);
        return 0;
    }
    void* target = (void*)GetProcAddress(m, fn);
    if (!target) {
        if (required) m2_logf("[!] HookApi: %s!%s not found", module, fn);
        return 0;
    }
    if (!m2_hook_attach(target, detour, orig)) {
        m2_logf("[!] m2_hook_attach failed for %s!%s", module, fn);
        return 0;
    }
    m2_logf("[*] hooked %s!%s -> %p", module, fn, detour);
    return 1;
}

static DWORD WINAPI WorkerThread(LPVOID arg) {
    (void)arg;

    LoadConfig();
    if (g_hook_dns) {
        ResolveServer();
    } else {
        m2_logf("[*] DNS resolution skipped (DNS redirect disabled)");
    }

    if (!m2_hook_init()) {
        m2_logf("[!] m2_hook_init failed; aborting");
        return 1;
    }

    /* 1. DNS redirect. */
    if (g_hook_dns) {
        HookApi("ws2_32.dll", "gethostbyname",   (void*)d_gethostbyname,   (void**)&o_gethostbyname,   1);
        HookApi("ws2_32.dll", "getaddrinfo",     (void*)d_getaddrinfo,     (void**)&o_getaddrinfo,     1);
        HookApi("ws2_32.dll", "GetAddrInfoW",    (void*)d_getaddrinfow,    (void**)&o_getaddrinfow,    1);
    } else {
        m2_logf("[*] DNS redirect hook disabled by config");
    }

    /* 2. Cert blob blindfold. */
    if (g_hook_cert) {
        HookApi("wintrust.dll", "WinVerifyTrust", (void*)d_winverifytrust, (void**)&o_winverifytrust, 1);
    } else {
        m2_logf("[*] WinVerifyTrust hook disabled by config");
    }

    /* 3. Time spoof. */
    if (g_spoof_clock) {
        HookApi("kernel32.dll", "GetSystemTime",            (void*)d_GetSystemTime,            (void**)&o_GetSystemTime,            1);
        HookApi("kernel32.dll", "GetLocalTime",             (void*)d_GetLocalTime,             (void**)&o_GetLocalTime,             1);
        HookApi("kernel32.dll", "GetSystemTimeAsFileTime",  (void*)d_GetSystemTimeAsFileTime,  (void**)&o_GetSystemTimeAsFileTime,  1);
        const char* crt[] = { "msvcrt.dll", "msvcr80.dll", "msvcr90.dll" };
        for (size_t i = 0; i < sizeof(crt) / sizeof(crt[0]); ++i) {
            HookApi(crt[i], "time",    (void*)d_time,    NULL, 0);
            HookApi(crt[i], "_time32", (void*)d_time32,  NULL, 0);
            HookApi(crt[i], "_time64", (void*)d_time64,  NULL, 0);
        }
        m2_logf("[*] clock spoof active: %04d-%02d-%02d", SPOOF_YEAR, SPOOF_MONTH, SPOOF_DAY);
    } else {
        m2_logf("[*] clock spoof disabled by config");
    }

    /* 4. FESL CA pubkey patch — runs after hooks so any logging from
     *    the wait loop goes through the live logger. */
    if (g_patch_ca) {
        PatchFeslCAKey();
    } else {
        m2_logf("[*] FESL CA key patch disabled by config");
    }

    m2_logf("[*] multiplayer-restore: armed. Server target = %s", g_resolved_ip);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)h;
        DisableThreadLibraryCalls(h);
        m2_log_init(g_hModule);
        m2_logf("==========================================");
        m2_logf("[*] multiplayer-restore loading");
        m2_logf("==========================================");
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
