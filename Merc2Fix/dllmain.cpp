#include "pch.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wintrust.h>
#include "include/MinHook.h"
#include <string>
#include <fstream>
#include <algorithm>
#include <stdarg.h>
#include <time.h> // Required for CRT time hooks
#include <atomic>
#include <mutex>
#include <deque>
#include <cstddef>   // offsetof
#include <cstdint>   // uint32_t etc.

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wintrust.lib")

// ----------------------------------------------------------------------------
// Merc2Fix engine
//
// Changes vs the previous build:
//   * DNS redirection now also hooks getaddrinfo and GetAddrInfoW, not just the
//     legacy gethostbyname. Modern/2008-era engines often resolve via
//     getaddrinfo; if it isn't hooked the redirect silently misses and the game
//     dials the dead real ea.com, which looks like an instant disconnect.
//   * WinVerifyTrust "blindfold": local file/catalog checks (VMProtect DRM boot)
//     pass through untouched, but a network cert BLOB validation
//     (WTD_CHOICE_BLOB) is forced to ERROR_SUCCESS so the game accepts the
//     local server's certificate.
//   * The clock spoof sets a full mid-window date (not just the year) so it sits
//     comfortably inside the served cert's notBefore..notAfter range.
//   * C-Runtime Bridge: Hooks time(), _time32(), and _time64() across standard
//     MSVCRT DLLs because the statically linked OpenSSL relies on the C-Runtime,
//     not Windows APIs, to validate the certificate expiration date.
// ----------------------------------------------------------------------------

std::string g_ServerIP = "127.0.0.1";

static const WORD SPOOF_YEAR = 2012;
static const WORD SPOOF_MONTH = 6;
static const WORD SPOOF_DAY = 15;   // mid-window; cert validity checks the date

// ----------------------------------------------------------------------------
// MLoader RSA-key replacement (replaces the only thing MLoader.exe does that
// the rest of this DLL doesn't already cover).
//
// MLoader is Themida-protected, but its strings table and unpacked dump
// reveal the entire patch: a single 128-byte write into Mercenaries2.exe's
// .rdata. The bytes below were extracted bit-for-bit from MLoader_dump.exe
// at file offset 0xc6c0 (right after MLoader's "Unable to find RSA key!"
// log string). The destination RVA was confirmed by matching against the
// game's memory after MLoader had run.
//
// The bytes are NOT in canonical DER/BE form for the modulus — they appear
// to be the in-memory BIGNUM/precomputed representation the game expects.
// We don't need to interpret them; we just replay the same write.
// ----------------------------------------------------------------------------
static const DWORD kFeslCAKeyRVA = 0x768378;
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
void Log(const char* fmt, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    std::ofstream logFile("Merc2Debug.log", std::ios_base::app);
    if (logFile.is_open()) {
        logFile << buffer << "\n";
        logFile.close();
    }
}
static bool PatchFeslCAKey() {
    HMODULE mod = GetModuleHandleA("Mercenaries2.exe");
    if (!mod) {
        Log("[!] PatchFeslCAKey: GetModuleHandle(Mercenaries2.exe) returned NULL");
        return false;
    }
    BYTE* target = reinterpret_cast<BYTE*>(mod) + kFeslCAKeyRVA;

    // SecuROM unpacks .rdata before the game runs any meaningful code, but
    // depending on when this DLL is injected we may briefly race the unpacker.
    // Wait until the destination bytes look populated (not all-zero).
    for (int tries = 0; tries < 200; tries++) {
        bool nonzero = false;
        for (int i = 0; i < 16; i++) {
            if (target[i] != 0) { nonzero = true; break; }
        }
        if (nonzero) break;
        Sleep(25);
    }

    if (memcmp(target, kFeslCAKeyPayload, sizeof(kFeslCAKeyPayload)) == 0) {
        Log("[*] FESL CA key already matches payload (MLoader present?) — skipping patch");
        return true;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, sizeof(kFeslCAKeyPayload), PAGE_READWRITE, &oldProtect)) {
        Log("[!] PatchFeslCAKey: VirtualProtect(RW) failed, GLE=%lu", GetLastError());
        return false;
    }
    memcpy(target, kFeslCAKeyPayload, sizeof(kFeslCAKeyPayload));
    DWORD tmp = 0;
    VirtualProtect(target, sizeof(kFeslCAKeyPayload), oldProtect, &tmp);

    Log("[+] FESL CA key patched at %p (RVA 0x%X, %u bytes)",
        target, kFeslCAKeyRVA, (unsigned)sizeof(kFeslCAKeyPayload));
    return true;
}

// --- helpers ---------------------------------------------------------------
static bool IsTargetHost(const std::string& host) {
    return host.find("ea.com") != std::string::npos ||
        host.find("gamespy.com") != std::string::npos ||
        host.find("fesl") != std::string::npos;
}

static std::wstring Widen(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static std::string Narrow(const wchar_t* w) {
    std::string s;
    if (w) {
        for (; *w; ++w) s += static_cast<char>(*w & 0xFF);
    }
    return s;
}

static std::string ResolveDomain(const std::string& domain) {
    WSADATA wsaData;
    // Briefly initialize Winsock specifically for this thread
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        Log("[!] WSAStartup failed during DNS resolution.");
        return "";
    }

    std::string ip = "";
    struct addrinfo hints = { 0 };
    struct addrinfo* res = nullptr;

    // Force IPv4, as the 2008 engine will reject an IPv6 string
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Perform the DNS lookup
    if (getaddrinfo(domain.c_str(), nullptr, &hints, &res) == 0) {
        struct sockaddr_in* ipv4 = reinterpret_cast<struct sockaddr_in*>(res->ai_addr);

        // inet_ntoa is highly compatible with older MSVC toolsets
        ip = inet_ntoa(ipv4->sin_addr);
        freeaddrinfo(res);
    }
    else {
        Log("[!] Failed to resolve domain: %s", domain.c_str());
    }

    WSACleanup();
    return ip;
}

// --- Original Function Pointers --------------------------------------------
typedef hostent* (WINAPI* GETHOSTBYNAME)(const char* name);
GETHOSTBYNAME fpOriginalGetHostByName = NULL;

typedef int (WSAAPI* GETADDRINFO)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
GETADDRINFO fpOriginalGetAddrInfo = NULL;

typedef int (WSAAPI* GETADDRINFOW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
GETADDRINFOW fpOriginalGetAddrInfoW = NULL;

typedef LONG(WINAPI* WINVERIFYTRUST)(HWND, GUID*, LPVOID);
WINVERIFYTRUST fpOriginalWinVerifyTrust = NULL;

typedef VOID(WINAPI* GETSYSTEMTIME)(LPSYSTEMTIME lpSystemTime);
GETSYSTEMTIME fpOriginalGetSystemTime = NULL;

typedef VOID(WINAPI* GETSYSTEMTIMEASFILETIME)(LPFILETIME lpSystemTimeAsFileTime);
GETSYSTEMTIMEASFILETIME fpOriginalGetSystemTimeAsFileTime = NULL;

typedef VOID(WINAPI* GETLOCALTIME)(LPSYSTEMTIME lpSystemTime);
GETLOCALTIME fpOriginalGetLocalTime = NULL;

// --- Detour 1a: DNS Spoofing (legacy gethostbyname) ------------------------
hostent* WINAPI DetourGetHostByName(const char* name) {
    if (name != NULL) {
        std::string host(name);
        if (IsTargetHost(host)) {
            Log("[+] (gethostbyname) Routing %s to %s", host.c_str(), g_ServerIP.c_str());
            return fpOriginalGetHostByName(g_ServerIP.c_str());
        }
    }
    return fpOriginalGetHostByName(name);
}

// --- Detour 1b: DNS Spoofing (getaddrinfo, ANSI) ---------------------------
int WSAAPI DetourGetAddrInfo(PCSTR pNodeName, PCSTR pServiceName,
    const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    if (pNodeName != NULL) {
        std::string host(pNodeName);
        if (IsTargetHost(host)) {
            Log("[+] (getaddrinfo) Routing %s to %s", host.c_str(), g_ServerIP.c_str());
            return fpOriginalGetAddrInfo(g_ServerIP.c_str(), pServiceName, pHints, ppResult);
        }
    }
    return fpOriginalGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
}

// --- Detour 1c: DNS Spoofing (GetAddrInfoW, wide) --------------------------
int WSAAPI DetourGetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
    const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    if (pNodeName != NULL) {
        std::string host = Narrow(pNodeName);
        if (IsTargetHost(host)) {
            Log("[+] (GetAddrInfoW) Routing %s to %s", host.c_str(), g_ServerIP.c_str());
            std::wstring ip = Widen(g_ServerIP);
            return fpOriginalGetAddrInfoW(ip.c_str(), pServiceName, pHints, ppResult);
        }
    }
    return fpOriginalGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

// --- Detour 2: WinVerifyTrust blindfold ------------------------------------
LONG WINAPI DetourWinVerifyTrust(HWND hwnd, GUID* pgActionID, LPVOID pWVTData) {
    if (pWVTData != NULL) {
        WINTRUST_DATA* d = static_cast<WINTRUST_DATA*>(pWVTData);
        if (d->dwUnionChoice == WTD_CHOICE_BLOB) {
            Log("[+] WinVerifyTrust(BLOB) intercepted -> forcing ERROR_SUCCESS");
            return ERROR_SUCCESS;
        }
    }
    return fpOriginalWinVerifyTrust(hwnd, pgActionID, pWVTData);
}

// --- Detour 3: The Time Machine (Windows APIs) -----------------------------
static void ApplySpoof(LPSYSTEMTIME st) {
    st->wYear = SPOOF_YEAR;
    st->wMonth = SPOOF_MONTH;
    st->wDay = SPOOF_DAY;
}

VOID WINAPI DetourGetSystemTime(LPSYSTEMTIME lpSystemTime) {
    fpOriginalGetSystemTime(lpSystemTime);
    ApplySpoof(lpSystemTime);
}

VOID WINAPI DetourGetLocalTime(LPSYSTEMTIME lpSystemTime) {
    fpOriginalGetLocalTime(lpSystemTime);
    ApplySpoof(lpSystemTime);
}

VOID WINAPI DetourGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    SYSTEMTIME st;
    fpOriginalGetSystemTime(&st);
    ApplySpoof(&st);
    SystemTimeToFileTime(&st, lpSystemTimeAsFileTime);
}

// --- Detour 4: The C-Runtime Bridge (OpenSSL CRT Bypass) -------------------
// Grabs the mathematically perfect flowing FILETIME from our Windows hook
// and converts it down to a standard Unix Epoch timestamp for OpenSSL.
static time_t GetSpoofedEpoch() {
    FILETIME ft;
    DetourGetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    // Magic number converts 100ns Windows intervals to Unix Epoch seconds
    return (time_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

time_t __cdecl DetourTime(time_t* timer) {
    time_t spoofed = GetSpoofedEpoch();
    if (timer) *timer = spoofed;
    return spoofed;
}

__time32_t __cdecl DetourTime32(__time32_t* timer) {
    __time32_t spoofed = static_cast<__time32_t>(GetSpoofedEpoch());
    if (timer) *timer = spoofed;
    return spoofed;
}

__time64_t __cdecl DetourTime64(__time64_t* timer) {
    __time64_t spoofed = static_cast<__time64_t>(GetSpoofedEpoch());
    if (timer) *timer = spoofed;
    return spoofed;
}

// ===========================================================================
// Lua bridge — capture the engine lua_State and expose a localhost REPL.
//
// All RVAs were derived from Mercenaries2.exe.bak via tools/find_lua_print.py
// and tools/resolve_lua_api.py; full notes are in tools/lua_api_findings.md.
//
// Key facts that shaped this design (see tools/lua_api_findings.md and the
// crash-driven discoveries from rebuild #2):
//   * Lua 5.1.2 is statically linked into the exe (no Lua DLL).
//   * Lua's `print` is a tiny no-op stub (`xor eax,eax; ret`) at RVA
//     0x002AEF90. The engine registers this SAME stub under many other
//     names too (SendEvent_AddObjective, SetSourceEnterMusic,
//     SetCinematicMode, _SummonEd, ... — anything they stripped from
//     the shipping build). Hooking the stub fires every time scripts
//     call ANY of those, so capture probability is much higher than
//     print() alone would suggest.
//   * We also hook `type` (real fn, scripts call it constantly) and
//     CreateTextWidget (engine binding, fires during menu render).
//     First detour to win the atomic CAS keeps L.
//   * The debug library was stripped, so `lua_sethook` isn't easy to find.
//     Instead we pump the inbound queue directly from the capture detours.
//
// What the rebuild #2 crash taught us about the Lua C API in this binary:
//   * `lua_gettop`, `lua_settop`, `lua_pcall`, `luaL_loadstring` are ALL
//     inlined by the compiler — they don't exist as callable functions.
//     What I'd previously identified as `lua_settop` (RVA 0x45F2C0) is
//     actually `luaL_where` (108-byte stack frame for lua_Debug + a call
//     pattern matching lua_getstack).
//   * `luaD_pcall` IS a real function at RVA 0x468CF0, but uses a custom
//     register-based ABI: L in EAX, errfunc in EDX, func/u/old_top
//     pushed on the stack. NOT `__cdecl`. Calling it requires inline asm.
//   * RVA 0x461190 (what I'd called luaL_loadbuffer) is actually a
//     SecuROM forwarding thunk (`mov eax,[edx+8]; jmp [0x24D2FCC]`),
//     not a real callable function.
//   * `lua_tolstring` at RVA 0x46B480 IS real `__cdecl` — the only
//     internal Lua API we can call directly with a normal typedef.
//   * `lua_State` layout in this build differs from stock Lua 5.1.2:
//     L->top is at offset 8 (stock: 12), L->base at offset 0xC (stock:
//     16). Pandemic packed the CommonHeader more tightly. Confirmed by
//     reading luaB_pcall's prologue — it accesses [L+8] as top and
//     [L+0xC] as base.
//
// This file is at Phase 1: diagnostic-only. LuaDoString reports L's
// state but doesn't execute Lua code (which would require inline-asm
// wrappers for luaD_pcall plus crafting a fake-but-GC-fixed TString to
// push the chunk onto L's stack). Phase 2 will build the real executor.
// ===========================================================================

struct lua_State;  // opaque
#define LUA_MULTRET (-1)

// 1. Lua C functions registered via luaL_Reg (e.g. luaB_type, the noop-stub).
//    Confirmed __cdecl from binary inspection — these are dispatched by Lua's
//    internal precall machinery using stack-based args.
typedef int(__cdecl* lua_CFunction_t)(lua_State* L);

// 2. Pandemic engine bindings (e.g. CreateTextWidget) — __fastcall.
//    L goes to ECX (first arg). EDX is the dummy second arg.
typedef int(__fastcall* pandemic_CFunction_t)(lua_State* L, void* edx);

// (NO lua_tolstring typedef: what we thought was lua_tolstring at
// 0x46B480 turned out to be luaC_step. lua_tolstring is inlined.)

// NOT typedef'd intentionally (Phase 2 work):
//   - luaD_pcall (0x468CF0): custom register ABI, needs inline-asm wrapper
//   - lua_settop / lua_pcall / luaL_loadstring: INLINED by the compiler,
//     no callable symbol exists in the binary
//   - "luaL_loadbuffer" (0x461190): SecuROM forwarding thunk, not directly
//     callable with normal conventions

// RVAs in Mercenaries2.exe (PE image base 0x00400000). At runtime:
//   target = GetModuleHandleA("Mercenaries2.exe") + RVA
//
// Per-binary tables: the same source-level Lua code lands at different
// absolute addresses depending on the build of Mercenaries2.exe in
// use. We support two known builds and fall through to the prologue
// validator (= bridge stays disabled) on anything else.
//
// To add a new binary:
//   1) run tools/find_lua_print.py and tools/resolve_lua_api.py
//      against that exe to get the new RVAs;
//   2) compute a fingerprint with the same FNV-1a-of-4KB-at-RVA-0x11000
//      formula SelectRvas() uses (one-liner in Python — see comment
//      on SelectRvas);
//   3) add another entry to the switch in SelectRvas.
//
// CA key RVA stays in .rdata and is identical across both known builds
// (byte-for-byte verified), so it's not in the per-binary struct. If a
// future binary moves it, add it.
struct LuaRvaSet {
    const char* label;
    DWORD noop_stub;         // shared no-op stub (print/SendEvent_*/...)
    DWORD luaB_type;
    DWORD luaB_loadstring;
    DWORD luaB_pcall;
    DWORD CreateTextWidget;
    DWORD luaL_register;
};

// v1.1 — the canonical archive.org English retail build. This was the
// first one the bridge was developed against; all the comments below
// referring to "the engine" originally meant this binary.
//
// luaL_register's custom register ABI (ECX = lua_State* L, EAX =
// libname, [esp+4] = table; caller cleans 4 bytes) was determined by
// inspecting its base-lib registration call site at 0x008621B2 and
// string-lib call site at 0x0086579C in this build. Its prologue
// `mov edi,eax; test edi,edi; mov esi,ecx; je no_libname_path` is the
// canonical Lua 5.1 luaL_register source pattern.
static const LuaRvaSet kRvas_v1_1 = {
    "v1.1 (archive.org English retail)",
    0x002AEF90,  // noop_stub        VA 0x006AEF90
    0x00460E90,  // luaB_type        VA 0x00860E90
    0x004611E0,  // luaB_loadstring  VA 0x008611E0  (real __cdecl)
    0x00461810,  // luaB_pcall       VA 0x00861810  (real __cdecl)
    0x001B7D30,  // CreateTextWidget VA 0x005B7D30  (__fastcall engine binding)
    0x0045F720,  // luaL_register    VA 0x0085F720  (custom register ABI)
};

// v1.1 + mercs2-securom-bypass — the cracked retail exe that the
// Mercenaries-Fan-Build framework targets. Same source code, but the
// bypass tool restructured .text: most basic-library functions
// shifted by -0x220, widget bindings shifted by +0x10, and the noop
// stub moved to an entirely new region. .rdata is unchanged (CA key
// still at 0x768378). All addresses below were verified by
// byte-signature match against the original prologues; see commit
// message for the diff data.
static const LuaRvaSet kRvas_v1_1_bypass = {
    "v1.1 + mercs2-securom-bypass (cracked retail)",
    0x002D5640,  // noop_stub        (moved +0x266B0)
    0x00460C70,  // luaB_type        (shifted -0x220)
    0x00460FC0,  // luaB_loadstring  (shifted -0x220)
    0x004615F0,  // luaB_pcall       (shifted -0x220)
    0x001B7D40,  // CreateTextWidget (shifted +0x10)
    0x0045F500,  // luaL_register    (shifted -0x220)
};

// Selected at runtime by SelectRvas(). All hook/executor code reads
// from this pointer rather than hard-coded RVA constants.
static const LuaRvaSet* g_rvas = &kRvas_v1_1;

// FNV-1a 64-bit. Hashes are stable, deterministic, no crypto deps,
// fast enough that fingerprinting at startup is invisible.
static uint64_t Fnv1a64(const void* data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint8_t* b = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        h ^= b[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

// Forward decl — SafeProbe is defined further down with the other
// memory-safety helpers but SelectRvas (right below) needs it.
static bool SafeProbe(const void* p, size_t bytes);

// Fingerprint the loaded Mercenaries2.exe by hashing 4 KB at
// RVA 0x11000 (= .text + 0x10000). Picked because:
//   * it's well inside .text on every binary we've seen
//   * the bypass tool's restructuring affects this region, so the
//     hash discriminates v1.1 vs v1.1+bypass cleanly
//   * 4 KB is large enough that collisions are statistically zero
//   * no user-specific bytes live here
//
// Reproduce the hash for a new binary in Python (see Open questions
// comment at the top of the per-binary tables):
//
//     def fnv1a64(d, h=0xCBF29CE484222325):
//         for b in d: h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
//         return h
//     # read 4096 bytes at file offset = .text_RawData + 0x10000
//     # (compute via PE section headers; for both known builds
//     # .text starts at RVA 0x1000 and is at file offset 0x400)
static const LuaRvaSet* SelectRvas(HMODULE mod) {
    BYTE* base = reinterpret_cast<BYTE*>(mod);
    if (!SafeProbe(base + 0x11000, 0x1000)) {
        Log("[!] LuaBridge: SelectRvas: 4KB at RVA 0x11000 unreadable; "
            "defaulting to v1.1 RVAs.");
        return &kRvas_v1_1;
    }
    uint64_t fp = Fnv1a64(base + 0x11000, 0x1000);
    Log("[*] LuaBridge: binary fingerprint = 0x%016llX", fp);

    switch (fp) {
        case 0xB79E4DD22A4BFCB3ULL:
            Log("[*] LuaBridge: matched %s", kRvas_v1_1.label);
            return &kRvas_v1_1;
        case 0x1942B494FF9F4DB3ULL:
            Log("[*] LuaBridge: matched %s", kRvas_v1_1_bypass.label);
            return &kRvas_v1_1_bypass;
        default:
            Log("[!] LuaBridge: unknown binary (fingerprint not in table). "
                "Falling back to v1.1 RVAs; the prologue validator will "
                "disable any hook whose target bytes don't match. To enable "
                "the bridge on this binary, re-derive RVAs via tools/, add "
                "a new LuaRvaSet to dllmain.cpp, and add this fingerprint "
                "(0x%016llX) to the SelectRvas switch.", fp);
            return &kRvas_v1_1;
    }
}

// Known but unused:
//   RVA 0x468CF0 = luaD_pcall       — internal, custom EAX-first ABI.
//   RVA 0x461190 = SecuROM thunk    — forwarder for some luaL_load* variant.
//   RVA 0x45F2C0 = luaL_where       (NOT lua_settop — that's inlined)
//   RVA 0x46B480 = luaC_step        (NOT lua_tolstring — that's inlined)

// lua_State layout in this Mercenaries 2 build (Pandemic packed
// CommonHeader more tightly than stock Lua 5.1.2). Verified by reading
// luaB_pcall's prologue at RVA 0x461810 — it accesses [L+8] as top and
// [L+0xC] as base inside the inlined luaL_checkany.
static constexpr unsigned LUA_OFF_TOP    = 0x08;
static constexpr unsigned LUA_OFF_BASE   = 0x0C;

// TValue layout: 8 bytes per slot (Value at +0, tt at +4). Pandemic
// compiled this build with `lua_Number = float` (single-precision),
// which collapses the Value union from 8 bytes (stock Lua's double)
// to 4 bytes — the entire TValue then packs into 8 bytes with no
// padding. Verified empirically: in DetourNoopStub's caller frame
// for L=1FEFFE70, saved_top - saved_base = 0x08 (= one arg), and the
// stack memory past our write showed a clear repeating
// `[ptr (4)][tt=5 (4)]` pattern (engine TValues with LUA_TTABLE tags).
// Numbers in this build are float (4 bytes), NOT double — FormatTValue
// reads them as float for that reason.
static constexpr unsigned TVALUE_SIZE      = 0x08;
static constexpr unsigned TVALUE_TT_OFFSET = 0x04;

// Lua 5.1 type tags.
static constexpr int LUA_TNIL      = 0;
static constexpr int LUA_TBOOLEAN  = 1;
static constexpr int LUA_TNUMBER   = 3;
static constexpr int LUA_TSTRING   = 4;
static constexpr int LUA_TTABLE    = 5;
static constexpr int LUA_TFUNCTION = 6;

// luaL_register raw pointer + MinHook trampoline. We hook by ABSOLUTE
// ADDRESS (not via a function-pointer typedef) because the function uses
// a custom register convention that no MSVC declaration syntax expresses.
typedef void (*OpaqueFn)();
static OpaqueFn fpOriginal_luaL_register = nullptr;

// Phase 3 executor: restored after we determined the earlier crashes
// were L-source contamination, not the FixedTString approach itself.
// The executor now runs against an L passed in from the current
// dispatch context (inside DetourLuaType) — guaranteed valid.
static lua_CFunction_t p_luaB_loadstring = nullptr;
static lua_CFunction_t p_luaB_pcall      = nullptr;

// Raw address of luaL_register (custom register ABI: ECX=L, EAX=libname,
// [esp+4]=table, caller cleans 4 bytes). Set in LuaBridgeInitThread
// from g_rvas->luaL_register. Invoked via inline asm in CallLuaLRegister
// below since no standard calling convention matches.
static void* p_luaL_register_raw = nullptr;

// =====================================================================
// Tcp.Send — expose outbound TCP-send to Lua chunks
//
// Registers a single Lua C function as _G.Tcp.Send so chunks running
// through the bridge can talk to other local services (most notably
// the debug-overlay mod on 127.0.0.1:27051). Pattern:
//
//   Tcp.Send("127.0.0.1", 27051, "SET fps 60")
//
// Returns nil on failure (bad args / connect failed), or the number
// of bytes sent on success. Synchronous — blocks for the duration of
// the connect+send. Fast on localhost (microseconds); not designed
// for long-haul or large-payload use.
//
// Lifecycle: registered once per captured L via RegisterTcpLibOnce
// (called from the detour path, where we know we're in a clean
// Lua dispatch context and L is verified valid).
// =====================================================================

static int __cdecl LuaTcpSend(lua_State* L) {
    char* Lc = reinterpret_cast<char*>(L);
    char* base = *reinterpret_cast<char**>(Lc + LUA_OFF_BASE);
    char* top  = *reinterpret_cast<char**>(Lc + LUA_OFF_TOP);

    auto push_nil_and_return_1 = [&]() {
        if (SafeProbe(top, TVALUE_SIZE)) {
            *reinterpret_cast<int*>(top + TVALUE_TT_OFFSET) = LUA_TNIL;
            *reinterpret_cast<char**>(Lc + LUA_OFF_TOP) = top + TVALUE_SIZE;
        }
        return 1;
    };

    // Need at least 3 args: host, port, msg.
    ptrdiff_t nargs_bytes = top - base;
    if (nargs_bytes < 3 * TVALUE_SIZE) return push_nil_and_return_1();

    // Arg 1: host (string)
    int tt0 = *reinterpret_cast<int*>(base + TVALUE_TT_OFFSET);
    if (tt0 != LUA_TSTRING) return push_nil_and_return_1();
    char* gc0 = *reinterpret_cast<char**>(base);
    if (!SafeProbe(gc0, 0x14)) return push_nil_and_return_1();
    uint32_t host_len = *reinterpret_cast<uint32_t*>(gc0 + 0x0C);
    if (host_len == 0 || host_len > 100) return push_nil_and_return_1();
    const char* host_data = gc0 + 0x10;
    if (!SafeProbe(host_data, host_len + 1)) return push_nil_and_return_1();

    // Arg 2: port (number, lua_Number = float in this build)
    int tt1 = *reinterpret_cast<int*>(base + TVALUE_SIZE + TVALUE_TT_OFFSET);
    if (tt1 != LUA_TNUMBER) return push_nil_and_return_1();
    float port_f = *reinterpret_cast<float*>(base + TVALUE_SIZE);
    int port = static_cast<int>(port_f);
    if (port <= 0 || port > 65535) return push_nil_and_return_1();

    // Arg 3: msg (string)
    int tt2 = *reinterpret_cast<int*>(base + 2 * TVALUE_SIZE + TVALUE_TT_OFFSET);
    if (tt2 != LUA_TSTRING) return push_nil_and_return_1();
    char* gc2 = *reinterpret_cast<char**>(base + 2 * TVALUE_SIZE);
    if (!SafeProbe(gc2, 0x14)) return push_nil_and_return_1();
    uint32_t msg_len = *reinterpret_cast<uint32_t*>(gc2 + 0x0C);
    if (msg_len > 64 * 1024) return push_nil_and_return_1();
    const char* msg_data = gc2 + 0x10;
    if (!SafeProbe(msg_data, msg_len + 1)) return push_nil_and_return_1();

    // Copy host into a NUL-terminated buffer for inet_pton / getaddrinfo.
    char host_buf[128];
    memcpy(host_buf, host_data, host_len);
    host_buf[host_len] = '\0';

    // Build outgoing buffer: msg + '\n' so receivers using line-framed
    // protocols (like debug-overlay) get a complete command per Send.
    std::string out;
    out.reserve(msg_len + 1);
    out.append(msg_data, msg_len);
    if (msg_len == 0 || out[out.size() - 1] != '\n') out += '\n';

    int sent_total = 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s != INVALID_SOCKET) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<u_short>(port));
        if (inet_pton(AF_INET, host_buf, &addr.sin_addr) != 1) {
            // Not a dotted-quad — try DNS.
            ADDRINFOA hints{}, *res = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host_buf, nullptr, &hints, &res) == 0 && res) {
                addr.sin_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr;
                freeaddrinfo(res);
            } else {
                closesocket(s);
                return push_nil_and_return_1();
            }
        }
        // Short blocking timeout so a misconfigured host can't hang the
        // game's Lua dispatch.
        DWORD tv_ms = 1500;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            size_t off = 0;
            while (off < out.size()) {
                int n = send(s, out.c_str() + off, static_cast<int>(out.size() - off), 0);
                if (n <= 0) break;
                off += static_cast<size_t>(n);
                sent_total += n;
            }
        }
        closesocket(s);
    }

    // Push (float)sent_total as the single return value.
    if (SafeProbe(top, TVALUE_SIZE)) {
        *reinterpret_cast<float*>(top) = static_cast<float>(sent_total);
        *reinterpret_cast<int*>(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;
        *reinterpret_cast<char**>(Lc + LUA_OFF_TOP) = top + TVALUE_SIZE;
    }
    return 1;
}

// Static luaL_Reg table registered into _G.Tcp.
static const LuaLReg_Entry kTcpLib[] = {
    { "Send", reinterpret_cast<void*>(&LuaTcpSend) },
    { nullptr, nullptr },
};

// Invoke luaL_register with its custom ABI from C++. The standard
// luaL_register signature is `void luaL_register(L, libname, reg)` but
// Pandemic's build expects ECX=L, EAX=libname, [esp+4]=reg, with the
// caller cleaning 4 bytes. MSVC inline asm wraps it cleanly.
static void CallLuaLRegister(void* L, const char* libname, const LuaLReg_Entry* reg) {
    if (!p_luaL_register_raw) return;
    __asm {
        mov ecx, L
        mov eax, libname
        push reg
        call dword ptr [p_luaL_register_raw]
        add esp, 4
    }
}

// Register _G.Tcp = { Send = LuaTcpSend } exactly once per L. The
// engine has two visible Ls (frontend + gameplay); we register on
// each independently so chunks running on either VM can use Tcp.Send.
//
// Must be called from within a known Lua dispatch context (i.e. from
// one of the detours, with arg0 as L) so the register call's stack
// manipulation lands on a sane frame.
static void RegisterTcpLibOnce(void* L) {
    if (!L || !p_luaL_register_raw) return;
    // Per-L dedupe — same shape as CaptureL's seen array.
    static std::atomic<void*> registered_for[8]{};
    for (int i = 0; i < 8; ++i) {
        void* slot = registered_for[i].load(std::memory_order_acquire);
        if (slot == L) return;  // already registered for this L
        if (slot == nullptr) {
            void* expected = nullptr;
            if (registered_for[i].compare_exchange_strong(expected, L)) {
                break;  // we own this slot, proceed
            }
            // CAS lost — re-check this slot or move on
            if (registered_for[i].load(std::memory_order_acquire) == L) return;
        }
    }
    // CallLuaLRegister manipulates L's stack; do it under the same
    // re-entry guard as the executor so a fired pump detour can't
    // race into us.
    if (g_inBridgeExec) return;
    g_inBridgeExec = true;
    CallLuaLRegister(L, "Tcp", kTcpLib);
    g_inBridgeExec = false;
    Log("[+] Tcp.Send registered into _G.Tcp on L=%p", L);
}

// Byte-crafted TString to push the chunk source onto L's stack without
// calling lua_pushstring (which is inlined in this build). Layout
// matches stock Lua 5.1.2 (sizeof(TString) = 16 bytes, data follows).
//   +0x00 GCObject *next       (null — not in GC chain)
//   +0x04 lu_byte tt           (= LUA_TSTRING = 4)
//   +0x05 lu_byte marked       (FIXEDBIT|WHITE0 = 0x21 — GC will skip it)
//   +0x06 lu_byte reserved     (0)
//   +0x07 1 byte padding
//   +0x08 unsigned int hash    (any non-zero)
//   +0x0C size_t len           (length, no NUL)
//   +0x10 char data[]          (string + NUL)
#pragma pack(push, 4)
struct FixedTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    // 1 MB. The original 4 KB sized for the early `return 1+1` probes,
    // but as the engine API got mapped out, real modder scripts (whole
    // gamemode scaffolds, the recursive globals walker, multi-thousand-
    // line probes) started bumping the cap. 1 MB is plenty for any
    // hand-written Lua a human is going to push through this bridge —
    // larger than anything in tools/ today by ~3 orders of magnitude.
    // Costs are one-time: the buffer is a static global in .bss, so it
    // doesn't grow the DLL on disk; at runtime it's a single 1 MB page
    // group reserved at process start.
    char     data[1048576];
};
#pragma pack(pop)
static FixedTString g_chunkSource;

static void InitChunkSource() {
    memset(&g_chunkSource, 0, sizeof(g_chunkSource));
    g_chunkSource.tt     = (uint8_t)LUA_TSTRING;
    g_chunkSource.marked = 0x20 | 0x01;  // FIXEDBIT | WHITE0BIT
    g_chunkSource.hash   = 0xDEADBEEF;
}

static lua_CFunction_t      fpOriginal_NoopStub = nullptr;
static lua_CFunction_t      fpOriginal_luaB_type = nullptr; // Core Lua
static pandemic_CFunction_t fpOriginal_CreateTextWidget = nullptr; // Pandemic Engine

static std::atomic<lua_State*> g_LuaState{ nullptr };
static std::mutex g_inMtx;
static std::deque<std::string> g_inQueue;
static std::mutex g_outMtx;
static std::string g_outBuf;
static std::atomic<int> g_PendingScripts{ 0 }; // Atomic Counter for queue bypass

// Prevents the executor from recursing into itself if a capture detour
// happens to fire mid-LuaDoString. Thread-local so the engine's own
// recursive Lua calls are unaffected.
static thread_local bool g_inBridgeExec = false;

static void OutAppend(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_outMtx);
    g_outBuf += s;
    g_outBuf += "\n";
}

// Returns true iff `bytes` starting at `p` are readable. Implemented via
// VirtualQuery rather than SEH around a raw deref so we don't generate
// (immediately-handled) access violations on every bad noop-stub capture
// — dxwrapper's exception logger doesn't distinguish "raised and caught"
// from "raised and unhandled" and was emitting 90k+ entries per session.
static bool SafeProbe(const void* p, size_t bytes) {
    if (!p || reinterpret_cast<uintptr_t>(p) < 0x10000) return false;
    constexpr DWORD kReadable =
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    constexpr DWORD kUnreadable = PAGE_NOACCESS | PAGE_GUARD;

    const char* addr = static_cast<const char*>(p);
    const char* end  = addr + bytes;
    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & kUnreadable) return false;
        if (!(mbi.Protect & kReadable)) return false;
        addr = static_cast<const char*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return true;
}

// Cheap but specific identity check on a candidate lua_State pointer.
//
// The noop-stub hook fires from BOTH Lua dispatch (arg0 = real L) AND
// C++ engine code that calls the stub under one of its many other
// registered names (arg0 = some unrelated `this`). Earlier versions
// only did structural checks (top/base look like aligned pointers,
// l_G non-null) which let C++ objects through whenever their layout
// happened to match — that's what caused rebuild #5's framerate tank
// (five false captures of music-system pointers) and the CTD when the
// executor direct-wrote into one of them.
//
// The strong check: a real lua_State is itself a GCObject; its
// CommonHeader.tt at offset +4 is LUA_TTHREAD = 8. Random C++
// objects won't have exactly 8 at offset +4.
static bool LooksLikeLuaState(void* L) {
    if (!SafeProbe(L, 0x18)) return false;

    // Strong identity check first (one byte read, zero syscalls).
    // LUA_TTHREAD = 8 is the type tag Lua puts in every lua_State's
    // CommonHeader when luaE_newthread initializes it.
    uint8_t L_tt = *reinterpret_cast<uint8_t*>(static_cast<char*>(L) + 4);
    if (L_tt != 8 /* LUA_TTHREAD */) return false;

    // Structural cross-check on top/base/l_G as belt-and-braces.
    void* top  = *reinterpret_cast<void**>(static_cast<char*>(L) + LUA_OFF_TOP);
    void* base = *reinterpret_cast<void**>(static_cast<char*>(L) + LUA_OFF_BASE);
    void* l_G  = *reinterpret_cast<void**>(static_cast<char*>(L) + 0x10);  // global_State*

    if (!SafeProbe(base, 16) || !SafeProbe(top, 4) || !SafeProbe(l_G, 4)) return false;

    auto t = reinterpret_cast<uintptr_t>(top);
    auto b = reinterpret_cast<uintptr_t>(base);
    if ((t | b) & 0x3) return false;
    if (t < b) return false;
    if (t - b > 0x10000) return false;
    return true;
}

// SEH-wrapped invocation of a real __cdecl lua_CFunction. In its own
// function because MSVC forbids __try inside any function with C++
// destructors (LuaDoString has std::string locals).
static int SafeCallLuaCFunction(lua_CFunction_t fn, void* L) {
    __try {
        return fn(static_cast<lua_State*>(L));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}

// Hex-dump up to 64 bytes of `p` into a fixed string for Log().
// Returns "<unreadable>" if SafeProbe fails. Caps output at the first
// 64 bytes (anything past that gets the "..." marker).
static std::string HexDump(const void* p, size_t bytes) {
    if (bytes > 64) bytes = 64;
    if (!SafeProbe(p, bytes)) return "<unreadable>";
    const uint8_t* b = static_cast<const uint8_t*>(p);
    std::string out;
    char tmp[8];
    for (size_t i = 0; i < bytes; ++i) {
        _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                    (i % 4 == 3 && i + 1 < bytes) ? "%02x " : "%02x", b[i]);
        out += tmp;
    }
    return out;
}

// Format a TValue at `slot` as a human-readable string for the REPL.
// Only safe to call on slots inside [base, top) of a validated L.
static std::string FormatTValue(const char* slot) {
    int tt = *reinterpret_cast<const int*>(slot + TVALUE_TT_OFFSET);
    switch (tt) {
        case LUA_TNIL:     return "nil";
        case LUA_TBOOLEAN: return *reinterpret_cast<const int*>(slot) ? "true" : "false";
        case LUA_TNUMBER: {
            // lua_Number = float in this build (see TVALUE_SIZE
            // comment). A double read here would walk past the slot
            // into the next TValue and print garbage.
            float n = *reinterpret_cast<const float*>(slot);
            char b[64]; _snprintf_s(b, sizeof(b), _TRUNCATE, "%g", static_cast<double>(n));
            return b;
        }
        case LUA_TSTRING: {
            // Value.gc points to a TString. Engine TStrings match stock
            // layout (we confirmed via DetourLuaType's reference dump):
            // 16-byte header with len at +0x0C, data at +0x10.
            void* gc = *reinterpret_cast<void* const*>(slot);
            if (!SafeProbe(gc, 0x14)) return "<string: gc unreadable>";
            uint32_t len = *reinterpret_cast<uint32_t*>(static_cast<char*>(gc) + 0x0C);
            // Sanity cap: 16 MB. Anything past that is almost certainly
            // a bad TString pointer, not a real string. The walker
            // dumps can easily exceed 100 KB so the old 4 KB cap was
            // wrong — it kept turning real results into
            // "<string: implausible>" diagnostics.
            if (len > (16u * 1024u * 1024u)) {
                char b[96]; _snprintf_s(b, sizeof(b), _TRUNCATE,
                    "<string: implausible len=%u>", len);
                return b;
            }
            const char* data = static_cast<const char*>(gc) + 0x10;
            if (!SafeProbe(data, len + 1)) return "<string: data unreadable>";
            std::string out;
            out.reserve(len + 2);
            out += '"';
            out.append(data, len);
            out += '"';
            return out;
        }
        case LUA_TTABLE:    return "<table>";
        case LUA_TFUNCTION: return "<function>";
        default: {
            char b[64]; void* v = *reinterpret_cast<void* const*>(slot);
            _snprintf_s(b, sizeof(b), _TRUNCATE, "<tt=%d val=%p>", tt, v);
            return b;
        }
    }
}

// luaL_Reg layout used by Lua 5.1 — pairs of {name, fn} terminated by
// {NULL, NULL}. Pandemic almost certainly uses this stock shape.
struct LuaLReg_Entry {
    const char* name;
    void*       func;
};

// ====================================================================
// Registration-table hijack (Phase 3.1)
//
// When the engine calls luaL_register(L, NULL, _G_table), we walk the
// table BEFORE forwarding to the real luaL_register and swap specific
// entries' .func pointers to our own detours. The engine then
// registers OUR function under those names, so any Lua script calling
// e.g. `print(x)` resolves to our detour. arg0 is guaranteed to be a
// real lua_State because Lua's dispatcher just called us.
//
// This is the "patched registration table for printf and print"
// technique another modder used successfully to inject Lua execution
// into this game. It works where the MinHook+validation approach was
// firing too rarely (the engine in idle states almost never calls into
// the noop-stub from Lua context — but registered Lua functions ARE
// called regularly by script update loops).
//
// The table lives in .rdata, so we use VirtualProtect to make it
// writable for the swap. We patch idempotently: if the entry is
// already our function, skip.
// ====================================================================

static lua_CFunction_t fpOriginalPrint    = nullptr;
static lua_CFunction_t fpOriginalNext     = nullptr;
static lua_CFunction_t fpOriginalToString = nullptr;

// Forward decl — PumpQueue is defined further down with the detour
// helpers but the hijacks (right below) need to call it.
static void PumpQueue(void* L_for_exec);

// Hijacked Lua basic-library entries: fire on any script call, drain
// the queue if there's pending work, then forward to the original.
// L is guaranteed valid here — Lua's dispatcher gave it to us, so we
// skip LooksLikeLuaState's VirtualQuery cost.
//
// `print` is a noop in production (the engine's print resolves to the
// shared no-op stub at 0x6AEF90) so we don't need to preserve its
// arg. `next` and `tostring` are REAL functions — we MUST forward
// with L intact so their arg/result handling stays correct. Lua C
// functions read their args from L->base[0..]; we don't touch L
// before the forward, so this is automatic.
//
// Why three pump sources instead of one: `print` is rarely called by
// release-build scripts (devs strip prints from gameplay/menu code).
// `next` fires on every `pairs`/`ipairs` iteration step. `tostring`
// fires on most string formatting. Between them, any non-trivial UI
// frame update will trigger a pump within milliseconds of a queued
// chunk arriving.
// Per-detour diagnostic. Logs the very first invocation (so we can
// tell which detours are ever called by the engine) and a throttled
// sample of pump-attempts when there's work pending (so we can see
// why a queued chunk isn't draining). Throttling keeps the log usable
// — even with pending>0, next/tostring can fire thousands of times
// per second in active gameplay.
static void DetourDiag(const char* name, void* L_arg0,
                       std::atomic_bool& first_seen) {
    if (!first_seen.exchange(true, std::memory_order_relaxed)) {
        Log("[diag] %s: first invocation observed (L=%p)", name, L_arg0);
    }
    int pending = g_PendingScripts.load(std::memory_order_acquire);
    if (pending == 0) return;
    // First 8 attempts always; after that, every 4096th. Previous tuning
    // (every 256th) generated hundreds of log lines for a single
    // in-game chunk because DetourNoopStub fires very frequently with
    // C++ this-pointers that fail validation — useful to know once,
    // not useful to spam.
    static std::atomic<unsigned> attempts{0};
    unsigned c = attempts.fetch_add(1, std::memory_order_relaxed);
    if (c < 8 || (c & 0xfff) == 0) {
        bool valid = LooksLikeLuaState(L_arg0);
        Log("[diag] pump-attempt #%u via=%s L=%p pending=%d valid=%d",
            c, name, L_arg0, pending, (int)valid);
    }
}

static int __cdecl HijackedPrint(lua_State* L) {
    static std::atomic_bool seen{false};
    DetourDiag("HijackedPrint", L, seen);
    if (g_PendingScripts.load(std::memory_order_acquire) > 0 && !g_inBridgeExec) {
        PumpQueue(L);
    }
    return fpOriginalPrint ? fpOriginalPrint(L) : 0;
}
static int __cdecl HijackedNext(lua_State* L) {
    static std::atomic_bool seen{false};
    DetourDiag("HijackedNext", L, seen);
    if (g_PendingScripts.load(std::memory_order_acquire) > 0 && !g_inBridgeExec) {
        PumpQueue(L);
    }
    return fpOriginalNext ? fpOriginalNext(L) : 0;
}
static int __cdecl HijackedToString(lua_State* L) {
    static std::atomic_bool seen{false};
    DetourDiag("HijackedToString", L, seen);
    if (g_PendingScripts.load(std::memory_order_acquire) > 0 && !g_inBridgeExec) {
        PumpQueue(L);
    }
    return fpOriginalToString ? fpOriginalToString(L) : 0;
}

// Walk `table` looking for `name`. If found, save the current .func
// pointer to *out_original (first time only — subsequent VMs re-see the
// same already-patched table) and swap to our_fn. Idempotent.
static bool PatchTableEntry(LuaLReg_Entry* table, const char* name,
                            void* our_fn, lua_CFunction_t* out_original) {
    for (int i = 0; i < 500; ++i) {
        if (!SafeProbe(&table[i], sizeof(LuaLReg_Entry))) return false;
        if (!table[i].name) return false;
        if (!SafeProbe(table[i].name, 1)) return false;
        if (strcmp(table[i].name, name) != 0) continue;

        // Already patched? skip.
        if (table[i].func == our_fn) return true;

        // First-time observation: remember the real original.
        if (*out_original == nullptr) {
            *out_original = reinterpret_cast<lua_CFunction_t>(table[i].func);
        }

        // VirtualProtect-around-write because .rdata is read-only.
        DWORD oldProtect = 0;
        if (!VirtualProtect(&table[i].func, sizeof(void*), PAGE_READWRITE, &oldProtect)) {
            Log("[reg] PatchTableEntry: VirtualProtect(RW) failed for %s, GLE=%lu",
                name, GetLastError());
            return false;
        }
        table[i].func = our_fn;
        DWORD tmp = 0;
        VirtualProtect(&table[i].func, sizeof(void*), oldProtect, &tmp);

        Log("[reg] HIJACKED %s: original=%p -> %p (ours)",
            name, *out_original, our_fn);
        return true;
    }
    return false;
}

// Forward decl — CaptureL is defined further down with the other detour
// helpers but OnLuaRegisterCalled (right below) needs to call it.
static void CaptureL(lua_State* L, const char* via);

// Called from DetourLuaLRegister (below) on every luaL_register call.
// Captures L authoritatively (no validation guessing) and dumps every
// {name, fn} pair to Merc2Debug.log so we have a complete map of the
// engine's Lua API surface.
//
// Cap output at 500 entries per table and 60 tables per session so a
// single broken table can't blow up the log.
static std::atomic<int> g_regTableCount{ 0 };

static void __cdecl OnLuaRegisterCalled(void* L, const char* libname, const LuaLReg_Entry* table) {
    if (!L) return;
    if (!LooksLikeLuaState(L)) {
        Log("[reg] luaL_register fired but L=%p failed validation — skipping", L);
        return;
    }
    CaptureL(static_cast<lua_State*>(L), "luaL_register");

    // === HIJACK PHASE ===
    // Patch table entries BEFORE forwarding to the real luaL_register
    // so the engine registers OUR functions instead of the originals.
    // We want the _G registration (where the basic-lib entries live).
    // In Lua 5.1's stock lbaselib.c the basic library is registered as
    // `luaL_register(L, "_G", base_funcs)` — the literal string "_G",
    // NOT NULL. (Mercenaries 2 confirms: Merc2Debug.log line 16 shows
    // `[reg] #0 === lib="_G" ...`.) We tolerate NULL too in case a
    // future engine variant uses it.
    bool is_global = !libname || strcmp(libname, "_G") == 0;
    if (table && is_global) {
        LuaLReg_Entry* mut = const_cast<LuaLReg_Entry*>(table);
        PatchTableEntry(mut, "print",    (void*)&HijackedPrint,    &fpOriginalPrint);
        PatchTableEntry(mut, "next",     (void*)&HijackedNext,     &fpOriginalNext);
        PatchTableEntry(mut, "tostring", (void*)&HijackedToString, &fpOriginalToString);
    }

    // === LOG/DUMP PHASE ===
    int idx = g_regTableCount.fetch_add(1, std::memory_order_relaxed);
    if (idx >= 60) return;
    if (!table || !SafeProbe(table, sizeof(LuaLReg_Entry))) {
        Log("[reg] #%d lib=\"%s\" table=%p (unreadable)",
            idx, libname ? libname : "<global>", table);
        return;
    }
    Log("[reg] #%d === lib=\"%s\" table=%p ===",
        idx, libname ? libname : "<global>", table);

    int count = 0;
    for (int i = 0; i < 500; ++i) {
        const LuaLReg_Entry* e = &table[i];
        if (!SafeProbe(e, sizeof(LuaLReg_Entry))) break;
        if (!e->name) break;  // terminator
        if (!SafeProbe(e->name, 1)) {
            Log("[reg]   #%d name@%p unreadable, stopping", i, e->name);
            break;
        }
        Log("[reg]   %-40s -> %p", e->name, e->func);
        count++;
    }
    Log("[reg] (%d entries in lib=\"%s\")", count, libname ? libname : "<global>");
}

// Naked detour for luaL_register at RVA 0x45F720.
// On entry: ECX=L, EAX=libname, [esp+4]=table, [esp+0]=return_addr.
// We snapshot the args, call OnLuaRegisterCalled (cdecl), restore the
// original register/stack state, then tail-jmp to MinHook's trampoline
// so the engine's real luaL_register runs unchanged.
__declspec(naked) static void DetourLuaLRegister() {
    __asm {
        // Save volatile registers we'll trash. EDX is volatile in any
        // calling convention so preserving it is paranoia-safe. EAX and
        // ECX hold our input args; we need both at the end to forward
        // to the trampoline.
        push edx
        push eax       ; libname (saved)
        push ecx       ; L (saved)
        // Stack layout now:
        //   [esp+0x00] = ecx (L)
        //   [esp+0x04] = eax (libname)
        //   [esp+0x08] = edx
        //   [esp+0x0C] = return_addr
        //   [esp+0x10] = table (original stack arg)

        // Push cdecl args for OnLuaRegisterCalled(L, libname, table)
        // in reverse order.
        push dword ptr [esp + 0x10]  ; table
        push dword ptr [esp + 0x08]  ; libname (was at +4, now +8 after table push)
        push dword ptr [esp + 0x08]  ; L (was at +0, now +8 after two pushes)
        call OnLuaRegisterCalled
        add esp, 12                  ; clean cdecl args

        // Restore originals (reverse of save order).
        pop ecx       ; L back into ECX
        pop eax       ; libname back into EAX
        pop edx       ; EDX back

        // Stack now back to original entry state:
        //   [esp+0] = return_addr
        //   [esp+4] = table
        // ECX=L, EAX=libname. Tail-jmp to MinHook trampoline.
        jmp dword ptr [fpOriginal_luaL_register]
    }
}

// Phase 3 executor.
//
// Called from inside a real lua_CFunction detour (DetourLuaType,
// HijackedPrint). Builds a NEW Lua frame on top of the engine's active
// frame instead of stomping it.
//
// Why this matters: when DetourLuaType fires, the engine is in the
// middle of dispatching a script's `type(x)` call. The call's args
// occupy [L->base, L->top). The previous implementation did
// `*L->top = L->base` and wrote our chunk source at L->base[0], which
// clobbered `x`. When we then passed through to the real luaB_type, it
// read garbage as its argument. Same issue inside HijackedPrint.
//
// Fix: treat the executor invocation as a nested call.
//   new_base = saved_top  (= the first free slot above the active frame)
//   push chunk at new_base, run, read results
//   restore L->base / L->top to their saved values on the way out
//
// Lua's GC will see our FixedTString while it's reachable on the stack,
// but the FIXEDBIT in g_chunkSource.marked tells the collector to skip
// it (no premature free, no double free). Any TValues the user's chunk
// returns live in slots [new_base..new_top); we format them with
// FormatTValue before restoring L->top, so they don't need to survive
// past the restore.
//
// We do NOT explicitly luaG_checkstack — the executor only pushes ~3
// scratch slots beyond saved_top before pcall, and pcall itself
// reserves whatever the user's chunk asks for via the normal Lua stack
// growth path. If saved_top is somehow already at L->stack_last we'll
// trip SafeProbe and bail out cleanly.
static std::string LuaDoString(void* L, const char* code) {
    if (!L) return "[bridge] no L";
    if (!LooksLikeLuaState(L)) return "[bridge] L failed validation";
    if (!p_luaB_loadstring || !p_luaB_pcall) {
        return "[bridge] Phase 3 fn pointers not resolved";
    }

    size_t code_len = strlen(code);
    if (code_len == 0) return "[bridge] empty chunk";
    if (code_len >= sizeof(g_chunkSource.data)) return "[bridge] chunk too large";

    char* Lc = static_cast<char*>(L);
    void** top_ptr  = reinterpret_cast<void**>(Lc + LUA_OFF_TOP);
    void** base_ptr = reinterpret_cast<void**>(Lc + LUA_OFF_BASE);
    void* saved_top  = *top_ptr;
    void* saved_base = *base_ptr;

    char* new_base = static_cast<char*>(saved_top);

    // Need room for our chunk slot plus pcall's [chunk, fn] working set
    // (worst case 3 slots if loadstring fails with [chunk, nil, err]).
    if (!SafeProbe(new_base, 3 * TVALUE_SIZE)) {
        return "[bridge] L->top + scratch unwritable";
    }

    // 1. Load chunk source into FixedTString.
    memcpy(g_chunkSource.data, code, code_len);
    g_chunkSource.data[code_len] = '\0';
    g_chunkSource.len = static_cast<uint32_t>(code_len);

    // 2. Push the TString TValue at new_base and adopt the new frame.
    *reinterpret_cast<void**>(new_base) = &g_chunkSource;
    *reinterpret_cast<int*>(new_base + TVALUE_TT_OFFSET) = LUA_TSTRING;
    *base_ptr = new_base;
    *top_ptr  = new_base + TVALUE_SIZE;

    auto restore = [&]() {
        *top_ptr  = saved_top;
        *base_ptr = saved_base;
    };

    // One-shot pre-call diagnostic. Dumps L state + our constructed
    // TValue at new_base + our FixedTString header so we can diff
    // against the engine reference dumped by DetourLuaType. If any
    // bytes look wrong here, that's why luaB_loadstring crashes.
    static std::atomic_bool dumped_our_string{false};
    if (!dumped_our_string.exchange(true, std::memory_order_acq_rel)) {
        Log("[diag] LuaDoString: L=%p saved_base=%p saved_top=%p new_base=%p ci@L+0x10=%p",
            L, saved_base, saved_top, new_base,
            *reinterpret_cast<void**>(Lc + 0x10));
        Log("[diag] L bytes@%p (32 bytes): %s", L, HexDump(L, 32).c_str());
        Log("[diag] our TValue@%p (32 bytes): %s", new_base, HexDump(new_base, 32).c_str());
        Log("[diag] our TString@%p (32 bytes): %s", &g_chunkSource, HexDump(&g_chunkSource, 32).c_str());
        Log("[diag] chunk source: \"%s\" (len=%u)", g_chunkSource.data, g_chunkSource.len);
    }

    // 3. luaB_loadstring (real __cdecl). Reads chunk at index 1. On
    // success leaves [chunk, fn]; on compile error leaves [chunk, nil, err].
    int load_n = SafeCallLuaCFunction(p_luaB_loadstring, L);
    if (load_n < 0) {
        restore();
        return "[bridge] luaB_loadstring crashed";
    }
    if (load_n == 2) {
        char* err_slot = new_base + 2 * TVALUE_SIZE;
        std::string err = FormatTValue(err_slot);
        restore();
        return "[compile] " + err;
    }
    if (load_n != 1) {
        restore();
        return "[bridge] loadstring returned unexpected " + std::to_string(load_n);
    }

    // 4. Success: stack is [chunk, fn] starting at new_base. For pcall
    // we need [fn] at index 1 — compact by sliding fn down over chunk
    // (what Lua's own dispatch poscall would have done).
    char* top_slot = static_cast<char*>(*top_ptr) - TVALUE_SIZE;
    int compiled_tt = *reinterpret_cast<int*>(top_slot + TVALUE_TT_OFFSET);
    if (compiled_tt != LUA_TFUNCTION) {
        restore();
        return "[bridge] loadstring result not a function (tt=" +
               std::to_string(compiled_tt) + ")";
    }
    if (top_slot != new_base) {
        memcpy(new_base, top_slot, TVALUE_SIZE);
    }
    *top_ptr = new_base + TVALUE_SIZE;

    // 5. luaB_pcall (real __cdecl). Reads fn at index 1, leaves
    // [bool_status, results...] starting at new_base.
    int pcall_n = SafeCallLuaCFunction(p_luaB_pcall, L);
    if (pcall_n < 0) {
        restore();
        return "[bridge] luaB_pcall crashed";
    }

    // 6. Format results.
    ptrdiff_t after_exec = static_cast<char*>(*top_ptr) - new_base;
    int result_slots = static_cast<int>(after_exec / TVALUE_SIZE);
    if (result_slots > 16) result_slots = 16;

    // One-shot post-pcall diagnostic so we can verify what Pandemic's
    // luaB_pcall actually leaves on the stack. Empirically the first
    // attempt produced "[runtime] 2" for `return 1+1`, which means
    // base[0].tt was NOT LUA_TBOOLEAN. This dump shows it.
    static std::atomic_bool dumped_post_pcall{false};
    if (!dumped_post_pcall.exchange(true, std::memory_order_acq_rel)) {
        Log("[diag] post-pcall: pcall_n=%d result_slots=%d top=%p new_base=%p",
            pcall_n, result_slots, *top_ptr, new_base);
        Log("[diag] post-pcall stack@%p (32 bytes): %s",
            new_base, HexDump(new_base, 32).c_str());
    }

    // Detect pcall status. Stock Lua 5.1 pushes a boolean; Pandemic's
    // build appears to push a Lua number (consistent with their
    // lua_Number=float compilation — they may have done
    // `lua_pushnumber(L, status==0)` instead of `lua_pushboolean`).
    // Accept both so the label is right regardless.
    bool succeeded = false;
    bool have_status = false;
    if (result_slots >= 1) {
        int tt0 = *reinterpret_cast<int*>(new_base + TVALUE_TT_OFFSET);
        if (tt0 == LUA_TBOOLEAN) {
            have_status = true;
            succeeded = (*reinterpret_cast<int*>(new_base) != 0);
        } else if (tt0 == LUA_TNUMBER) {
            have_status = true;
            succeeded = (*reinterpret_cast<const float*>(new_base) != 0.0f);
        }
    }

    // If pcall pushed a status slot, results start at index 1.
    // Otherwise treat everything as a result.
    int first_result = have_status ? 1 : 0;
    std::string out = succeeded ? "[ok]" : "[runtime]";
    for (int i = first_result; i < result_slots; ++i) {
        char* rslot = new_base + i * TVALUE_SIZE;
        out += (succeeded ? "\t" : " ") + FormatTValue(rslot);
    }

    restore();
    return out;
}

// PumpQueue takes the L from the CURRENT dispatch context. Critical:
// LuaDoString MUST run against a valid L, and the only way to know an L
// is valid is to have it handed to us by the engine inside a real
// lua_CFunction call. We don't read g_LuaState here — that's a global
// that can drift between VMs.
//
// `L_for_exec` may be null when called from a detour that doesn't
// capture (noop-stub, CreateTextWidget). In that case we still pop the
// queue (to avoid accumulating chunks forever if no real Lua call is
// happening), but we just return a no-L diagnostic.
static void PumpQueue(void* L_for_exec) {
    if (g_PendingScripts.load(std::memory_order_acquire) == 0) return;
    if (g_inBridgeExec) return;
    for (;;) {
        std::string code;
        {
            std::lock_guard<std::mutex> lk(g_inMtx);
            if (g_inQueue.empty()) return;
            code = std::move(g_inQueue.front());
            g_inQueue.pop_front();
            g_PendingScripts.fetch_sub(1, std::memory_order_relaxed);
        }

        g_inBridgeExec = true;
        std::string result;
        if (L_for_exec && LooksLikeLuaState(L_for_exec)) {
            result = LuaDoString(L_for_exec, code.c_str());
        }
        else {
            result = "[bridge] pump fired without a valid L — chunk dropped. "
                     "Make sure type() or another real Lua C function is firing.";
        }
        g_inBridgeExec = false;

        Log("[+] Script Executed. Result: %s", result.c_str());
        OutAppend(result + "\n<<<END>>>");
    }
}

static void CaptureL(lua_State* L, const char* via) {
    if (!L) return;

    // Fast path: in steady state the same VM's L gets re-captured on
    // every detour fire. Skip validation and the store when nothing
    // would change.
    lua_State* current = g_LuaState.load(std::memory_order_acquire);
    if (current == L) return;

    // Slow path: structurally validate before storing. The noop-stub
    // hook fires with arg0=L from Lua dispatch, but with arg0=some C++
    // `this` from the engine's other aliases (music/event/cinematic
    // stubs). Without this filter we'd store a music-system pointer
    // as g_LuaState and crash on the first deref.
    if (!LooksLikeLuaState(L)) {
        static thread_local int rejects[4] = { 0 };
        int bucket =
            (via && via[0] == 'n') ? 0 :      // noop-stub
            (via && via[0] == 't') ? 1 :      // type
            (via && via[0] == 'C') ? 2 : 3;   // CreateTextWidget / other
        if (rejects[bucket]++ < 3) {
            Log("[!] CaptureL: rejected non-lua_State from %s: arg0=%p (tid=%lu)",
                via, L, GetCurrentThreadId());
        }
        return;
    }

    g_LuaState.store(L, std::memory_order_release);

    // Log only when we first acquire an L (current was null), and once
    // per distinct L we ever see. The engine runs multiple VMs on the
    // same main thread (frontend ~ 0x2006FD20, gameplay ~ 0x1FEFFE70 in
    // the last build) and each calls `type()` constantly inside its own
    // update loop, so g_LuaState legitimately flips ~hundreds of times
    // per second. Logging every flip filled Merc2Debug.log with 90k+
    // identical "shifted" lines per session and buried real signal.
    //
    // Tracking up to 8 unique Ls is enough for any sane game state
    // (frontend + gameplay + a handful of coroutines). Beyond that we
    // just silently swap — the executor only cares about the most
    // recently stored L anyway.
    static std::atomic<lua_State*> seen[8]{};
    bool new_to_us = true;
    for (int i = 0; i < 8; ++i) {
        lua_State* s = seen[i].load(std::memory_order_relaxed);
        if (s == L) { new_to_us = false; break; }
        if (s == nullptr) {
            lua_State* expected = nullptr;
            if (seen[i].compare_exchange_strong(expected, L)) break;
            // someone else claimed this slot; keep looking
        }
    }
    if (new_to_us) {
        Log("[+] Lua VM captured via %s: L=%p (tid=%lu) %s",
            via, L, GetCurrentThreadId(),
            current == nullptr ? "(first capture)" : "(new VM — flips silently from here)");
    }
}

// NOTE: the previous `DetourLuaSettop` was hooking RVA 0x45F2C0, which we
// now know is `luaL_where`, not `lua_settop`. We've removed that hook —
// `luaL_where` only fires from error paths and is a poor pump source.
// The noop-stub + luaB_type + CreateTextWidget trio gives us enough
// capture/pump frequency for Phase 1 diagnostics. Phase 2 may add more
// per-frame engine bindings (MinimapUpdate / InterpolateWidget).

// Noop-stub detour: pump only, no capture.
//
// The noop-stub at RVA 0x2AEF90 is registered under MANY names — `print`,
// SendEvent_*, music stubs, _SummonEd, etc. Engine C++ code calls these
// aliases very frequently with arbitrary `this` pointers in arg0, so
// per-call CaptureL means per-call LooksLikeLuaState, which means a
// per-call VirtualQuery syscall — that's what was tanking the framerate.
//
// luaL_register already gives us the authoritative L at VM init, and
// luaB_type (below) is a real Lua-only fn that re-captures cheaply.
// We don't need this detour to capture; it exists only as a pump source.
// Common gated-pump helper. Called from every detour with the detour's
// own arg0. Steady state: one atomic load + early return — essentially
// free. When a chunk is pending, validates L and pumps only if L is a
// real lua_State (per LooksLikeLuaState's tt-check + structural probe).
//
// This is the equivalent of the Reddit user's "patched registration
// table for print" technique — we intercept any noop-stub-bound call
// from Lua context (print, Debug.Printf, and dozens of others all
// resolve to the same stub address), pay the validation cost only when
// we have work, and skip cleanly on C++-context calls that happen to
// route through the same address with a `this` in arg0.
static inline void GatedPump(void* L_arg0) {
    if (g_PendingScripts.load(std::memory_order_acquire) == 0) return;
    if (g_inBridgeExec) return;
    if (!LooksLikeLuaState(L_arg0)) return;
    PumpQueue(L_arg0);
}

static int __cdecl DetourNoopStub(lua_State* L) {
    // print(), Debug.Printf(), and ~60 other registered-but-stripped
    // names all route here. When called from Lua, arg0 = real L. When
    // called from C++ engine code (the music/event stubs), arg0 = some
    // `this`. GatedPump distinguishes via LooksLikeLuaState.
    static std::atomic_bool seen{false};
    DetourDiag("DetourNoopStub", L, seen);
    GatedPump(L);
    return fpOriginal_NoopStub ? fpOriginal_NoopStub(L) : 0;
}

// luaB_type detour: arg0 is always a real lua_State (Lua dispatcher).
// Cheap to capture from too because CaptureL's fast path skips after the
// first observation per VM.
static int __cdecl DetourLuaType(lua_State* L) {
    static std::atomic_bool seen{false};
    DetourDiag("DetourLuaType", L, seen);
    CaptureL(L, "type");
    /* Lua dispatch gave us L → safe to invoke luaL_register here.
     * Per-L dedupe inside the call, so this is essentially free
     * after the first observation. */
    RegisterTcpLibOnce(L);

    // One-shot: when type() is called with a string arg, dump the
    // engine's TValue + the TString it points to. Gives us a verified
    // reference layout to compare LuaDoString's FixedTString writes
    // against. If those bytes don't match what we construct, the layout
    // assumption is wrong and that's why luaB_loadstring crashes.
    static std::atomic_bool dumped_engine_string{false};
    if (L && !dumped_engine_string.load(std::memory_order_acquire)) {
        char* Lc = reinterpret_cast<char*>(L);
        if (SafeProbe(Lc, 0x18)) {
            void* base = *reinterpret_cast<void**>(Lc + LUA_OFF_BASE);
            void* top  = *reinterpret_cast<void**>(Lc + LUA_OFF_TOP);
            if (SafeProbe(base, TVALUE_SIZE) && top > base) {
                int tt = *reinterpret_cast<int*>(static_cast<char*>(base) + TVALUE_TT_OFFSET);
                if (tt == LUA_TSTRING) {
                    void* gc = *reinterpret_cast<void**>(base);
                    if (SafeProbe(gc, 0x20)) {
                        if (!dumped_engine_string.exchange(true, std::memory_order_acq_rel)) {
                            Log("[diag] engine TValue@%p (32 bytes): %s",
                                base, HexDump(base, 32).c_str());
                            Log("[diag] engine TString@%p (32 bytes): %s",
                                gc, HexDump(gc, 32).c_str());
                            uint32_t len = *reinterpret_cast<uint32_t*>(static_cast<char*>(gc) + 0x0C);
                            Log("[diag] engine TString interpreted: len@+0xC=%u tt@+4=%02x marked@+5=%02x",
                                len,
                                *reinterpret_cast<uint8_t*>(static_cast<char*>(gc) + 4),
                                *reinterpret_cast<uint8_t*>(static_cast<char*>(gc) + 5));
                        }
                    }
                }
            }
        }
    }

    GatedPump(L);
    return fpOriginal_luaB_type ? fpOriginal_luaB_type(L) : 0;
}

// CreateTextWidget detour: __fastcall, L comes via ECX. Could also be
// called by engine C++ code with `this` in ECX, so still validate.
static int __fastcall DetourCreateTextWidget(lua_State* L, void* edx) {
    static std::atomic_bool seen{false};
    DetourDiag("DetourCreateTextWidget", L, seen);
    GatedPump(L);
    return fpOriginal_CreateTextWidget ? fpOriginal_CreateTextWidget(L, edx) : 0;
}

static DWORD WINAPI BridgeServerThread(LPVOID) {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        Log("[!] LuaBridge: WSAStartup failed");
        return 1;
    }
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) {
        Log("[!] LuaBridge: socket() failed GLE=%lu", WSAGetLastError());
        return 1;
    }
    BOOL reuse = TRUE;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27050);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(srv, 1) != 0) {
        Log("[!] LuaBridge: bind/listen failed GLE=%lu", WSAGetLastError());
        closesocket(srv);
        return 1;
    }
    Log("[*] LuaBridge: listening on 127.0.0.1:27050");

    for (;;) {
        SOCKET c = accept(srv, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        Log("[+] LuaBridge: client connected");

        std::string rx, chunk;
        for (;;) {
            // Flush any pending out buffer first so async REPL output
            // (from Lua print() or chunk results) reaches the client even
            // without new input.
            //
            // Loop until everything is drained — single send() can leave
            // bytes behind when the buffer is large (the walker output
            // is hundreds of KB), and the old single-shot send + clear
            // silently lost the tail.
            {
                std::lock_guard<std::mutex> lk(g_outMtx);
                size_t off = 0;
                bool send_failed = false;
                while (off < g_outBuf.size()) {
                    int sent = send(c, g_outBuf.c_str() + off,
                                    (int)(g_outBuf.size() - off), 0);
                    if (sent <= 0) { send_failed = true; break; }
                    off += static_cast<size_t>(sent);
                }
                g_outBuf.clear();
                if (send_failed) break;
            }
            fd_set fds; FD_ZERO(&fds); FD_SET(c, &fds);
            timeval tv{ 0, 50 * 1000 };  // 50 ms
            int r = select(0, &fds, nullptr, nullptr, &tv);
            if (r < 0) break;
            if (r == 0) continue;

            char buf[4096];
            int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            rx.append(buf, n);

            size_t pos;
            while ((pos = rx.find('\n')) != std::string::npos) {
                std::string ln = rx.substr(0, pos);
                rx.erase(0, pos + 1);
                if (!ln.empty() && ln.back() == '\r') ln.pop_back();
                if (ln == "<<<RUN>>>") {
                    if (!chunk.empty()) {
                        Log("[+] Received Lua Script (%zu bytes). Queued for execution.", chunk.size());

                        {
                            std::lock_guard<std::mutex> lk(g_inMtx);
                            g_inQueue.push_back(chunk);
                            // Tell the heartbeat that a script is waiting
                            g_PendingScripts.fetch_add(1, std::memory_order_release);
                        }

                        // ACK so the client can distinguish "server accepted the
                        // chunk" from "executor actually ran it". If you see
                        // [queued] but no [ok]/[runtime]/[compile] before the
                        // socket timeout, the pump source isn't firing in the
                        // current VM state and the chunk is just sitting in
                        // g_inQueue. The `<<<END>>>` framing marker is still
                        // emitted only by PumpQueue, so a healthy round-trip
                        // looks like: [queued]\n[ok]\n<<<END>>>
                        OutAppend("[queued]");
                    }
                    chunk.clear();
                }
                else {
                    chunk += ln;
                    chunk += "\n";
                }
            }
        }
        closesocket(c);
        Log("[-] LuaBridge: client disconnected");
    }
}

// What kind of byte pattern a hook target should look like. Used by
// ValidateHookTarget below to skip hooks when the user's exe is a
// different build than the one our RVAs were derived from. Without
// this check, MinHook patches arbitrary bytes at the wrong address
// and the game CTDs the first time the engine executes nearby.
enum HookKind {
    HOOK_NOOP_STUB,   // expect exactly: xor eax, eax; ret  (33 C0 C3)
    HOOK_NORMAL_FUNC, // expect a plausible x86 function prologue
};

// Verify that `p` looks like the kind of code we expect to hook at
// that RVA. Returns true on a recognisable pattern, false otherwise.
// On false we skip the hook entirely rather than letting MinHook
// corrupt unrelated bytes — multiplayer keeps working, Lua bridge
// simply stays disabled for that user.
static bool ValidateHookTarget(const void* p, HookKind kind) {
    if (!SafeProbe(p, 8)) return false;
    const uint8_t* b = static_cast<const uint8_t*>(p);

    if (kind == HOOK_NOOP_STUB) {
        // xor eax, eax; ret — the stripped-stub signature. If it's
        // anything else, we're not looking at print/SendEvent_*/etc.
        return b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0xC3;
    }

    // HOOK_NORMAL_FUNC: accept any of the common x86 function-entry
    // patterns that MinHook can safely save into a trampoline. Not
    // exhaustive but covers everything the verified binary uses;
    // false negatives (skipping a real but oddly-prologued function)
    // are strictly preferable to false positives (corrupting random
    // bytes mid-function).
    if (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) return true;  // push ebp; mov ebp, esp
    if (b[0] == 0x53) return true;                                  // push ebx
    if (b[0] == 0x56) return true;                                  // push esi
    if (b[0] == 0x57) return true;                                  // push edi
    if (b[0] == 0x83 && b[1] == 0xEC) return true;                  // sub esp, imm8
    if (b[0] == 0x81 && b[1] == 0xEC) return true;                  // sub esp, imm32
    if (b[0] == 0x6A) return true;                                  // push imm8
    if (b[0] == 0x68) return true;                                  // push imm32
    if (b[0] == 0x8B && b[1] == 0xFF) return true;                  // mov edi, edi (hot-patchable)
    if (b[0] == 0x8B && (b[1] & 0xC0) == 0xC0) return true;         // mov reg, reg (canonical luaL_register start)
    return false;
}

static DWORD WINAPI LuaBridgeInitThread(LPVOID) {
    HMODULE mod = GetModuleHandleA("Mercenaries2.exe");
    if (!mod) {
        Log("[!] LuaBridge: GetModuleHandle(Mercenaries2.exe) returned NULL");
        return 1;
    }
    BYTE* base = reinterpret_cast<BYTE*>(mod);

    // Pick the RVA table that matches this exe. Falls through to v1.1
    // RVAs on unknown binaries — the per-hook prologue validator then
    // refuses the hooks and the bridge stays disabled (no CTD).
    g_rvas = SelectRvas(mod);

    // Same unpack-race wait pattern as PatchFeslCAKey. .text appears to be
    // intact on disk for this binary, but waiting is cheap insurance.
    BYTE* probe = base + g_rvas->noop_stub;
    for (int t = 0; t < 400; t++) {
        bool nonzero = false;
        for (int i = 0; i < 8; i++) if (probe[i]) { nonzero = true; break; }
        if (nonzero) break;
        Sleep(25);
    }

    // Phase 3: resolve luaB_loadstring + luaB_pcall (real __cdecl
    // lua_CFunctions) and initialize the FixedTString buffer. The
    // executor in LuaDoString() uses these to compile+run user chunks,
    // but ONLY when invoked from a verified Lua context (currently
    // DetourLuaType — see PumpQueue(L) calls in each detour).
    p_luaB_loadstring   = reinterpret_cast<lua_CFunction_t>(base + g_rvas->luaB_loadstring);
    p_luaL_register_raw = reinterpret_cast<void*>(base + g_rvas->luaL_register);
    p_luaB_pcall      = reinterpret_cast<lua_CFunction_t>(base + g_rvas->luaB_pcall);
    InitChunkSource();
    Log("[*] LuaBridge: Phase 3 executor armed (loadstring=%p, pcall=%p, chunkbuf=%p)",
        p_luaB_loadstring, p_luaB_pcall, &g_chunkSource);

    struct HookSpec { DWORD rva; LPVOID detour; LPVOID* orig; const char* name; HookKind kind; };
    HookSpec specs[] = {
            { g_rvas->noop_stub,        &DetourNoopStub,         (LPVOID*)&fpOriginal_NoopStub,         "noop-stub (print/SendEvent_*/...)", HOOK_NOOP_STUB },
            { g_rvas->luaB_type,        &DetourLuaType,          (LPVOID*)&fpOriginal_luaB_type,        "luaB_type",                         HOOK_NORMAL_FUNC },
            { g_rvas->CreateTextWidget, &DetourCreateTextWidget, (LPVOID*)&fpOriginal_CreateTextWidget, "CreateTextWidget",                  HOOK_NORMAL_FUNC },
            // luaL_register: authoritative L capture + dump of every Lua
            // C function the engine exposes. The naked detour preserves
            // the custom ECX/EAX register-arg ABI; the C handler reads
            // the cdecl args we push and walks the luaL_Reg table.
            { g_rvas->luaL_register,    &DetourLuaLRegister,     (LPVOID*)&fpOriginal_luaL_register,    "luaL_register",                     HOOK_NORMAL_FUNC },
    };
    int hooks_armed = 0;
    for (const auto& s : specs) {
        LPVOID target = (LPVOID)(base + s.rva);
        // Sanity-check the bytes at the target address BEFORE asking
        // MinHook to patch them. If our RVA points somewhere
        // unexpected (because the user has a different exe build —
        // 1.0 Origin, 1.1 patched, EU/RU localizations, etc.) MinHook
        // will happily overwrite random bytes and the game will crash
        // the moment execution reaches them. Skipping instead means
        // the Lua bridge silently stays disabled and the user still
        // has working multiplayer.
        if (!ValidateHookTarget(target, s.kind)) {
            Log("[!] LuaBridge: RVA 0x%X (%s) at %p doesn't look like the expected code — "
                "skipping hook. This usually means a different Mercenaries2.exe build than "
                "the one this bridge was derived from (archive.org English release). "
                "Multiplayer is unaffected; the Lua REPL will be disabled.",
                s.rva, s.name, target);
            continue;
        }
        if (MH_CreateHook(target, s.detour, s.orig) != MH_OK) {
            Log("[!] LuaBridge: MH_CreateHook(%s) failed", s.name);
            continue;
        }
        if (MH_EnableHook(target) != MH_OK) {
            Log("[!] LuaBridge: MH_EnableHook(%s) failed", s.name);
            continue;
        }
        Log("[*] LuaBridge: hook armed on %s (RVA 0x%X -> %p)", s.name, s.rva, target);
        hooks_armed++;
    }

    // Fail closed: if not a single hook validated, the user's binary
    // is something we don't know how to drive. Don't even open the
    // REPL socket — that way a connecting client gets a clean
    // "connection refused" instead of "connected but chunks never
    // execute," which is much easier to diagnose.
    if (hooks_armed == 0) {
        Log("[!] LuaBridge: 0/%d hooks armed — bridge fully disabled for this binary. "
            "The REPL on 127.0.0.1:27050 will NOT be started. To enable, re-derive RVAs "
            "for your exe via tools/find_lua_print.py and tools/resolve_lua_api.py.",
            (int)(sizeof(specs)/sizeof(specs[0])));
        return 0;
    }

    CreateThread(nullptr, 0, BridgeServerThread, nullptr, 0, nullptr);
    return 0;
}

// --- Main Thread Execution -------------------------------------------------
DWORD WINAPI MainThread(LPVOID lpReserved) {
    std::ofstream clearLog("Merc2Debug.log", std::ios_base::trunc);
    clearLog.close();

    Log("==========================================");
    Log("[*] Merc2Fix Engine Initialized (Time Machine Mode)");
    Log("==========================================");

    // --- NEW DYNAMIC RESOLUTION BLOCK ---
    Log("[*] Attempting to resolve dynamic domain: refesl.live");
    std::string resolvedIP = ResolveDomain("refesl.live");

    if (!resolvedIP.empty()) {
        g_ServerIP = resolvedIP;
        Log("[+] refesl.live successfully resolved to %s", g_ServerIP.c_str());
    }
    else {
        Log("[!] Domain resolution failed. Falling back to server.txt...");
        std::ifstream infile("server.txt");
        if (infile.is_open()) {
            std::getline(infile, g_ServerIP);
            g_ServerIP.erase(std::remove_if(g_ServerIP.begin(), g_ServerIP.end(), ::isspace), g_ServerIP.end());
            Log("[*] Loaded Target IP from file: %s", g_ServerIP.c_str());
        }
        else {
            Log("[!] server.txt not found. Defaulting to 127.0.0.1");
        }
    }
    // ------------------------------------

    if (MH_Initialize() != MH_OK) {
        Log("[!] MH_Initialize failed");
        return 1;
    }

    // 1. Network redirection
    MH_CreateHookApi(L"ws2_32.dll", "gethostbyname", &DetourGetHostByName, (LPVOID*)&fpOriginalGetHostByName);
    MH_CreateHookApi(L"ws2_32.dll", "getaddrinfo", &DetourGetAddrInfo, (LPVOID*)&fpOriginalGetAddrInfo);
    MH_CreateHookApi(L"ws2_32.dll", "GetAddrInfoW", &DetourGetAddrInfoW, (LPVOID*)&fpOriginalGetAddrInfoW);

    // 2. Certificate trust blindfold
    MH_CreateHookApi(L"wintrust.dll", "WinVerifyTrust", &DetourWinVerifyTrust, (LPVOID*)&fpOriginalWinVerifyTrust);

    // 3. Time APIs (Windows)
    MH_CreateHookApi(L"kernel32.dll", "GetSystemTime", &DetourGetSystemTime, (LPVOID*)&fpOriginalGetSystemTime);
    MH_CreateHookApi(L"kernel32.dll", "GetLocalTime", &DetourGetLocalTime, (LPVOID*)&fpOriginalGetLocalTime);
    MH_CreateHookApi(L"kernel32.dll", "GetSystemTimeAsFileTime", &DetourGetSystemTimeAsFileTime, (LPVOID*)&fpOriginalGetSystemTimeAsFileTime);

    // 4. Time APIs (C-Runtime for OpenSSL)
    const wchar_t* crt_modules[] = { L"msvcrt.dll", L"msvcr80.dll", L"msvcr90.dll" };
    for (int i = 0; i < 3; i++) {
        MH_CreateHookApi(crt_modules[i], "time", &DetourTime, NULL);
        MH_CreateHookApi(crt_modules[i], "_time32", &DetourTime32, NULL);
        MH_CreateHookApi(crt_modules[i], "_time64", &DetourTime64, NULL);
    }

    MH_EnableHook(MH_ALL_HOOKS);
    Log("[*] Hooks active: DNS (gethostbyname/getaddrinfo/GetAddrInfoW), WinVerifyTrust, Time APIs x6");
    Log("[*] Temporal Displacement Active (clock -> %04d-%02d-%02d). Waiting for network activity...",
        SPOOF_YEAR, SPOOF_MONTH, SPOOF_DAY);

    // Replace MLoader's RSA key injection. Patches a 128-byte CA pubkey-like
    // structure in Mercenaries2.exe so the game accepts the local fesl.cer.
    PatchFeslCAKey();

    // Lua bridge: capture the engine lua_State via three race-to-fire detours
    // and serve a localhost REPL on 127.0.0.1:27050. Runs in its own thread
    // so it can wait for .text unpack without holding up the network hooks.
    //
    // Gated behind DISABLE_LUA_BRIDGE so we can ship a multiplayer-only
    // build for users on exe versions the bridge wasn't derived from
    // (the RVA sanity-check in LuaBridgeInitThread also catches that,
    // but compiling the init out entirely is a stronger guarantee and
    // removes any chance of regressions affecting MP-only users).
    // Defined on the MSBuild command line as
    // `/p:ExtraDefines=DISABLE_LUA_BRIDGE`.
#ifndef DISABLE_LUA_BRIDGE
    CreateThread(nullptr, 0, LuaBridgeInitThread, nullptr, 0, nullptr);
#else
    Log("[*] LuaBridge: COMPILED OUT (multiplayer-only build).");
#endif

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, MainThread, hModule, 0, nullptr);
    }
    return TRUE;
}