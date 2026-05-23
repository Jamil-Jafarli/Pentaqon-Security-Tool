/*
 * endpoint_scan.cpp — SOC Endpoint Triage Agent
 *
 * Server config is injected at build time (no hardcoding).
 * A custom PE section ".socmeta" carries the embedded config
 * so the binary can be identified back to its origin server.
 *
 * Checks:
 *   1. Suspicious registry persistence (Run, Winlogon, IFEO, SilentProcessExit)
 *   2. Open TCP/UDP ports with owning process
 *   3. Unusual files in System32
 *   4. Non-standard Windows services
 *   5. Unusual scheduled tasks (Task Scheduler COM)
 *
 * Compile (MinGW-w64, cross from Linux):
 *   x86_64-w64-mingw32-g++ -std=c++17 -O2 -static-libgcc -static-libstdc++ \
 *     -o agent.exe endpoint_scan.cpp \
 *     -lwinhttp -liphlpapi -lpsapi -ltaskschd -lole32 \
 *     -loleaut32 -luuid -ladvapi32 -lws2_32
 */

/* ── Injected at build time ─────────────────────────────── */
#ifndef SOC_HOST
#  define SOC_HOST "##SOC_HOST##"
#endif
#ifndef SOC_PORT
#  define SOC_PORT  ##SOC_PORT##
#endif
#ifndef SOC_PATH
#  define SOC_PATH "/api/postdata"
#endif
#ifndef BUILD_TS
#  define BUILD_TS "unknown"
#endif

/* ── PE metadata section (.socmeta) ────────────────────── */
#define _STR2(x) #x
#define _STR(x)  _STR2(x)
#ifdef __GNUC__
__attribute__((section(".socmeta"), used))
static const char _soc_meta[] =
    "SOC_META:host=" SOC_HOST
    ";port=" _STR(SOC_PORT)
    ";build=" BUILD_TS;
#endif

/* ── Includes ───────────────────────────────────────────── */
#define _WIN32_WINNT  0x0601
#include <winsock2.h>   /* must come before windows.h */
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsvc.h>
#include <objbase.h>
#include <oleauto.h>
#include <taskschd.h>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>

/* ── Lib hints (MSVC only) ──────────────────────────────── */
#ifdef _MSC_VER
#  pragma comment(lib, "winhttp.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "psapi.lib")
#  pragma comment(lib, "taskschd.lib")
#  pragma comment(lib, "ole32.lib")
#  pragma comment(lib, "oleaut32.lib")
#  pragma comment(lib, "advapi32.lib")
#  pragma comment(lib, "ws2_32.lib")
#endif

/* ══════════════════════════════════════════════════════════
 *  String helpers
 * ══════════════════════════════════════════════════════════ */
static std::string W2S(const wchar_t* p, int len = -1) {
    if (!p) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, p, len, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, p, len, &s[0], n, nullptr, nullptr);
    /* trim embedded null from len=-1 path */
    while (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}
static std::string W2S(const std::wstring& w) { return W2S(w.data(), (int)w.size()); }

static std::string Lower(std::string s) {
    for (char& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

static std::string Ts(const FILETIME& ft) {
    FILETIME lft; FileTimeToLocalFileTime(&ft, &lft);
    SYSTEMTIME st; FileTimeToSystemTime(&lft, &st);
    char b[24];
    snprintf(b, sizeof b, "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}
static std::string NowStr() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[24];
    snprintf(b, sizeof b, "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

static double DaysSinceCreate(const FILETIME& ctime) {
    FILETIME now; SYSTEMTIME st; GetSystemTime(&st); SystemTimeToFileTime(&st, &now);
    ULONGLONG a = ((ULONGLONG)now.dwHighDateTime   << 32) | now.dwLowDateTime;
    ULONGLONG b = ((ULONGLONG)ctime.dwHighDateTime << 32) | ctime.dwLowDateTime;
    return (a > b) ? (double)(a - b) / 864000000000.0 : 0.0;
}

static std::string DotExt(const std::string& name) {
    auto p = name.rfind('.');
    return (p == std::string::npos) ? "" : Lower(name.substr(p));
}

static std::string Ip4(DWORD ip) {       /* network-byte-order DWORD */
    char b[20];
    snprintf(b, sizeof b, "%u.%u.%u.%u",
             ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return b;
}

static std::string ProcName(DWORD pid) {
    if (pid == 0) return "Idle";
    if (pid == 4) return "System";
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return "pid=" + std::to_string(pid);
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameExW(h, nullptr, buf, MAX_PATH);
    CloseHandle(h);
    std::wstring w(buf);
    auto sl = w.rfind(L'\\');
    if (sl != std::wstring::npos) w = w.substr(sl + 1);
    return W2S(w);
}

/* ══════════════════════════════════════════════════════════
 *  1. REGISTRY — persistence / tampering
 * ══════════════════════════════════════════════════════════ */
static std::string CheckRegistry() {
    std::ostringstream out;
    out << "=== SUSPICIOUS REGISTRY ENTRIES ===\n";
    int hits = 0;

    /* ── Run-key path classifiers ───────────────────────── */

    /* Returns true → completely skip this entry (known-trusted vendor path) */
    auto IsKnownGood = [](const std::string& v) -> bool {
        std::string lv = Lower(v);
        static const char* trusted[] = {
            /* Windows & System32 */
            "\\windows\\", "\\system32\\", "\\syswow64\\",
            "%systemroot%", "%windir%",
            /* Standard install paths */
            "\\program files\\", "\\program files (x86)\\",
            "%programfiles%", "%commonprogramfiles%",
            /* Microsoft first-party apps in AppData */
            "\\appdata\\local\\microsoft\\",   /* OneDrive, Teams, Edge, etc. */
            "\\programdata\\microsoft\\",
            /* Common security / AV vendors */
            "\\symantec\\", "\\norton\\", "\\mcafee\\",
            "\\kaspersky\\", "\\eset\\", "\\bitdefender\\",
            "\\crowdstrike\\", "\\sentinel\\",
            /* Other ubiquitous trusted vendors */
            "\\google\\chrome\\", "\\mozilla\\firefox\\",
            "\\dropbox\\", "\\box\\",
            nullptr
        };
        for (int i = 0; trusted[i]; ++i)
            if (lv.find(trusted[i]) != std::string::npos) return true;
        return false;
    };

    /* Returns the severity label for everything that is NOT known-good */
    auto Severity = [](const std::string& v) -> const char* {
        std::string lv = Lower(v);
        /* Definite red flags */
        static const char* high[] = {
            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
            "\\users\\public\\", "\\desktop\\", "\\downloads\\",
            "-enc", "-encodedcommand", "invoke-", "iex(",
            "powershell", "cmd.exe", "wscript", "cscript",
            "mshta", "regsvr32", "rundll32",
            nullptr
        };
        for (int i = 0; high[i]; ++i)
            if (lv.find(high[i]) != std::string::npos) return "AUTORUN-HIGH";
        /* Unknown path — worth reviewing but not confirmed malicious */
        return "AUTORUN-INFO";
    };

    /* autorun key list */
    struct RK { HKEY root; const char* hive; const wchar_t* sub; };
    static const RK runKeys[] = {
        { HKEY_LOCAL_MACHINE, "HKLM",
          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, "HKLM",
          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER,  "HKCU",
          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER,  "HKCU",
          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, "HKLM",
          L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, "HKLM",
          L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute" },
    };

    for (auto& rk : runKeys) {
        HKEY hk;
        if (RegOpenKeyExW(rk.root, rk.sub, 0,
                          KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) continue;
        DWORD idx = 0;
        wchar_t vn[16384]; DWORD vnSz;
        BYTE   vd[16384];  DWORD vdSz, vt;
        while (true) {
            vnSz = 16384; vdSz = 16384;
            if (RegEnumValueW(hk, idx++, vn, &vnSz,
                              nullptr, &vt, vd, &vdSz) != ERROR_SUCCESS) break;
            std::string val;
            if (vt == REG_SZ || vt == REG_EXPAND_SZ)
                val = W2S((wchar_t*)vd);
            else if (vt == REG_DWORD && vdSz >= 4)
                val = std::to_string(*(DWORD*)vd);
            else
                val = "(binary " + std::to_string(vdSz) + "B)";

            if (IsKnownGood(val)) continue;   /* suppress trusted vendors */

            const char* sev = Severity(val);
            out << "  [" << sev << "] " << rk.hive << "\\" << W2S(rk.sub) << "\n"
                << "    Name : " << (vnSz ? W2S(vn) : "(Default)") << "\n"
                << "    Value: " << val << "\n";
            ++hits;
        }
        RegCloseKey(hk);
    }

    /* Winlogon value checks */
    {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {

            struct { const wchar_t* val; const char* want; } chk[] = {
                { L"Userinit",     "userinit.exe," },
                { L"Shell",        "explorer.exe"  },
                { L"AppInit_DLLs", ""              },
            };
            for (auto& c : chk) {
                wchar_t buf[4096] = {}; DWORD sz = sizeof(buf);
                if (RegQueryValueExW(hk, c.val, nullptr, nullptr,
                                     (BYTE*)buf, &sz) != ERROR_SUCCESS) continue;
                std::string sv = Lower(W2S(buf));
                bool bad = c.want[0] == '\0'
                               ? (!sv.empty() && sv != "0")
                               : sv.find(c.want) == std::string::npos;
                if (bad) {
                    out << "  [WINLOGON TAMPER] " << W2S(c.val)
                        << " = " << W2S(buf) << "\n";
                    ++hits;
                }
            }
            RegCloseKey(hk);
        }
    }

    /* IFEO — Debugger hijack */
    {
        HKEY hr2;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
            0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hr2) == ERROR_SUCCESS) {
            wchar_t sub[512]; DWORD idx = 0;
            while (RegEnumKeyW(hr2, idx++, sub, 512) == ERROR_SUCCESS) {
                std::wstring full =
                    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                    L"\\Image File Execution Options\\";
                full += sub;
                HKEY hs;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, full.c_str(),
                                  0, KEY_READ | KEY_WOW64_64KEY, &hs) != ERROR_SUCCESS) continue;
                wchar_t dbg[4096] = {}; DWORD sz = sizeof(dbg);
                if (RegQueryValueExW(hs, L"Debugger", nullptr, nullptr,
                                     (BYTE*)dbg, &sz) == ERROR_SUCCESS) {
                    out << "  [IFEO HIJACK] " << W2S(sub)
                        << "  =>  " << W2S(dbg) << "\n";
                    ++hits;
                }
                RegCloseKey(hs);
            }
            RegCloseKey(hr2);
        }
    }

    /* SilentProcessExit */
    {
        HKEY hr2;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit",
            0, KEY_READ | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &hr2) == ERROR_SUCCESS) {
            wchar_t sub[512]; DWORD idx = 0;
            while (RegEnumKeyW(hr2, idx++, sub, 512) == ERROR_SUCCESS) {
                out << "  [SILENT_EXIT MONITOR] " << W2S(sub) << "\n";
                ++hits;
            }
            RegCloseKey(hr2);
        }
    }

    if (!hits) out << "  (none detected)\n";
    out << "\n";
    return out.str();
}

/* ══════════════════════════════════════════════════════════
 *  2. OPEN PORTS
 * ══════════════════════════════════════════════════════════ */
static std::string CheckPorts() {
    std::ostringstream out;
    out << "=== OPEN PORTS & OWNING PROCESSES ===\n";

    /* TCP IPv4 */
    {
        DWORD sz = 0;
        GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(sz + 512);
        if (GetExtendedTcpTable(buf.data(), &sz, TRUE,
                                AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = (MIB_TCPTABLE_OWNER_PID*)buf.data();
            out << "  [TCP/IPv4]\n";
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                auto& r = t->table[i];
                int lp = (int)ntohs((u_short)r.dwLocalPort);
                int rp = (int)ntohs((u_short)r.dwRemotePort);
                const char* state = "?";
                switch (r.dwState) {
                    case MIB_TCP_STATE_LISTEN:     state = "LISTEN";      break;
                    case MIB_TCP_STATE_ESTAB:      state = "ESTABLISHED"; break;
                    case MIB_TCP_STATE_TIME_WAIT:  state = "TIME_WAIT";   break;
                    case MIB_TCP_STATE_CLOSE_WAIT: state = "CLOSE_WAIT";  break;
                    case MIB_TCP_STATE_SYN_SENT:   state = "SYN_SENT";    break;
                    case MIB_TCP_STATE_SYN_RCVD:   state = "SYN_RCVD";    break;
                    default: break;
                }
                char row[256];
                if (r.dwState == MIB_TCP_STATE_ESTAB)
                    snprintf(row, sizeof row,
                             "    %-22s -> %-22s %-12s PID=%-6lu %s\n",
                             (Ip4(r.dwLocalAddr)  + ":" + std::to_string(lp)).c_str(),
                             (Ip4(r.dwRemoteAddr) + ":" + std::to_string(rp)).c_str(),
                             state, (unsigned long)r.dwOwningPid,
                             ProcName(r.dwOwningPid).c_str());
                else
                    snprintf(row, sizeof row,
                             "    %-22s                        %-12s PID=%-6lu %s\n",
                             (Ip4(r.dwLocalAddr) + ":" + std::to_string(lp)).c_str(),
                             state, (unsigned long)r.dwOwningPid,
                             ProcName(r.dwOwningPid).c_str());
                out << row;
            }
        }
    }

    /* UDP IPv4 */
    {
        DWORD sz = 0;
        GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        std::vector<BYTE> buf(sz + 512);
        if (GetExtendedUdpTable(buf.data(), &sz, TRUE,
                                AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* t = (MIB_UDPTABLE_OWNER_PID*)buf.data();
            out << "  [UDP/IPv4]\n";
            for (DWORD i = 0; i < t->dwNumEntries; i++) {
                auto& r = t->table[i];
                int lp = (int)ntohs((u_short)r.dwLocalPort);
                char row[160];
                snprintf(row, sizeof row,
                         "    %-22s                        %-12s PID=%-6lu %s\n",
                         (Ip4(r.dwLocalAddr) + ":" + std::to_string(lp)).c_str(),
                         "UDP", (unsigned long)r.dwOwningPid,
                         ProcName(r.dwOwningPid).c_str());
                out << row;
            }
        }
    }

    out << "\n";
    return out.str();
}

/* ══════════════════════════════════════════════════════════
 *  3. UNUSUAL SYSTEM32 FILES
 * ══════════════════════════════════════════════════════════ */
/* ── System32 baseline whitelist ───────────────────────────
 * Filenames (lowercase) that are part of a standard Windows
 * installation.  Any file whose name appears here is SKIPPED
 * even if recently created/modified (Windows Update).
 * Only files NOT in this set are subject to heuristic checks.
 * ─────────────────────────────────────────────────────────── */
static const std::set<std::string> SYS32_BASELINE = {
    /* ── Core OS processes ── */
    "ntoskrnl.exe","ntkrnlpa.exe","ntkrnlmp.exe","ntkrpamp.exe",
    "smss.exe","csrss.exe","wininit.exe","winlogon.exe","lsass.exe",
    "lsm.exe","services.exe","svchost.exe","spoolsv.exe","dwm.exe",
    "taskhost.exe","taskhostw.exe","taskeng.exe","userinit.exe",
    "explorer.exe","sihost.exe","fontdrvhost.exe","ctfmon.exe",
    "conhost.exe","condrv.sys","dllhst3g.exe",
    /* ── Admin & shell tools ── */
    "cmd.exe","powershell.exe","powershell_ise.exe","pwsh.exe",
    "mmc.exe","msiexec.exe","reg.exe","regedit.exe","regedt32.exe",
    "regsvr32.exe","regsvr64.exe","rundll32.exe","runonce.exe",
    "notepad.exe","taskmgr.exe","tasklist.exe","taskkill.exe",
    "sc.exe","net.exe","net1.exe","netstat.exe","nbtstat.exe",
    "ipconfig.exe","ping.exe","tracert.exe","pathping.exe",
    "route.exe","arp.exe","netsh.exe","nslookup.exe","ftp.exe",
    "telnet.exe","ssh.exe","where.exe","whoami.exe","hostname.exe",
    "systeminfo.exe","wmic.exe","wbemtest.exe","mofcomp.exe",
    "xcopy.exe","robocopy.exe","icacls.exe","cacls.exe","takeown.exe",
    "expand.exe","extrac32.exe","compact.exe","cipher.exe",
    "sfc.exe","dism.exe","bcdedit.exe","diskpart.exe","fsutil.exe",
    "chkdsk.exe","defrag.exe","format.com","subst.exe","mountvol.exe",
    "wscript.exe","cscript.exe","mshta.exe","hh.exe","mstsc.exe",
    "certutil.exe","certreq.exe","bitsadmin.exe","wusa.exe",
    "mtstocom.exe","odbcconf.exe","regasm.exe","regsvcs.exe",
    "installutil.exe","cmstp.exe","eventvwr.exe","eventvwr.msc",
    "devmgmt.msc","diskmgmt.msc","compmgmt.msc","services.msc",
    "gpedit.msc","secpol.msc","lusrmgr.msc","fsmgmt.msc",
    "perfmon.exe","perfmon.msc","resmon.exe","resmon.msc",
    "dxdiag.exe","msinfo32.exe","msconfig.exe","msdt.exe",
    "mdsched.exe","rstrui.exe","recdisc.exe","slui.exe",
    "wevtutil.exe","auditpol.exe","logman.exe","typeperf.exe",
    "relog.exe","tracerpt.exe","xperf.exe",
    "makecab.exe","cabarc.exe","cabview.dll",
    "write.exe","wordpad.exe","charmap.exe","calc.exe","mspaint.exe",
    "snippingtool.exe","magnify.exe","narrator.exe","osk.exe",
    "utilman.exe","accessibility.cpl",
    "appwiz.cpl","desk.cpl","hdwwiz.cpl","inetcpl.cpl","intl.cpl",
    "main.cpl","mmsys.cpl","ncpa.cpl","powercfg.cpl","sysdm.cpl",
    "timedate.cpl","wscui.cpl","wuaucpl.cpl","telephon.cpl",
    /* ── Security & auth ── */
    "lsasrv.dll","sspi.dll","msv1_0.dll","kerberos.dll","wdigest.dll",
    "tspkg.dll","pku2u.dll","cloudap.dll","schannel.dll","secur32.dll",
    "sspicli.dll","security.dll","cryptdll.dll","cryptnet.dll",
    "cryptsp.dll","cryptui.dll","crypt32.dll","bcrypt.dll","bcryptprimitives.dll",
    "ncrypt.dll","dpapi.dll","dpapimig.exe","vaultcli.dll",
    "samlib.dll","samsrv.dll","ntdsapi.dll","dnsapi.dll","dnscache.dll",
    "wintrust.dll","imagehlp.dll","dbghelp.dll",
    /* ── Win32 core DLLs ── */
    "ntdll.dll","kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll",
    "gdi32full.dll","win32u.dll","advapi32.dll","advapi32res.dll",
    "shell32.dll","shlwapi.dll","comdlg32.dll","comctl32.dll",
    "ole32.dll","oleaut32.dll","oleacc.dll","oledlg.dll","olecnv32.dll",
    "msvcrt.dll","msvcr100.dll","msvcr110.dll","msvcr120.dll",
    "vcruntime140.dll","vcruntime140_1.dll","msvcp140.dll",
    "ucrtbase.dll","api-ms-win-core-console-l1-1-0.dll",
    "winmm.dll","winmmbase.dll","avrt.dll","dsound.dll","mmdevapi.dll",
    "mfplat.dll","mf.dll","mfreadwrite.dll","mfperfhelper.dll",
    "winspool.drv","localspl.dll","printui.dll","prntvpt.dll",
    "wsock32.dll","ws2_32.dll","ws2help.dll","mswsock.dll",
    "wininet.dll","urlmon.dll","ieframe.dll","mshtml.dll","jscript.dll",
    "jscript9.dll","chakra.dll","vbscript.dll",
    "netapi32.dll","netutils.dll","srvcli.dll","wkscli.dll",
    "rpcrt4.dll","rpcss.dll","rpcns4.dll",
    "combase.dll","clbcatq.dll","sti.dll",
    "wldap32.dll","ldap.dll","activeds.dll","adsldpc.dll",
    "setupapi.dll","cfgmgr32.dll","newdev.dll","devobj.dll",
    "userenv.dll","profapi.dll","profext.dll",
    "psapi.dll","pdh.dll","perfctrs.dll","loadperf.dll",
    "msasn1.dll","wintypes.dll","windows.storage.dll",
    "uxtheme.dll","themeservice.dll","dwmapi.dll","d3d9.dll",
    "d3d10.dll","d3d10core.dll","d3d11.dll","d3d12.dll",
    "dxgi.dll","dxgimms.dll","d2d1.dll","dwrite.dll",
    "opengl32.dll","glu32.dll","glmf32.dll",
    "wtsapi32.dll","winsta.dll","termsrv.dll",
    "imm32.dll","msimm.dll","input.dll","tiptsf.dll",
    "msi.dll","msiparts.exe","msisip.dll","msieftp.dll",
    "wer.dll","werui.dll","faultrep.dll",
    "cabinet.dll","zipfldr.dll","sendmail.dll",
    "mlang.dll","iertutil.dll","iesysprep.dll",
    "xmllite.dll","msxml3.dll","msxml6.dll",
    "hlink.dll","oledb32.dll","odbc32.dll","odbccp32.dll",
    "odbcbcp.dll","sqpros.dll",
    "msvfw32.dll","avicap32.dll","amstream.dll","devenum.dll",
    "quartz.dll","qcap.dll","qdvd.dll","qwave.dll",
    "dxva2.dll","evr.dll","mfcore.dll",
    "clusapi.dll","resutils.dll",
    "wbemcomn.dll","wbemcore.dll","wbemprox.dll","wbemsvc.dll",
    "fastprox.dll","esscli.dll","wmiutils.dll","wmidcprv.dll",
    "framedyn.dll","framedynos.dll","wmiaputil.dll","wmipjobj.dll",
    /* ── Networking ── */
    "iphlpapi.dll","dhcpcsvc.dll","dhcpcsvc6.dll","rasapi32.dll",
    "rasman.dll","rastapi.dll","rasppp.dll","ndishc.dll",
    "nlaapi.dll","netprofm.dll","nlasvc.dll","ncsi.dll",
    "ndfapi.dll","ndfcore.dll","ndfhcdiscovery.dll",
    "winnsi.dll","traffic.dll","qos.dll","tcpip.sys",
    "winhttp.dll","httpapi.dll","http.sys",
    "ntlmshared.dll","ntlmssps.dll","msapsspc.dll","msnsspc.dll",
    /* ── Storage & FS ── */
    "ntfs.sys","refs.sys","rdbss.sys","csc.sys","mrxsmb.sys",
    "mrxsmb10.sys","mrxsmb20.sys","mup.sys","nfs41_driver.sys",
    "iologmsg.dll","fltlib.dll","fltmgr.sys",
    "disk.sys","classpnp.sys","partmgr.sys","volmgr.sys","volmgrx.sys",
    "storport.sys","storahci.sys","storvsp.sys","stornvme.sys",
    "wd.sys","wdcsam.sys","wdcsam64.sys",
    "cdfs.sys","udfs.sys","fastfat.sys","exfat.sys",
    "mountmgr.sys","volsnap.sys","fvevol.sys","rdyboost.sys",
    "vss.exe","vshadow.exe","vssadmin.exe","vswriter.dll",
    /* ── Hardware / drivers ── */
    "hal.dll","ntdll.dll","bootvid.dll","kdcom.dll",
    "acpi.sys","pci.sys","pcie.sys","pcmcia.sys",
    "usbhub.sys","usbhub3.sys","usbport.sys","usbehci.sys",
    "usbxhci.sys","usbuhci.sys","usbohci.sys","usbccgp.sys",
    "hidclass.sys","hidparse.sys","kbdclass.sys","mouclass.sys",
    "i8042prt.sys","kbd101.dll","kdlib.dll",
    "ndis.sys","netio.sys","fwpkclnt.sys","fwpuclnt.dll",
    "wdf01000.sys","wdfldr.sys","wdfdynamics.sys",
    "dxgkrnl.sys","dxgmms1.sys","dxgmms2.sys","basicdisplay.sys",
    "basicrender.sys","monitor.sys","vga.dll","vgapnp.sys",
    /* ── Services & infrastructure ── */
    "sppsvc.exe","sppuinotify.dll","slc.dll","slwga.dll",
    "wuaueng.dll","wuauclt.exe","wuapi.dll","wudriver.dll",
    "bits.dll","bitsperf.dll","qmgr.dll","qmgrprxy.dll",
    "msdtc.exe","msdtcprx.dll","msdtctm.dll","xolehlp.dll",
    "wmisvc.dll","wmipdskq.dll","wmiprvse.exe","winmgmt.exe",
    "tlntsvr.exe","snmptrap.exe","snmp.exe","snmpapi.dll",
    "w32time.dll","w32tm.exe","winsrv.dll",
    "tapisrv.exe","tapiui.dll","tapi32.dll","tapi.dll",
    "efsadu.dll","efssvc.dll","efslsaext.dll",
    "appinfo.dll","apphlpdm.dll","consent.exe",
    "schedsvc.dll","taskcomp.dll","taskschd.dll",
    "sens.dll","sensapi.dll","sensrsvc.dll",
    "ssdpapi.dll","ssdpsrv.dll","upnp.dll","upnphost.dll",
    "evteng.dll","evtprov.dll","wevtapi.dll",
    "netevent.dll","netsetupapi.dll","netsvc.dll",
    "srm.exe","srmhost.exe","winrm.dll","wsmsvc.dll",
    /* ── .NET runtime ── */
    "clr.dll","clrjit.dll","clrjit2.dll","fusion.dll",
    "mscorwks.dll","mscoreei.dll","mscoree.dll","mscorlib.dll",
    "mscorsvc.exe","mscorsvw.exe","ngen.exe","ngenstrings.dll",
    "dotnet.exe","coreclr.dll","hostpolicy.dll","hostfxr.dll",
    /* ── WinSxS & activation ── */
    "actxprxy.dll","aclui.dll","authz.dll","sechost.dll",
    "appobj.dll","iiscore.dll","w3svc.dll",
    /* ── Misc utilities ── */
    "mscms.dll","icm32.dll","color.dll","colorcpl.exe",
    "wlanapi.dll","wlansvc.dll","wlanui.dll","wlanmsm.dll",
    "wlanpref.dll","dot3api.dll","dot3cfg.dll","dot3dlg.dll",
    "bthprop.cpl","bthserv.dll","bthci.dll","bthudtask.exe",
    "ir50_32.dll","ir50_qcx.dll",
    "ksproxy.ax","ks.sys","ksecdd.sys","ksecpkg.dll",
    "elscore.dll","elshyph.dll","elslad.dll",
    "tzres.dll","mui.dll","locale.nls","normalization.nls",
    "cmutil.dll","cmstp.exe","rasplap.dll",
    /* ── Extended System32 baseline (from known-clean scan) ── */
    /* EFI / boot */
    "winload.efi","winresume.efi","secconfig.efi",
    "boot.sdi","bootsect.exe","bootim.exe","bcdboot.exe","bcdedit.exe",
    /* Device reg / AAD */
    "dsregcmd.exe","aadcloudap.dll","aadauthhelper.dll","aadtb.dll",
    "aadwamextension.dll","aadjcsp.dll",
    /* Scheduled task scripts */
    "manage-bde.wsf","manage-bde.exe","slmgr.vbs","winrm.vbs",
    "winrm.cmd","syncappvpublishingserver.vbs","syncappvpublishingserver.exe",
    "gathernetworkinfo.vbs",
    /* Text / doc assets */
    "thirdpartynoticesbyshs.txt","windowscodecraw.txt","license.rtf",
    "windowscodecraw.txt",
    /* Printer assets */
    "pscript.sep","sysprint.sep","sysprtj.sep","pcl.sep",
    /* XSLT */
    "transformppstowlan.xslt","transformppstowlancredentials.xslt",
    /* WsmPty / WsmTxt */
    "wsmpty.xsl","wsmtxt.xsl",
    /* Header file */
    "rasctrnm.h",
    /* DTD */
    "xwizard.dtd",
    /* Config */
    "mmc.exe.config","uevappmonitor.exe.config","uevappmonitor.exe",
    /* Response file */
    "odbcconf.rsp",
    /* Binary assets (rooms/HRTFs for spatial audio) */
    "averageroom.bin","largeroom.bin","mediumroom.bin","smallroom.bin",
    "outdooraudioenvironment.bin","defaulthrtfs.bin",
    "dynamiclong.bin","dynamicmedium.bin","dynamicshort.bin",
    /* AppX provisioning */
    "appxprovisioning.xml",
    /* WinSAT / other XML data */
    "defaultquestions.json","integratedservicesregionpolicyset.json",
    "mixedrealityruntime.json","wpr.config.xml",
    "wsmanconfig_schema.xml","wdsunattendtemplate.xml",
    "nativeevents.xml","eventvwr_eventdetails.xsl",
    /* Misc known-clean executables */
    "aitstatic.exe","aggegatorhost.exe","aggregatorhost.exe",
    "agentactivationruntimestarter.exe","agentservice.exe",
    "apphostregistrationverifier.exe","applytrustsettingstemplatecatalog.exe",
    "applytrustedoffline.exe","approvechildrequest.exe",
    "assignedaccessguard.exe","authhost.exe",
    "backgroundtaskhost.exe","backgroundtransferhost.exe",
    "baaupdate.exe","bdechangepin.exe","bdehcfg.exe",
    "certcred.exe","certenrollui.dll","certutil.exe",
    "cloudnotifications.exe","cloudrestorelauncher.dll",
    "cofire.exe","comppkgsrv.exe","computerdefaults.exe",
    "consent.exe","consentux.dll","consentuxclient.dll",
    "credentialenrollmentmanager.exe","credentialuibroker.exe",
    "credwiz.exe","custominstallexec.exe","customshellhost.exe",
    "dataclen.dll","dataexchangehost.exe","datastorecachedumptool.exe",
    "datausagelivetilestask.exe","daxexec.dll",
    "dccw.exe","dcomp.dll","ddodiag.exe","desktopimgdownldr.exe",
    "devicecensus.exe","deviceenroller.exe","devicepairingwizard.exe",
    "deviceproperties.exe","dfrgui.exe","dfsvc.dll",
    "directxdatabaseupdater.exe","disksnapshot.exe","disksnapshot.conf",
    "dispdiag.exe","displayswitch.exe","djoin.exe",
    "dllhost.exe","dllhst3g.exe","dmcertinst.exe","dmcfghost.exe",
    "dmclient.exe","dmenrollengine.dll","dmnotificationbroker.exe",
    "dmprocessxmlfiltered.dll","dmpushproxy.dll","dmomacp.exe",
    "dnscacheugc.exe","dosettings.dll","dpapimig.exe","dpiscaling.exe",
    "drvinst.exe","drtmauthtxt.wim",
    "dsregtask.dll","dsuiext.dll","dtuhhandler.exe",
    "dwwin.exe","dxdiag.exe","dxgiadaptercache.exe","dxpserver.exe",
    "eap3host.exe","easinvoker.exe","easinvoker.proxystub.dll",
    "easpoilcymanagerbrokerhost.exe","edpcleanup.exe","edpnotify.exe",
    "efsui.exe","ehstorauthn.exe","em.exe",
    "enrollmentapi.dll","enterpriseappvmgmtcsp.dll",
    "fcclip.exe","filehistory.exe","fodhelper.exe","fondue.exe",
    "fontdrvhost.exe","fontview.exe","fsavailux.exe",
    "fsiso.exe","fsquirt.exe","fvenotify.exe","fveprompt.exe",
    "gamepanel.exe","genbvalobj.exe","groupinghc.dll",
    "hdwwiz.exe","helppanetproxy.dll",
    "hvax64.exe","hvix64.exe","hvsievaluator.exe",
    "icsunattend.exe","ie4uinit.exe","ietsysprep.dll",
    "immersivetpmvscmgrsvr.exe","iotstartup.exe",
    "ipconfig.exe","iscsicli.exe","iscsicpl.exe","isoburn.exe",
    "languagecomponentsinstallercomhandler.exe",
    "launchdwapp.exe","launchwinapp.exe","licensemangershellext.exe",
    "licensingui.exe","locationnotificationwindows.exe",
    "locator.exe","lockapphost.exe","lockscreencontentserver.exe",
    "logagent.exe","logoff.exe","logonui.exe",
    "lsaiso.exe","lpkinstall.exe","lpksetup.exe",
    "makecab.exe","mavinject.exe","mbr2gpt.exe","mblctr.exe",
    "mdediag.exe","mdmdiagnosticstool.exe","mdmagent.exe",
    "mdsched.exe","mmsys.cpl","mobsync.exe",
    "mousocoreworker.exe","mpnotify.exe","mpsigstub.exe",
    "mrt.exe","msdt.exe","msdtc.exe","msiexec.exe",
    "msspellcheckinghost.exe","mstsc.exe","muiunatend.exe",
    "musnotification.exe","musnotificationux.exe","musnotifyicon.exe",
    "ndadmin.exe","netcfg.exe","netcfgnotifyobjecthost.exe",
    "notepad.exe","ngciso.exe","ngcctnrsvc.dll",
    "odbcad32.exe","odbcconf.exe","ocsetapi.dll",
    "oobe-maintenance.exe","openfiles.exe","openwith.exe",
    "optionalfeatures.exe","osk.exe",
    "pcacli.dll","pcalua.exe","pcaui.exe","pcwrun.exe",
    "pickerhostexe.exe","pickerhost.exe","pkgmgr.exe","pktmon.exe",
    "pnpunattend.exe","pnputil.exe","provlaunch.exe","provtool.exe",
    "proximityuxhost.exe","psr.exe","pwlauncher.exe",
    "rdpsa.exe","rdpsaproxy.exe","rdpsauachelper.exe",
    "readclouddatasettings.exe","reagentc.exe","recdisc.exe",
    "recover.exe","recoverydriveexe.exe","recoverydrive.exe",
    "reg.exe","regini.exe","register-cimprovider.exe","regsvr32.exe",
    "rekeywiz.exe","remoteapplifetimemanager.exe",
    "reset.exe","reseteng.exe","resmon.exe","rstrui.exe",
    "rmactivate.exe","rmactivate_isv.exe","rmclient.exe",
    "robocopy.exe","rrinstaller.exe","runas.exe","rundll32.exe",
    "runexehelper.exe","runlegacycplelveated.exe","runonce.exe",
    "rwinsta.exe","sc.exe","scansetting.dll","schtasks.exe",
    "scriptrunner.exe","sdbinst.exe","sdclt.exe","sdiagnhost.exe",
    "searchfilterhost.exe","searchindexer.exe","searchprotocolhost.exe",
    "secedit.exe","secinit.exe","securekernel.exe",
    "sethc.exe","settingsynhost.exe","setupcl.exe","setx.exe",
    "sfc.exe","shrpubw.exe","shutdown.exe","sigverif.exe",
    "sihclient.exe","sihost.exe","slui.exe","smphost.dll",
    "sndvol.exe","snipingtool.exe","snippingtool.exe",
    "spaceman.exe","spatialaudiolicensesrv.exe","spectrum.exe",
    "spoolsv.exe","sppextcomobj.exe","sppsvc.exe",
    "sysresexter.exe","sysreseterr.exe","systemreset.exe",
    "systemsettingsadminflows.exe","systemsettingsbroker.exe",
    "systemsettingsremovedevice.exe","systemuwplauncher.exe",
    "systray.exe","tabcal.exe",
    "taskhostw.exe","taskkill.exe","tasklist.exe","taskmgr.exe",
    "tcmsetup.exe","thumbnailerextractionhost.exe","thumbnailextractionhost.exe",
    "timeout.exe","tpmcoreprovisioning.dll","tpminit.exe","tpmtool.exe",
    "tpmvscmgr.exe","tpmvscmgrsvr.exe","tracerpt.exe",
    "ttdinject.exe","ttdloader.dll","ttdplm.dll","ttdrecord.dll",
    "tttracer.exe","ucpdmgr.exe",
    "uevagentpolicygenerator.exe","uevappmonitor.exe",
    "uevtemplatebaselinegenerator.exe","uevtemplateconfigitemgenerator.exe",
    "uimanagerbroker.exe","uimgrbroker.exe","unregmp2.exe","unlodctr.exe",
    "uppinterinstaller.exe","upprinterinstaller.exe","usoclient.exe",
    "utcdecorderhost.exe","utcdecoderhost.exe","utilman.exe",
    "vaultcmd.exe","vds.exe","vdsldr.exe","verifier.exe","verifiergui.exe",
    "vm3dservice.exe","vssadmin.exe","vssvc.exe",
    "waasmedicagent.exe",
    "waitfor.exe","wbadmin.exe","wbengine.exe",
    "wdibiosvrc.dll","wevtutil.exe","wextract.exe",
    "wfaultsecure.exe","werfault.exe","wermgr.exe","wfs.exe",
    "where.exe","whoami.exe","wiaacmgr.exe","wiawow64.exe",
    "wimserv.exe","winbiodatamodel.exe","winbiodatamodeloobe.exe",
    "wininit.exe","winload.exe","winlogon.exe","winresume.exe",
    "winrs.exe","winrsshost.exe","winrshostexe.exe","winrshost.exe",
    "winrtnetmuahostserver.exe","winsat.exe","winsetupui.exe","winver.exe",
    "wlrmdr.exe","wmpdmc.exe","workefolders.exe","workfolders.exe",
    "wscsadminui.exe","wscollect.exe","wscript.exe",
    "wsmhttpconfig.exe","wsmanconfig.exe","wsmanthttpconfig.exe",
    "wsmprovhost.exe","wsreset.exe","wtsapi32.dll",
    "wuapihost.exe","wuauclt.exe","wudfcompanionhost.exe",
    "wudfhost.exe","wusa.exe","xcopy.exe","xwizard.exe",
    /* Locale/NLS dirs that appear as file entries on some builds */
    "locale.nls","sortdefault.nls","sorttbls.nlp",
};

/* Allowed extensions for files in System32 */
static const std::set<std::string> KNOWN_EXT = {
    /* executables & libraries */
    ".dll",".exe",".sys",".ocx",".drv",".scr",".cpl",".ax",".tsp",".acm",
    ".com",".ime",".winmd",
    /* PE metadata & signing */
    ".mui",".cat",".pdb",".manifest",".rll",".rs",
    /* setup & config */
    ".inf",".msi",".msc",".cfg",".ini",".dat",".bin",".reg",".policy",".adml",".admx",
    /* data / databases */
    ".nls",".nlp",".sdb",".db",".etl",".log",".mof",".mfl",
    /* XML/markup */
    ".xml",".xsl",".xsd",".xrm-ms",".ptxml",".xslt",".dtd",
    /* fonts */
    ".ttf",".ttc",".fon",".otf",
    /* type libraries */
    ".tlb",
    /* character encoding tables */
    ".uce",".dic",
    /* certificates & crypto */
    ".cer",".crt",".p7b",".pfx",".der",
    /* archive / image containers */
    ".cab",".wim",".sdi",".efi",
    /* scripts shipped with Windows */
    ".vbs",".wsc",".js",".wsf",".cmd",
    /* config / data formats */
    ".conf",".json",".gpd",".ppd",".rsp",".config",
    /* plain text / docs */
    ".txt",".rtf",".h",
    /* printer separator pages */
    ".sep",
    /* images (toast icons, Windows Hello assets, etc.) */
    ".png",".gif",".jpg",".jpeg",".bmp",".ico",".cur",".ani",".tiff",".wmf",
    /* help */
    ".chm",".hlp",
    /* misc */
    ".iec",".iec2",".iec3"
};

/* Returns true if the filename has a UUID prefix like
   "69fe178f-26e7-43a9-aa7d-2b616b672dde_something.dll"
   These are Windows Update staging artifacts — always clean. */
static bool IsGuidPrefixed(const std::string& name) {
    if (name.size() < 36) return false;
    auto h = [](char c){ return (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'); };
    auto seg = [&](int p, int l){ for(int i=0;i<l;i++) if(!h(name[p+i])) return false; return true; };
    return seg(0,8) && name[8]=='-' && seg(9,4) && name[13]=='-' &&
           seg(14,4) && name[18]=='-' && seg(19,4) && name[23]=='-' && seg(24,12);
}

static bool IsSuspiciousPath(const std::string& p) {
    std::string lp = Lower(p);
    return lp.find("\\temp\\")      != std::string::npos ||
           lp.find("\\tmp\\")       != std::string::npos ||
           lp.find("\\appdata\\")   != std::string::npos ||
           lp.find("\\public\\")    != std::string::npos ||
           lp.find("\\downloads\\") != std::string::npos ||
           lp.find("\\desktop\\")   != std::string::npos;
}

static std::string CheckSystem32() {
    std::ostringstream out;
    out << "=== UNUSUAL SYSTEM32 FILES ===\n";
    out << "  Flags: [E]=unknown ext  [N]=unknown file created<3d  [T]=tiny unknown exe(<4KB)\n";
    out << "  (baseline-whitelisted Windows files are suppressed)\n";

    wchar_t sys[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH);
    std::wstring pat = std::wstring(sys) + L"\\*";
    WIN32_FIND_DATAW fd;
    HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) {
        out << "  (cannot open System32)\n\n"; return out.str();
    }

    int hits = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::string name  = W2S(fd.cFileName);
        std::string lname = Lower(name);
        std::string ext   = DotExt(name);
        ULONGLONG   fsz   = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        double      age   = DaysSinceCreate(fd.ftCreationTime);

        /* Skip files that are in the known-good baseline */
        if (SYS32_BASELINE.count(lname)) continue;

        /* Skip Windows notification/resource icon assets (@-prefixed) */
        if (!name.empty() && name[0] == '@') continue;

        /* Skip Windows Update staging artifacts (GUID-prefixed filenames) */
        if (IsGuidPrefixed(name)) continue;

        bool knownExt = (KNOWN_EXT.find(ext) != KNOWN_EXT.end());

        std::string flags;
        /* Unknown extension — suspicious regardless of age */
        if (!knownExt && !ext.empty())
            flags += "[E]";
        /* File not in baseline AND created very recently AND unknown extension
           Known-ext files created recently are normal Windows Update deliveries */
        if (age < 3.0 && !knownExt)
            flags += "[N]";
        /* Tiny executable not in baseline.
           Suppress for *res.dll / *resources.dll — Windows ships many
           resource-only satellite DLLs that are legitimately <4 KB.
           Also suppress api-ms-win-* forwarding stubs (always tiny by design). */
        if ((ext==".exe"||ext==".dll"||ext==".sys") && fsz < 4096) {
            bool isResDll = (lname.size() > 7 &&
                             (lname.rfind("res.dll")       == lname.size()-7 ||
                              lname.rfind("resources.dll") != std::string::npos));
            bool isApiSet = (lname.rfind("api-ms-win-",0) == 0 ||
                             lname.rfind("ext-ms-win-",0) == 0 ||
                             lname.rfind("api-ms-",0)     == 0);
            if (!isResDll && !isApiSet) flags += "[T]";
        }

        if (flags.empty()) continue;

        out << "  " << flags << " " << name << "\n"
            << "    Size   : " << fsz << " B\n"
            << "    Created: " << Ts(fd.ftCreationTime) << "\n"
            << "    Written: " << Ts(fd.ftLastWriteTime) << "\n";
        if (++hits >= 60) { out << "  ...(truncated)\n"; break; }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);

    if (!hits) out << "  (none detected)\n";
    out << "\n";
    return out.str();
}

/* ══════════════════════════════════════════════════════════
 *  4. UNUSUAL SERVICES
 * ══════════════════════════════════════════════════════════ */
static bool IsSystemBin(const std::string& p) {
    std::string lp = Lower(p);
    return lp.find("\\windows\\")      != std::string::npos ||
           lp.find("\\system32\\")     != std::string::npos ||
           lp.find("\\syswow64\\")     != std::string::npos ||
           lp.find("svchost.exe")      != std::string::npos ||
           /* env-var prefixes that haven't been expanded */
           lp.rfind("%systemroot%", 0) == 0 ||
           lp.rfind("%windir%",     0) == 0;
}
static bool IsTrustedBin(const std::string& p) {
    std::string lp = Lower(p);
    return lp.find("\\program files\\")       != std::string::npos ||
           lp.find("\\program files (x86)\\") != std::string::npos ||
           lp.find("\\programdata\\")          != std::string::npos ||
           lp.rfind("%programfiles%",       0) == 0 ||
           lp.rfind("%programfiles(x86)%",  0) == 0 ||
           lp.rfind("%commonprogramfiles%", 0) == 0;
}

static std::string CheckServices() {
    std::ostringstream out;
    out << "=== UNUSUAL SERVICES ===\n";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { out << "  (access denied)\n\n"; return out.str(); }

    DWORD need = 0, ret = 0, res = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, nullptr, 0, &need, &ret, &res, nullptr);
    std::vector<BYTE> buf(need + 512); res = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, buf.data(), (DWORD)buf.size(),
                          &need, &ret, &res, nullptr);

    auto* svcs = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    int hits = 0;

    for (DWORD i = 0; i < ret; i++) {
        auto& svc = svcs[i];
        SC_HANDLE hs = OpenServiceW(scm, svc.lpServiceName, SERVICE_QUERY_CONFIG);
        if (!hs) continue;

        DWORD cfgSz = 0;
        QueryServiceConfigW(hs, nullptr, 0, &cfgSz);
        std::vector<BYTE> cb(cfgSz + 128);
        auto* cfg = (QUERY_SERVICE_CONFIGW*)cb.data();

        bool flag = false; std::string reason, binPath;
        if (QueryServiceConfigW(hs, cfg, cfgSz, &cfgSz)) {
            binPath = W2S(cfg->lpBinaryPathName);
            if (IsSuspiciousPath(binPath)) {
                flag = true; reason = "binary in user-writable/temp path";
            } else if (!IsSystemBin(binPath) && !IsTrustedBin(binPath) && !binPath.empty()) {
                flag = true;
                reason = svc.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING
                             ? "RUNNING from non-standard path"
                             : "binary outside standard paths";
            }
            std::string lp = Lower(binPath);
            if (lp.find("powershell") != std::string::npos ||
                lp.find("-enc")       != std::string::npos ||
                lp.find("cmd.exe")    != std::string::npos) {
                flag = true; reason += " | LOLBin in binary path";
            }
        }
        CloseServiceHandle(hs);

        if (flag) {
            const char* state =
                svc.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING  ? "RUNNING" :
                svc.ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED  ? "STOPPED" : "OTHER";
            out << "  [" << state << "] " << W2S(svc.lpServiceName)
                << " — " << W2S(svc.lpDisplayName) << "\n"
                << "    Path  : " << binPath << "\n"
                << "    Reason: " << reason  << "\n";
            if (++hits >= 40) { out << "  ...(truncated)\n"; break; }
        }
    }
    CloseServiceHandle(scm);
    if (!hits) out << "  (none detected)\n";
    out << "\n";
    return out.str();
}

/* ══════════════════════════════════════════════════════════
 *  5. SCHEDULED TASKS  (Task Scheduler COM, raw BSTR/VARIANT)
 * ══════════════════════════════════════════════════════════ */

/* BSTR helpers that don't need _bstr_t */
static std::string BS(BSTR b) { return b ? W2S(b) : std::string(); }

static bool BadAction(const std::string& cmd) {
    std::string lc = Lower(cmd);

    /* rundll32 calling a system DLL is normal for Windows scheduled tasks.
       Only flag it when the DLL path is outside Windows directories. */
    if (lc.find("rundll32") != std::string::npos) {
        bool sysPath = lc.find("%windir%")      != std::string::npos ||
                       lc.find("%systemroot%")  != std::string::npos ||
                       lc.find("\\windows\\")   != std::string::npos ||
                       lc.find("\\system32\\")  != std::string::npos ||
                       lc.find("\\syswow64\\")  != std::string::npos;
        if (!sysPath) return true;
        /* sysPath rundll32 — fall through to check other indicators */
    }

    /* \appdata\ is suspicious UNLESS it is a known Microsoft product path
       (e.g. OneDrive, Teams, Office live in %localappdata%\Microsoft\). */
    bool hasAppdata = lc.find("\\appdata\\")    != std::string::npos ||
                      lc.find("%localappdata%") != std::string::npos ||
                      lc.find("%appdata%")      != std::string::npos;
    if (hasAppdata) {
        bool msftApp = lc.find("\\appdata\\local\\microsoft\\")   != std::string::npos ||
                       lc.find("\\appdata\\roaming\\microsoft\\")  != std::string::npos ||
                       lc.find("%localappdata%\\microsoft\\")      != std::string::npos ||
                       lc.find("%appdata%\\microsoft\\")           != std::string::npos;
        if (!msftApp) return true;
    }

    static const char* bad[] = {
        "powershell","-enc","-encodedcommand","cmd.exe /c",
        "wscript","cscript","mshta","regsvr32",
        "certutil","bitsadmin",
        "\\temp\\","\\tmp\\","\\public\\",
        nullptr
    };
    for (int i = 0; bad[i]; ++i)
        if (lc.find(bad[i]) != std::string::npos) return true;
    return false;
}

static void ScanFolder(ITaskFolder* folder, const std::string& fpath,
                        std::ostringstream& out, int& hits) {
    if (hits >= 40) return;

    /* tasks in this folder */
    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks))) {
        LONG cnt = 0; tasks->get_Count(&cnt);
        for (LONG i = 1; i <= cnt && hits < 40; i++) {
            IRegisteredTask* task = nullptr;
            VARIANT vi; VariantInit(&vi);
            vi.vt = VT_I4; vi.lVal = i;
            if (FAILED(tasks->get_Item(vi, &task))) { VariantClear(&vi); continue; }
            VariantClear(&vi);

            BSTR bName = nullptr; task->get_Name(&bName);
            std::string tName = BS(bName); SysFreeString(bName);

            std::string actions, author;
            ITaskDefinition* def = nullptr;
            if (SUCCEEDED(task->get_Definition(&def))) {
                IActionCollection* ac = nullptr;
                if (SUCCEEDED(def->get_Actions(&ac))) {
                    LONG aCnt = 0; ac->get_Count(&aCnt);
                    for (LONG j = 1; j <= aCnt; j++) {
                        IAction* act = nullptr;
                        if (FAILED(ac->get_Item(j, &act))) continue;
                        TASK_ACTION_TYPE at; act->get_Type(&at);
                        if (at == TASK_ACTION_EXEC) {
                            IExecAction* ea = nullptr;
                            if (SUCCEEDED(act->QueryInterface(IID_IExecAction, (void**)&ea))) {
                                BSTR p = nullptr, a = nullptr;
                                ea->get_Path(&p); ea->get_Arguments(&a);
                                if (p) actions += BS(p) + " ";
                                if (a) actions += BS(a);
                                SysFreeString(p); SysFreeString(a);
                                ea->Release();
                            }
                        }
                        act->Release();
                    }
                    ac->Release();
                }
                IRegistrationInfo* ri = nullptr;
                if (SUCCEEDED(def->get_RegistrationInfo(&ri))) {
                    BSTR ba = nullptr; ri->get_Author(&ba);
                    author = BS(ba); SysFreeString(ba);
                    ri->Release();
                }
                def->Release();
            }

            VARIANT_BOOL enabled = VARIANT_FALSE;
            task->get_Enabled(&enabled);
            task->Release();

            std::string fp = fpath + "\\" + tName;
            std::string lfp = Lower(fp);
            /* A task is considered Microsoft if: its path is under \Microsoft\
               or \Windows\, OR the registered author is "Microsoft Corporation".
               OneDrive tasks live at \OneDrive\... but are authored by Microsoft. */
            bool isMsft  = lfp.find("microsoft") != std::string::npos ||
                           lfp.find("\\windows\\") != std::string::npos ||
                           Lower(author).find("microsoft corporation") != std::string::npos;
            bool badAct  = BadAction(actions);
            /* A task whose action runs only Windows system binaries is safe
               even if the task folder path / author don't say "Microsoft".
               e.g. dsregcmd.exe /checkrecovery lives at \Microsoft\Windows\AAD\
               but on some builds the author field is blank. */
            std::string lac = Lower(actions);
            bool sysAction = !actions.empty() && (
                lac.find("%systemroot%") != std::string::npos ||
                lac.find("%windir%")     != std::string::npos ||
                lac.find("\\windows\\")  != std::string::npos ||
                lac.find("\\system32\\") != std::string::npos ||
                lac.find("\\syswow64\\") != std::string::npos);
            if ((!isMsft && !sysAction) || badAct) {
                std::string reason;
                if (!isMsft && !sysAction) reason += "non-Microsoft task; ";
                if (badAct)  reason += "suspicious command; ";
                out << "  [TASK] " << fp << "\n"
                    << "    Action : " << (actions.empty() ? "(none)" : actions.substr(0,300)) << "\n"
                    << "    Author : " << (author.empty() ? "N/A" : author) << "\n"
                    << "    Enabled: " << (enabled == VARIANT_TRUE ? "Yes" : "No") << "\n"
                    << "    Reason : " << reason << "\n";
                ++hits;
            }
        }
        tasks->Release();
    }

    /* recurse sub-folders */
    ITaskFolderCollection* subs = nullptr;
    if (SUCCEEDED(folder->GetFolders(0, &subs))) {
        LONG fc = 0; subs->get_Count(&fc);
        for (LONG i = 1; i <= fc && hits < 40; i++) {
            ITaskFolder* sub = nullptr;
            VARIANT vi; VariantInit(&vi);
            vi.vt = VT_I4; vi.lVal = i;
            if (FAILED(subs->get_Item(vi, &sub))) { VariantClear(&vi); continue; }
            VariantClear(&vi);
            BSTR bn = nullptr; sub->get_Name(&bn);
            std::string sname = fpath + "\\" + BS(bn);
            SysFreeString(bn);
            ScanFolder(sub, sname, out, hits);
            sub->Release();
        }
        subs->Release();
    }
}

static std::string CheckTasks() {
    std::ostringstream out;
    out << "=== UNUSUAL SCHEDULED TASKS ===\n";
    int hits = 0;

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ITaskService* svc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
                                  CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc);
    if (FAILED(hr)) {
        out << "  (CoCreateInstance failed 0x" << std::hex << (unsigned)hr << ")\n\n";
        CoUninitialize(); return out.str();
    }

    VARIANT empty; VariantInit(&empty);
    hr = svc->Connect(empty, empty, empty, empty);
    VariantClear(&empty);

    if (FAILED(hr)) {
        svc->Release();
        out << "  (Connect failed)\n\n";
        CoUninitialize(); return out.str();
    }

    ITaskFolder* root = nullptr;
    BSTR rootPath = SysAllocString(L"\\");
    if (SUCCEEDED(svc->GetFolder(rootPath, &root))) {
        ScanFolder(root, "", out, hits);
        root->Release();
    }
    SysFreeString(rootPath);
    svc->Release();
    CoUninitialize();

    if (!hits) out << "  (none detected)\n";
    out << "\n";
    return out.str();
}

/* ══════════════════════════════════════════════════════════
 *  6. HTTP POST  (WinHTTP)
 * ══════════════════════════════════════════════════════════ */
static bool PostReport(const std::string& body) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, SOC_HOST, -1, nullptr, 0);
    std::wstring whost(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, SOC_HOST, -1, &whost[0], wlen);
    while (!whost.empty() && whost.back() == L'\0') whost.pop_back();

    int plen = MultiByteToWideChar(CP_UTF8, 0, SOC_PATH, -1, nullptr, 0);
    std::wstring wpath(plen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, SOC_PATH, -1, &wpath[0], plen);
    while (!wpath.empty() && wpath.back() == L'\0') wpath.pop_back();

    HINTERNET hSess = WinHttpOpen(L"SOC-Agent/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) return false;

    HINTERNET hConn = WinHttpConnect(hSess, whost.c_str(), (INTERNET_PORT)SOC_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); return false; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return false;
    }

    static const wchar_t* hdrs = L"Content-Type: text/plain; charset=utf-8\r\n";
    bool ok = WinHttpSendRequest(hReq, hdrs, (DWORD)-1L,
                  (LPVOID)body.c_str(), (DWORD)body.size(),
                  (DWORD)body.size(), 0) &&
              WinHttpReceiveResponse(hReq, nullptr);

    if (ok) {
        DWORD code = 0, csz = sizeof code;
        WinHttpQueryHeaders(hReq,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &code, &csz,
            WINHTTP_NO_HEADER_INDEX);
        ok = (code >= 200 && code < 300);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return ok;
}

/* ══════════════════════════════════════════════════════════
 *  MAIN
 * ══════════════════════════════════════════════════════════ */
int main() {
    wchar_t cname[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD cnl = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(cname, &cnl);

    wchar_t uname[256] = {}; DWORD unl = 256;
    GetUserNameW(uname, &unl);

    std::string osName = "Windows";
    {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
            wchar_t prod[256] = {}; DWORD sz = sizeof prod;
            RegQueryValueExW(hk, L"ProductName", nullptr, nullptr, (BYTE*)prod, &sz);
            wchar_t build[64] = {}; sz = sizeof build;
            RegQueryValueExW(hk, L"CurrentBuildNumber", nullptr, nullptr, (BYTE*)build, &sz);
            osName = W2S(prod) + " (build " + W2S(build) + ")";
            RegCloseKey(hk);
        }
    }

    std::ostringstream rep;
    rep << "=================================================\n"
        << "  SOC ENDPOINT TRIAGE REPORT\n"
        << "=================================================\n"
        << "Host     : " << W2S(cname)  << "\n"
        << "User     : " << W2S(uname)  << "\n"
        << "OS       : " << osName       << "\n"
        << "DateTime : " << NowStr()     << "\n"
        << "Server   : " << SOC_HOST << ":" << SOC_PORT << "\n"
        << "Build    : " << BUILD_TS     << "\n"
        << "=================================================\n\n";

    rep << CheckRegistry();
    rep << CheckPorts();
    rep << CheckSystem32();
    rep << CheckServices();
    rep << CheckTasks();
    rep << "=================================================\n"
        << "END OF REPORT\n";

    std::string body = rep.str();

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w;
    WriteConsoleA(hOut, body.c_str(), (DWORD)body.size(), &w, nullptr);

    printf("\n[*] POSTing to %s:%d%s ...\n", SOC_HOST, SOC_PORT, SOC_PATH);
    bool ok = PostReport(body);
    printf(ok ? "[+] Delivered.\n" : "[-] POST failed.\n");
    return ok ? 0 : 1;
}
