/* Aegis ETW consumer — Microsoft-Windows-Kernel-Process.
 *
 * Subscribes to the kernel process provider (ID 1 = Start, ID 2 = Stop) and
 * optionally to Microsoft-Windows-Kernel-Network TCP connect (ID 12), then
 * writes one JSON object per line to stdout. The unified Go agent is the
 * consumer; this file deliberately has no HTTP/client code.
 *
 *   aegis-etw.exe [--session NAME] [--replace]
 *
 * Runtime: Windows 10+, administrator privileges (kernel trace session).
 * Build check (MinGW):
 *   x86_64-w64-mingw32-gcc -O2 -Wall aegis_etw.c -o aegis-etw.exe \
 *       -ladvapi32 -ltdh -lws2_32
 *
 * Contract notes:
 * - ts_ns is monotonic (QPC), ts_wall_ns is the ETW event FILETIME. They are
 *   separate fields on purpose: an ETW wall clock must never masquerade as a
 *   monotonic timestamp.
 * - ETW Kernel-Network ID 12 is "connection attempted", not "established".
 *   We emit it because it is still useful outbound evidence, but mark it
 *   quality=degraded:etw-connect-attempt instead of pretending a handshake
 *   completed. The Brain can therefore distinguish it from eBPF ESTABLISHED.
 * - Windows paths contain backslashes. They go through json_write_wstring(),
 *   not printf("%s"), so C:\Windows\... is valid JSON.
 */
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Microsoft-Windows-Kernel-Process */
static const GUID KERNEL_PROCESS_PROVIDER = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}
};
/* Microsoft-Windows-Kernel-Network */
static const GUID KERNEL_NETWORK_PROVIDER = {
    0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}
};
/* Session GUID: not a provider GUID. It identifies this private session. */
static const GUID AEGIS_ETW_SESSION_GUID = {
    0x2f6c8a51, 0x4c6e, 0x4f6b, {0x9a, 0x1e, 0x7d, 0x52, 0x31, 0x44, 0x8c, 0x01}
};

#define KEYWORD_PROCESS 0x10ULL
#define KEYWORD_TCPIP   0x10ULL
#define EVT_ID_PROCESS_START 1
#define EVT_ID_PROCESS_STOP  2
/* Microsoft-Windows-Kernel-Network: 12 = TcpIp/Connection attempted (IPv4). */
#define EVT_ID_TCP_CONNECT_ATTEMPT 12
#define MAX_IMAGE_CHARS 1024

static TRACEHANDLE g_session = 0;
static volatile int g_running = 1;

/* The manifest requests elevation for manual launches. This runtime check is
 * still required: a service or a parent process can start the helper with a
 * filtered token, and StartTrace would then fail with a misleading error. */
static int is_elevated(void)
{
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID administrators = NULL;
    BOOL member = FALSE;

    if (!AllocateAndInitializeSid(&nt_authority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &administrators))
        return 0;
    if (!CheckTokenMembership(NULL, administrators, &member))
        member = FALSE;
    FreeSid(administrators);
    return member ? 1 : 0;
}

static BOOL WINAPI on_ctrl(DWORD type)
{
    (void)type;
    g_running = 0;
    return TRUE;
}

/* Write a wide string as a UTF-8 JSON string literal. The previous code used
 * printf("%s") on a wchar_t buffer and a separate json_escape() that was never
 * called: paths such as C:\Windows\System32\cmd.exe produced invalid JSON. */
static void json_write_wstring(FILE *f, const wchar_t *s)
{
    if (!s) {
        fputs("\"\"", f);
        return;
    }

    int bytes = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (bytes <= 0) {
        fputs("\"\"", f);
        return;
    }
    char *buf = (char *)malloc((size_t)bytes);
    if (!buf) {
        fputs("\"\"", f);
        return;
    }
    if (WideCharToMultiByte(CP_UTF8, 0, s, -1, buf, bytes, NULL, NULL) <= 0) {
        free(buf);
        fputs("\"\"", f);
        return;
    }

    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)buf; *p; p++) {
        switch (*p) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\b': fputs("\\b", f); break;
        case '\f': fputs("\\f", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (*p < 0x20)
                fprintf(f, "\\u%04x", (unsigned int)*p);
            else
                fputc(*p, f);
            break;
        }
    }
    fputc('"', f);
    free(buf);
}

static int tdh_get_raw(PEVENT_RECORD rec, const wchar_t *name,
                       BYTE *out, ULONG out_size, ULONG *actual_size)
{
    PROPERTY_DATA_DESCRIPTOR desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.PropertyName = (ULONGLONG)(ULONG_PTR)name;
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, NULL, 1, &desc, &size) != ERROR_SUCCESS)
        return -1;
    if (size == 0 || size > out_size)
        return -1;
    if (TdhGetProperty(rec, 0, NULL, 1, &desc, size, out) != ERROR_SUCCESS)
        return -1;
    if (actual_size)
        *actual_size = size;
    return 0;
}

static int tdh_u32(PEVENT_RECORD rec, const wchar_t *name, ULONG *out)
{
    BYTE buf[16];
    ULONG size = 0;
    if (tdh_get_raw(rec, name, buf, sizeof(buf), &size) != 0 || size < sizeof(ULONG))
        return -1;
    memcpy(out, buf, sizeof(ULONG));
    return 0;
}

static int tdh_u16(PEVENT_RECORD rec, const wchar_t *name, USHORT *out)
{
    BYTE buf[16];
    ULONG size = 0;
    if (tdh_get_raw(rec, name, buf, sizeof(buf), &size) != 0 || size < sizeof(USHORT))
        return -1;
    memcpy(out, buf, sizeof(USHORT));
    return 0;
}

static int tdh_wstring(PEVENT_RECORD rec, const wchar_t *name,
                       wchar_t *out, size_t out_chars)
{
    if (!out || out_chars == 0)
        return -1;
    out[0] = L'\0';

    BYTE buf[8192];
    ULONG size = 0;
    if (tdh_get_raw(rec, name, buf, sizeof(buf), &size) != 0)
        return -1;
    if (size < sizeof(wchar_t))
        return -1;

    size_t chars = size / sizeof(wchar_t);
    if (chars >= out_chars)
        chars = out_chars - 1;
    memcpy(out, buf, chars * sizeof(wchar_t));
    out[chars] = L'\0';
    return 0;
}

/* ProcessStop v0/v1 declares ImageName as win:AnsiString, while ProcessStart
 * declares it as win:UnicodeString. Reading the stop field as UTF-16 produced
 * CJK-looking mojibake (for example "cmd.exe" became a sequence of CJK
 * codepoints). Decode by the schema type instead of assuming one encoding. */
static int tdh_ansistring(PEVENT_RECORD rec, const wchar_t *name,
                          wchar_t *out, size_t out_chars)
{
    if (!out || out_chars == 0)
        return -1;
    out[0] = L'\0';

    char buf[8192];
    ULONG size = 0;
    if (tdh_get_raw(rec, name, (BYTE *)buf, sizeof(buf), &size) != 0)
        return -1;
    if (size == 0)
        return -1;
    buf[sizeof(buf) - 1] = '\0';
    if (MultiByteToWideChar(CP_ACP, 0, buf, -1, out, (int)out_chars) <= 0) {
        out[0] = L'\0';
        return -1;
    }
    return 0;
}

static unsigned long long filetime_to_unix_ns(LONGLONG ft)
{
    /* FILETIME is 100ns intervals since 1601-01-01. */
    const LONGLONG epoch = 116444736000000000LL;
    if (ft <= epoch)
        return 0;
    return (unsigned long long)(ft - epoch) * 100ULL;
}

static unsigned long long monotonic_ns(void)
{
    LARGE_INTEGER counter, frequency;
    if (!QueryPerformanceCounter(&counter) || !QueryPerformanceFrequency(&frequency) ||
        frequency.QuadPart <= 0) {
        return 0;
    }
    return (unsigned long long)((double)counter.QuadPart * 1000000000.0 /
                                (double)frequency.QuadPart);
}

static unsigned long long event_wall_ns(PEVENT_RECORD rec)
{
    /* EventHeader.TimeStamp is the event time, not the time we happened to
     * process it. That distinction matters when the consumer is delayed. */
    return filetime_to_unix_ns(rec->EventHeader.TimeStamp.QuadPart);
}

static void write_timestamps(PEVENT_RECORD rec)
{
    printf("\"ts_ns\":%llu,\"ts_wall_ns\":%llu",
           monotonic_ns(), event_wall_ns(rec));
}

static void on_network_event(PEVENT_RECORD rec)
{
    if (rec->EventHeader.EventDescriptor.Id != EVT_ID_TCP_CONNECT_ATTEMPT)
        return;

    ULONG pid = 0, daddr = 0;
    USHORT dport = 0;
    if (tdh_u32(rec, L"PID", &pid) != 0 || pid == 0)
        return;
    if (tdh_u32(rec, L"daddr", &daddr) != 0 || daddr == 0)
        return;
    if (tdh_u16(rec, L"dport", &dport) != 0 || dport == 0)
        return;

    ULONG ip = ntohl(daddr);
    USHORT port = ntohs(dport);

    fputc('{', stdout);
    write_timestamps(rec);
    printf(",\"pid\":%lu,\"ppid\":0,\"uid\":0,\"comm\":\"\",\"filename\":\"\","
           "\"event_type\":\"CONNECTION_ESTABLISHED\",\"proto\":\"tcp\","
           "\"direction\":\"outbound\",\"quality\":\"degraded:etw-connect-attempt\","
           "\"remote\":\"%lu.%lu.%lu.%lu:%u\"}\n",
           pid,
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
           (unsigned int)port);
    fflush(stdout);
}

static void on_process_event(PEVENT_RECORD rec)
{
    USHORT id = rec->EventHeader.EventDescriptor.Id;
    if (id != EVT_ID_PROCESS_START && id != EVT_ID_PROCESS_STOP)
        return;

    ULONG pid = 0, ppid = 0, exit_status = 0;
    int has_exit = 0;
    wchar_t image[MAX_IMAGE_CHARS] = L"";

    if (tdh_u32(rec, L"ProcessID", &pid) != 0 || pid == 0)
        return;
    (void)tdh_u32(rec, L"ParentProcessID", &ppid);
    if (id == EVT_ID_PROCESS_START)
        (void)tdh_wstring(rec, L"ImageName", image, MAX_IMAGE_CHARS);
    else {
        (void)tdh_ansistring(rec, L"ImageName", image, MAX_IMAGE_CHARS);
        has_exit = (tdh_u32(rec, L"ExitCode", &exit_status) == 0);
    }

    const wchar_t *comm = image;
    const wchar_t *slash = wcsrchr(image, L'\\');
    if (slash)
        comm = slash + 1;

    fputc('{', stdout);
    write_timestamps(rec);
    printf(",\"pid\":%lu,\"ppid\":%lu,\"uid\":0,\"comm\":", pid, ppid);
    json_write_wstring(stdout, comm);
    printf(",\"filename\":");
    json_write_wstring(stdout, image);
    printf(",\"event_type\":\"%s\"",
           id == EVT_ID_PROCESS_START ? "PROCESS_CREATED" : "PROCESS_EXITED");
    if (id == EVT_ID_PROCESS_STOP && has_exit)
        printf(",\"exit_code\":%lu", exit_status);
    printf("}\n");
    fflush(stdout);
}

static VOID WINAPI on_event(PEVENT_RECORD rec)
{
    if (IsEqualGUID(&rec->EventHeader.ProviderId, &KERNEL_NETWORK_PROVIDER)) {
        on_network_event(rec);
        return;
    }
    if (IsEqualGUID(&rec->EventHeader.ProviderId, &KERNEL_PROCESS_PROVIDER))
        on_process_event(rec);
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s [--session NAME] [--replace]\n"
            "  --session NAME  trace session name (default AegisKernelProcess)\n"
            "  --replace       stop an existing session with the same name first\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *session_name = "AegisKernelProcess";
    int replace = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--session") && i + 1 < argc) {
            session_name = argv[++i];
        } else if (!strcmp(argv[i], "--replace")) {
            replace = 1;
        } else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    if (!is_elevated()) {
        fprintf(stderr,
                "aegis-etw: administrator privileges are required; refusing "
                "to start with a filtered token. Launch it elevated or run it "
                "from the AegisAgent service (LocalSystem).\n");
        return 2;
    }
    if (strlen(session_name) == 0 || strlen(session_name) > 1024) {
        fprintf(stderr, "invalid session name\n");
        return 2;
    }

    const ULONG buf_size = sizeof(EVENT_TRACE_PROPERTIES) + 4096;
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)calloc(1, buf_size);
    if (!props)
        return 1;

    props->Wnode.BufferSize = buf_size;
    props->Wnode.Guid = AEGIS_ETW_SESSION_GUID;
    props->Wnode.ClientContext = 1; /* QPC */
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer = 1;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    strncpy((char *)props + props->LoggerNameOffset, session_name, 1024 - 1);

    ULONG status = StartTraceA(&g_session, session_name, props);
    if (status == ERROR_ALREADY_EXISTS && replace) {
        fprintf(stderr, "aegis-etw: replacing existing session %s\n", session_name);
        ULONG stop = ControlTraceA(0, session_name, props, EVENT_TRACE_CONTROL_STOP);
        if (stop != ERROR_SUCCESS && stop != ERROR_WMI_INSTANCE_NOT_FOUND) {
            fprintf(stderr, "ControlTrace(stop existing): %lu\n", stop);
            free(props);
            return 1;
        }
        status = StartTraceA(&g_session, session_name, props);
    }
    if (status != ERROR_SUCCESS) {
        if (status == ERROR_ALREADY_EXISTS) {
            fprintf(stderr,
                    "StartTrace: session %s already exists (another agent or a "
                    "stale session). Stop it explicitly with `logman stop %s -ets` "
                    "or pass --replace.\n", session_name, session_name);
        } else if (status == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "StartTrace: access denied (run as administrator)\n");
        } else {
            fprintf(stderr, "StartTrace: %lu\n", status);
        }
        free(props);
        return 1;
    }

    ENABLE_TRACE_PARAMETERS params;
    ZeroMemory(&params, sizeof(params));
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    params.EnableProperty = EVENT_ENABLE_PROPERTY_SID;

    status = EnableTraceEx2(g_session, &KERNEL_PROCESS_PROVIDER,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, KEYWORD_PROCESS, 0, 0, &params);
    if (status != ERROR_SUCCESS) {
        fprintf(stderr, "EnableTraceEx2(process): %lu\n", status);
        ControlTraceA(g_session, session_name, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        return 1;
    }

    status = EnableTraceEx2(g_session, &KERNEL_NETWORK_PROVIDER,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, KEYWORD_TCPIP, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        /* Process events are the core contract. Network is additive and the
         * degradation is visible to the operator; do not claim it is active. */
        fprintf(stderr, "EnableTraceEx2(network): %lu (process events only)\n", status);
    }

    EVENT_TRACE_LOGFILEA logfile;
    ZeroMemory(&logfile, sizeof(logfile));
    logfile.LoggerName = (LPSTR)session_name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = on_event;

    TRACEHANDLE consumer = OpenTraceA(&logfile);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "OpenTrace: %lu\n", GetLastError());
        ControlTraceA(g_session, session_name, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        return 1;
    }

    SetConsoleCtrlHandler(on_ctrl, TRUE);
    fprintf(stderr, "aegis-etw: listening (session=%s)\n", session_name);
    ULONG prc = ProcessTrace(&consumer, 1, NULL, NULL);
    if (prc != ERROR_SUCCESS && g_running)
        fprintf(stderr, "ProcessTrace: %lu\n", prc);

    CloseTrace(consumer);
    ControlTraceA(g_session, session_name, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
    return prc == ERROR_SUCCESS || !g_running ? 0 : 1;
}
