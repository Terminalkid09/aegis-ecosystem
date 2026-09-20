/* Aegis ETW consumer — Microsoft-Windows-Kernel-Process (niente polling).
 *
 * Sottoscrive il provider kernel per gli eventi di creazione/terminazione
 * processi (ID 1 = Start, ID 2 = Stop) e stampa una riga JSON per evento su
 * stdout, stesso contratto del collector eBPF (EventSchema / PROCESS_CREATED).
 *
 *   aegis-etw.exe [--session NAME]
 *
 * Requisiti runtime: Windows 10+, privilegi di amministrazione (logger kernel),
 * provider GUID {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}, keyword PROCESS 0x10.
 * Compile check (mingw, senza esecuzione):
 *   gcc -O2 -Wall aegis_etw.c -o aegis-etw.exe -ladvapi32 -ltdh
 *
 * NOTA onesta: senza admin non si apre il kernel logger — la validazione
 * runtime va fatta in lab admin (vedi README). Questo file compila pulito
 * e segue lo stesso schema del collector eBPF verificato su kernel 6.6.
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

/* Microsoft-Windows-Kernel-Process */
static const GUID KERNEL_PROCESS_PROVIDER = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}
};
/* Microsoft-Windows-Kernel-Network (TCP connect/accept, best-effort TDH) */
static const GUID KERNEL_NETWORK_PROVIDER = {
    0x7dd42a49, 0x5329, 0x4832, {0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88}
};
#define KEYWORD_PROCESS 0x10
#define KEYWORD_TCPIP 0x10
#define EVT_ID_PROCESS_START 1
#define EVT_ID_PROCESS_STOP 2
/* Kernel-Network TCPIP task: 1 = Connect (documentato MS-KN). Altri ID ignorati. */
#define EVT_ID_TCP_CONNECT 1

static TRACEHANDLE g_session = 0;
static volatile int g_running = 1;

static BOOL WINAPI on_ctrl(DWORD type)
{
    (void)type;
    g_running = 0;
    return TRUE;
}

static void json_escape(FILE *f, const wchar_t *s)
{
    fputwc(L'"', f);
    for (; *s; s++) {
        if (*s == L'"' || *s == L'\\')
            fwprintf(f, L"\\%c", (char)*s);
        else if (*s < 0x20)
            fwprintf(f, L"\\u%04x", *s);
        else
            fputwc(*s, f);
    }
    fputwc(L'"', f);
}

/* Legge una proprietà UnicodeString/UInt32 via TDH. Ritorna 0 se ok. */
static int tdh_property(PEVENT_RECORD rec, const wchar_t *name,
                        wchar_t *out_str, size_t out_chars, ULONG *out_u32)
{
    PROPERTY_DATA_DESCRIPTOR desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    ULONG status = TdhGetPropertySize(rec, 0, NULL, 1, &desc, &size);
    if (status != ERROR_SUCCESS)
        return -1;
    BYTE *buf = (BYTE *)malloc(size);
    if (!buf)
        return -1;
    status = TdhGetProperty(rec, 0, NULL, 1, &desc, size, buf);
    if (status != ERROR_SUCCESS) {
        free(buf);
        return -1;
    }
    if (out_str) {
        size_t n = (size / sizeof(wchar_t));
        if (n > out_chars - 1)
            n = out_chars - 1;
        memcpy(out_str, buf, n * sizeof(wchar_t));
        out_str[n] = L'\0';
    } else if (out_u32) {
        *out_u32 = *(ULONG *)buf;
    }
    free(buf);
    return 0;
}

/* Rete: TcpIp Connect -> CONNECTION_ESTABLISHED (best-effort TDH).
 * daddr UINT32 + dport UINT16 negli eventi Kernel-Network; se un campo
 * manca si scarta in silenzio (niente falsi eventi). */
static VOID on_network_event(PEVENT_RECORD rec)
{
    if (rec->EventHeader.EventDescriptor.Id != EVT_ID_TCP_CONNECT)
        return;
    ULONG pid = 0, daddr = 0, dport = 0;
    if (tdh_property(rec, L"PID", NULL, 0, &pid) != 0 || pid == 0)
        return;
    if (tdh_property(rec, L"daddr", NULL, 0, &daddr) != 0 || daddr == 0)
        return;
    if (tdh_property(rec, L"dport", NULL, 0, &dport) != 0 || dport == 0)
        return;
    /* daddr arriva network-order: ntohl per dotted quad. */
    ULONG ip = ntohl(daddr);
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER t;
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    unsigned long long ts_ns = (t.QuadPart - 116444736000000000ULL) * 100ULL;
    printf("{\"ts_ns\":%llu,\"pid\":%lu,\"ppid\":0,\"uid\":0,\"comm\":\"\","
           "\"filename\":\"\",\"event_type\":\"CONNECTION_ESTABLISHED\","
           "\"remote\":\"%lu.%lu.%lu.%lu:%lu\"}\n",
           ts_ns, pid,
           (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
           dport & 0xFFFF);
    fflush(stdout);
}

static VOID WINAPI on_event(PEVENT_RECORD rec)
{
    if (IsEqualGUID(&rec->EventHeader.ProviderId, &KERNEL_NETWORK_PROVIDER)) {
        on_network_event(rec);
        return;
    }
    if (!IsEqualGUID(&rec->EventHeader.ProviderId, &KERNEL_PROCESS_PROVIDER))
        return;
    USHORT id = rec->EventHeader.EventDescriptor.Id;
    if (id != EVT_ID_PROCESS_START && id != EVT_ID_PROCESS_STOP)
        return;

    ULONG pid = 0, ppid = 0;
    ULONG exit_status = 0;
    int has_exit = 0;
    wchar_t image[512] = L"";
    tdh_property(rec, L"ProcessID", NULL, 0, &pid);
    tdh_property(rec, L"ParentProcessID", NULL, 0, &ppid);
    tdh_property(rec, L"ImageName", image, 512, NULL);
    if (id == EVT_ID_PROCESS_STOP)
        has_exit = (tdh_property(rec, L"ExitStatus", NULL, 0, &exit_status) == 0);

    /* comm = basename di ImageName */
    const wchar_t *comm = image;
    const wchar_t *slash = wcsrchr(image, L'\\');
    if (slash)
        comm = slash + 1;

    /* ts_ns wall-clock: FILETIME (100ns dal 1601) -> unix ns */
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER t;
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    unsigned long long ts_ns = (t.QuadPart - 116444736000000000ULL) * 100ULL;

    /* uid: i SID Windows non si mappano in UID Unix — contratto dice 0 */
    printf("{\"ts_ns\":%llu,\"pid\":%lu,\"ppid\":%lu,\"uid\":0,\"comm\":\"",
           ts_ns, pid, ppid);
    /* comm ascii-safe */
    for (const wchar_t *p = comm; *p; p++)
        putchar(*p < 0x80 ? (char)*p : '?');
    printf("\",\"filename\":\"");
    for (const wchar_t *p = image; *p; p++)
        putchar(*p < 0x80 ? (char)*p : '?');
    printf("\",\"event_type\":\"%s\"", id == EVT_ID_PROCESS_START ? "PROCESS_CREATED" : "PROCESS_EXITED");
    if (id == EVT_ID_PROCESS_STOP && has_exit)
        printf(",\"exit_code\":%lu", exit_status);
    printf("}\n");
    fflush(stdout);
    (void)json_escape;
}

int main(int argc, char **argv)
{
    const char *session_name = "AegisKernelProcess";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--session") && i + 1 < argc)
            session_name = argv[++i];
    }

    ULONG buf_size = sizeof(EVENT_TRACE_PROPERTIES) + 4096;
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES *)calloc(1, buf_size);
    if (!props)
        return 1;
    props->Wnode.BufferSize = buf_size;
    props->Wnode.Guid = KERNEL_PROCESS_PROVIDER;
    props->Wnode.ClientContext = 1; /* QPC clock */
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceA(&g_session, session_name, props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        fprintf(stderr, "StartTrace: %lu (serve admin)\n", status);
        free(props);
        return 1;
    }
    /* Se la sessione esisteva già, la riusiamo. */
    if (status == ERROR_ALREADY_EXISTS) {
        status = ControlTraceA(0, session_name, props, EVENT_TRACE_CONTROL_QUERY);
        if (status != ERROR_SUCCESS) {
            fprintf(stderr, "ControlTrace QUERY: %lu\n", status);
            free(props);
            return 1;
        }
        g_session = props->Wnode.HistoricalContext;
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
        free(props);
        return 1;
    }
    status = EnableTraceEx2(g_session, &KERNEL_NETWORK_PROVIDER,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, KEYWORD_TCPIP, 0, 0, &params);
    if (status != ERROR_SUCCESS) {
        /* Non fatale: processi ok, rete degradata (log e continua). */
        fprintf(stderr, "EnableTraceEx2(network): %lu (solo processi)\n", status);
    }

    EVENT_TRACE_LOGFILEA logfile;
    ZeroMemory(&logfile, sizeof(logfile));
    logfile.LoggerName = (LPSTR)session_name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = on_event;

    TRACEHANDLE h = OpenTraceA(&logfile);
    if (h == INVALID_PROCESSTRACE_HANDLE) {
        fprintf(stderr, "OpenTrace: %lu\n", GetLastError());
        free(props);
        return 1;
    }

    SetConsoleCtrlHandler(on_ctrl, TRUE);
    fprintf(stderr, "aegis-etw: listening (session=%s)\n", session_name);
    ULONG prc = ProcessTrace(&h, 1, NULL, NULL);
    if (prc != ERROR_SUCCESS && g_running)
        fprintf(stderr, "ProcessTrace: %lu\n", prc);

    CloseTrace(h);
    ControlTraceA(g_session, session_name, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
    return 0;
}
