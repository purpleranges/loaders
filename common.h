// MDK
// docs    : https://sebafvs.com/mdk/common
// author  : @sebafvs

#pragma once

#include <windows.h>
#include "mdk/result.h"


typedef int (*mdk_loader_payload_fn)(void);

int mdk_loader_start(IN int argc, IN char** argv, IN mdk_loader_payload_fn payload_fn);

const char* mdk_loader_shellcode_path(void);

MDK_RESULT mdk_loader_setup_bypasses(void);

void mdk_loader_cleanup_bypasses(void);

MDK_RESULT mdk_loader_payload(IN const char* arg, IN const BYTE* embedded, IN SIZE_T embedded_size, OUT PBYTE* data, OUT SIZE_T* size);
