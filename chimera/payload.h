// MDK / loaders / chimera / payload.h

#pragma once

#include <windows.h>

// xor rax, rax ; ret  (harmless placeholder, returns 0)
static const BYTE g_payload[] = { 0x48, 0x31, 0xC0, 0xC3 };
