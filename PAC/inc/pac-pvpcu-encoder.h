#pragma once

#define PAC_PVPCU_ASM_ELF

#include <stdbool.h>
#include <pac-asm.h>

#define EM_PVCPU 0x5650

bool encode_pvcpu(Assembler* ctx, const char* output_file, IRList* irlist, int bits);
bool encode_pvpcu(Assembler* ctx, const char* output_file, IRList* irlist, int bits);