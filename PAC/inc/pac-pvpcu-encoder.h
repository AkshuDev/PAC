#pragma once

#define PAC_PVPCU_ASM_ELF

#include <stdbool.h>
#include <pac-asm.h>

#define EM_PVCPU 0x5650
#define R_PVCPU_64 0x80001000
#define R_PVCPU_32 0x80001001
#define R_PVCPU_16 0x80001002
#define R_PVCPU_8 0x80001003

bool encode_pvcpu(Assembler* ctx, const char* output_file, IRList* irlist, int bits);
