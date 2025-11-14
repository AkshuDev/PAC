#pragma once

#define PAC_x86_64_ASM_ELF

#include <stdbool.h>
#include <pac-asm.h>

bool encode_x86_64(Assembler* ctx, const char* output_file, IRList* irlist, int bits);
bool encode_x86(Assembler* ctx, const char* output_file, IRList* irlist, int bits);