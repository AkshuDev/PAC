#pragma once

#define PAC_x86_64_ASM_ELF

#include <stdbool.h>
#include <pac-asm.h>

bool encode_x86_64(Assembler* ctx, FILE* out, IRList* irlist, int bits, bool unlocked, size_t text_off, Section* text_sec);
