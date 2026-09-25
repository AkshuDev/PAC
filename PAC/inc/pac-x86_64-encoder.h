#pragma once

#define PAC_x86_64_ASM_ELF

#include <stdbool.h>
#include <stddef.h>
#include <pac-asm.h>
#include <pac-encoder.h>

bool encode_x86_64(Assembler* ctx, FILE* out, IRList* irlist, int bits, bool unlocked, size_t text_off, Section* text_sec, SymbolMapEntry* symbol_list, size_t symbol_list_size);
