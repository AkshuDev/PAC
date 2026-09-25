#pragma once

#include <stddef.h>
#include <pac-extra.h>
#include <pac-asm.h>
#include <stdbool.h>

typedef struct {
    uint32_t ir_idx;
    uint32_t sym_idx;
} SymbolMapEntry;

bool encode(Assembler* ctx, const char* output_file, IRList* irlist, int bits, bool unlocked, enum Architecture arch);
bool encode_binary(Assembler* ctx, const char* output_file, IRList* irlist, int bits, bool unlocked, enum Architecture arch);