#pragma once

#include <stddef.h>
#include <pac-extra.h>
#include <pac-asm.h>
#include <stdbool.h>

bool encode(Assembler* ctx, const char* output_file, IRList* irlist, int bits, bool unlocked, enum Architecture arch);
