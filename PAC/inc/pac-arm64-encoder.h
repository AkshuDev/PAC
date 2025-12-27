#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <pac-asm.h>

bool encode_arm64(Assembler* ctx, FILE* out, IRList* irlist, int bits, bool unlocked, size_t text_off, Section* text_sec);
