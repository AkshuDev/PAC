#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <pac-asm.h>
#include <pac-extra.h>
#include <pac-arm64-encoder.h>

typedef struct {
    uint8_t id; // 0–31
    uint8_t bits;
    bool is_sp;
    bool is_zr;
} RegInfo;


