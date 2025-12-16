#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <elf.h>

#include <pac-lexer.h>
#include <pac-parser.h>
#include <pac-extra.h>
#include <pac-err.h>

#include <pac-asm.h>
#include <pac-pvpcu-encoder.h>

#define OPCODE_BITS 0b111111111111
#define MODE_BITS 0b1111
#define RSRC_BITS 0b111111
#define RDEST_BITS 0b111111
#define FLAGS_BITS 0b1111

#define FLAGS_VALID (1 << 0) // Is It Valid????
#define FLAGS_IMM (1 << 1) // Used for memory and just numbers
#define FLAGS_EXTFLAGS (1 << 2) // Extended Flags (8 byte)
#define FLAGS_DISP (1 << 3) // 64-bit Displacement, using the registers

#define FLAGS_SHIFT 0
#define RDEST_SHIFT 4
#define RSRC_SHIFT 10
#define MODE_SHIFT 16
#define OPCODE_SHIFT 20

typedef enum {
    MODE_NULL = 0, // No mode
    MODE_REG_REG, // dest = src
    MODE_REG_IMM, // src is actually a imm! dest is a reg (dest = src (as imm))
    MODE_REG_EXTIMM, // Allows use of Bit 1 of Flags (dest = imm)
    MODE_REG_DISP, // Allows use of Bit 2 of Flags (dest = mem[disp + src])
    MODE_LOAD_REGADDR, // dest = mem[src]
    MODE_LOAD_IMMADDR, // dest = mem[imm]
    MODE_LOAD_PC_REL, // dest = mem[src (as offset) + PC]
    MODE_STORE_REGADDR, // mem[dest] = src
    MODE_STORE_IMMADDR, // mem[imm] = src
    MODE_STORE_PC_REL, // mem[dest (as offset) + PC] = src
    // Special
    MODE_SRC_REG, // (opcode) reg
    MODE_SRC_REG_IMM, // (opcode) (src as imm)
    MODE_SRC_IMM, // (opcode) imm
} Modes;

typedef struct {
    uint8_t code; // 6-bit ID
    char name[8]; // Name of register
    uint8_t size; // Operand size (8, 16, 32, 64)
    bool valid;
} RegInfo;

static void emit_bytes(FILE* out, uint8_t* bytes, size_t count) {
    fwrite(bytes, 1, count, out);
}

static RegInfo encode_register(const char *reg, bool unlocked) {
    RegInfo r = {0};

    r.valid = true;
    strncpy(r.name, reg, sizeof(r.name));

    // 64-bit (q<REG>)
    if (strcmp(reg, "qnull") == 0) { r.code = 0x0; return r; }
    else if (strcmp(reg, "qg0") == 0) { r.code = 0x1; r.size = 64; return r; }
    else if (strcmp(reg, "qg1") == 0) { r.code = 0x2; r.size = 64; return r; }
    else if (strcmp(reg, "qg2") == 0) { r.code = 0x3; r.size = 64; return r; }
    else if (strcmp(reg, "qg3") == 0) { r.code = 0x4; r.size = 64; return r; }
    else if (strcmp(reg, "qg4") == 0) { r.code = 0x5; r.size = 64; return r; }
    else if (strcmp(reg, "qg5") == 0) { r.code = 0x6; r.size = 64; return r; }
    else if (strcmp(reg, "qg6") == 0) { r.code = 0x7; r.size = 64; return r; }
    else if (strcmp(reg, "qg7") == 0) { r.code = 0x8; r.size = 64; return r; }
    else if (strcmp(reg, "qg8") == 0) { r.code = 0x9; r.size = 64; return r; }
    else if (strcmp(reg, "qg9") == 0) { r.code = 0x10; r.size = 64; return r; }
    else if (strcmp(reg, "qg10") == 0) { r.code = 0x11; r.size = 64; return r; }
    else if (strcmp(reg, "qg11") == 0) { r.code = 0x12; r.size = 64; return r; }
    else if (strcmp(reg, "qg12") == 0) { r.code = 0x13; r.size = 64; return r; }
    else if (strcmp(reg, "qg13") == 0) { r.code = 0x14; r.size = 64; return r; }
    else if (strcmp(reg, "qg14") == 0) { r.code = 0x15; r.size = 64; return r; }
    else if (strcmp(reg, "qg15") == 0) { r.code = 0x16; r.size = 64; return r; }
    else if (strcmp(reg, "qg16") == 0) { r.code = 0x17; r.size = 64; return r; }
    else if (strcmp(reg, "qg17") == 0) { r.code = 0x18; r.size = 64; return r; }
    else if (strcmp(reg, "qg18") == 0) { r.code = 0x19; r.size = 64; return r; }
    else if (strcmp(reg, "qg19") == 0) { r.code = 0x20; r.size = 64; return r; }
    else if (strcmp(reg, "qg20") == 0) { r.code = 0x21; r.size = 64; return r; }
    else if (strcmp(reg, "qg21") == 0) { r.code = 0x22; r.size = 64; return r; }
    else if (strcmp(reg, "qg22") == 0) { r.code = 0x23; r.size = 64; return r; }
    else if (strcmp(reg, "qg23") == 0) { r.code = 0x24; r.size = 64; return r; }
    else if (strcmp(reg, "qg24") == 0) { r.code = 0x25; r.size = 64; return r; }
    else if (strcmp(reg, "qg25") == 0) { r.code = 0x26; r.size = 64; return r; }
    else if (strcmp(reg, "qg26") == 0) { r.code = 0x27; r.size = 64; return r; }
    else if (strcmp(reg, "qg27") == 0) { r.code = 0x28; r.size = 64; return r; }
    else if (strcmp(reg, "qg28") == 0) { r.code = 0x29; r.size = 64; return r; }
    else if (strcmp(reg, "qg29") == 0) { r.code = 0x30; r.size = 64; return r; }
    else if (strcmp(reg, "qg30") == 0) { r.code = 0x31; r.size = 64; return r; }
    else if (strcmp(reg, "qlr") == 0) { r.code = 0x32; r.size = 64; return r; }
    else if (strcmp(reg, "qsf") == 0) { r.code = 0x33; r.size = 64; return r; }
    else if (strcmp(reg, "qsp") == 0) { r.code = 0x34; r.size = 64; return r; }

    // 32-bit
    else if (strcmp(reg, "dg0") == 0) { r.code = 0x1; r.size = 32; return r; }
    else if (strcmp(reg, "dg1") == 0) { r.code = 0x2; r.size = 32; return r; }
    else if (strcmp(reg, "dg2") == 0) { r.code = 0x3; r.size = 32; return r; }
    else if (strcmp(reg, "dg3") == 0) { r.code = 0x4; r.size = 32; return r; }
    else if (strcmp(reg, "dg4") == 0) { r.code = 0x5; r.size = 32; return r; }
    else if (strcmp(reg, "dg5") == 0) { r.code = 0x6; r.size = 32; return r; }
    else if (strcmp(reg, "dg6") == 0) { r.code = 0x7; r.size = 32; return r; }
    else if (strcmp(reg, "dg7") == 0) { r.code = 0x8; r.size = 32; return r; }
    else if (strcmp(reg, "dg8") == 0) { r.code = 0x9; r.size = 32; return r; }
    else if (strcmp(reg, "dg9") == 0) { r.code = 0x10; r.size = 32; return r; }
    else if (strcmp(reg, "dg10") == 0) { r.code = 0x11; r.size = 32; return r; }
    else if (strcmp(reg, "dg11") == 0) { r.code = 0x12; r.size = 32; return r; }
    else if (strcmp(reg, "dg12") == 0) { r.code = 0x13; r.size = 32; return r; }
    else if (strcmp(reg, "dg13") == 0) { r.code = 0x14; r.size = 32; return r; }
    else if (strcmp(reg, "dg14") == 0) { r.code = 0x15; r.size = 32; return r; }
    else if (strcmp(reg, "dg15") == 0) { r.code = 0x16; r.size = 32; return r; }
    else if (strcmp(reg, "dg16") == 0) { r.code = 0x17; r.size = 32; return r; }
    else if (strcmp(reg, "dg17") == 0) { r.code = 0x18; r.size = 32; return r; }
    else if (strcmp(reg, "dg18") == 0) { r.code = 0x19; r.size = 32; return r; }
    else if (strcmp(reg, "dg19") == 0) { r.code = 0x20; r.size = 32; return r; }
    else if (strcmp(reg, "dg20") == 0) { r.code = 0x21; r.size = 32; return r; }
    else if (strcmp(reg, "dg21") == 0) { r.code = 0x22; r.size = 32; return r; }
    else if (strcmp(reg, "dg22") == 0) { r.code = 0x23; r.size = 32; return r; }
    else if (strcmp(reg, "dg23") == 0) { r.code = 0x24; r.size = 32; return r; }
    else if (strcmp(reg, "dg24") == 0) { r.code = 0x25; r.size = 32; return r; }
    else if (strcmp(reg, "dg25") == 0) { r.code = 0x26; r.size = 32; return r; }
    else if (strcmp(reg, "dg26") == 0) { r.code = 0x27; r.size = 32; return r; }
    else if (strcmp(reg, "dg27") == 0) { r.code = 0x28; r.size = 32; return r; }
    else if (strcmp(reg, "dg28") == 0) { r.code = 0x29; r.size = 32; return r; }
    else if (strcmp(reg, "dg29") == 0) { r.code = 0x30; r.size = 32; return r; }
    else if (strcmp(reg, "dg30") == 0) { r.code = 0x31; r.size = 32; return r; }
    else if (strcmp(reg, "dlr") == 0) { r.code = 0x32; r.size = 32; return r; }
    else if (strcmp(reg, "dsf") == 0) { r.code = 0x33; r.size = 32; return r; }
    else if (strcmp(reg, "dsp") == 0) { r.code = 0x34; r.size = 32; return r; }

    // 16-bit
    else if (strcmp(reg, "wg0") == 0) { r.code = 0x1; r.size = 16; return r; }
    else if (strcmp(reg, "wg1") == 0) { r.code = 0x2; r.size = 16; return r; }
    else if (strcmp(reg, "wg2") == 0) { r.code = 0x3; r.size = 16; return r; }
    else if (strcmp(reg, "wg3") == 0) { r.code = 0x4; r.size = 16; return r; }
    else if (strcmp(reg, "wg4") == 0) { r.code = 0x5; r.size = 16; return r; }
    else if (strcmp(reg, "wg5") == 0) { r.code = 0x6; r.size = 16; return r; }
    else if (strcmp(reg, "wg6") == 0) { r.code = 0x7; r.size = 16; return r; }
    else if (strcmp(reg, "wg7") == 0) { r.code = 0x8; r.size = 16; return r; }
    else if (strcmp(reg, "wg8") == 0) { r.code = 0x9; r.size = 16; return r; }
    else if (strcmp(reg, "wg9") == 0) { r.code = 0x10; r.size = 16; return r; }
    else if (strcmp(reg, "wg10") == 0) { r.code = 0x11; r.size = 16; return r; }
    else if (strcmp(reg, "wg11") == 0) { r.code = 0x12; r.size = 16; return r; }
    else if (strcmp(reg, "wg12") == 0) { r.code = 0x13; r.size = 16; return r; }
    else if (strcmp(reg, "wg13") == 0) { r.code = 0x14; r.size = 16; return r; }
    else if (strcmp(reg, "wg14") == 0) { r.code = 0x15; r.size = 16; return r; }
    else if (strcmp(reg, "wg15") == 0) { r.code = 0x16; r.size = 16; return r; }
    else if (strcmp(reg, "wg16") == 0) { r.code = 0x17; r.size = 16; return r; }
    else if (strcmp(reg, "wg17") == 0) { r.code = 0x18; r.size = 16; return r; }
    else if (strcmp(reg, "wg18") == 0) { r.code = 0x19; r.size = 16; return r; }
    else if (strcmp(reg, "wg19") == 0) { r.code = 0x20; r.size = 16; return r; }
    else if (strcmp(reg, "wg20") == 0) { r.code = 0x21; r.size = 16; return r; }
    else if (strcmp(reg, "wg21") == 0) { r.code = 0x22; r.size = 16; return r; }
    else if (strcmp(reg, "wg22") == 0) { r.code = 0x23; r.size = 16; return r; }
    else if (strcmp(reg, "wg23") == 0) { r.code = 0x24; r.size = 16; return r; }
    else if (strcmp(reg, "wg24") == 0) { r.code = 0x25; r.size = 16; return r; }
    else if (strcmp(reg, "wg25") == 0) { r.code = 0x26; r.size = 16; return r; }
    else if (strcmp(reg, "wg26") == 0) { r.code = 0x27; r.size = 16; return r; }
    else if (strcmp(reg, "wg27") == 0) { r.code = 0x28; r.size = 16; return r; }
    else if (strcmp(reg, "wg28") == 0) { r.code = 0x29; r.size = 16; return r; }
    else if (strcmp(reg, "wg29") == 0) { r.code = 0x30; r.size = 16; return r; }
    else if (strcmp(reg, "wg30") == 0) { r.code = 0x31; r.size = 16; return r; }
    else if (strcmp(reg, "wlr") == 0) { r.code = 0x32; r.size = 16; return r; }
    else if (strcmp(reg, "wsf") == 0) { r.code = 0x33; r.size = 16; return r; }
    else if (strcmp(reg, "wsp") == 0) { r.code = 0x34; r.size = 16; return r; }

    // 8-bit
    else if (strcmp(reg, "bg0") == 0) { r.code = 0x1; r.size = 8; return r; }
    else if (strcmp(reg, "bg1") == 0) { r.code = 0x2; r.size = 8; return r; }
    else if (strcmp(reg, "bg2") == 0) { r.code = 0x3; r.size = 8; return r; }
    else if (strcmp(reg, "bg3") == 0) { r.code = 0x4; r.size = 8; return r; }
    else if (strcmp(reg, "bg4") == 0) { r.code = 0x5; r.size = 8; return r; }
    else if (strcmp(reg, "bg5") == 0) { r.code = 0x6; r.size = 8; return r; }
    else if (strcmp(reg, "bg6") == 0) { r.code = 0x7; r.size = 8; return r; }
    else if (strcmp(reg, "bg7") == 0) { r.code = 0x8; r.size = 8; return r; }
    else if (strcmp(reg, "bg8") == 0) { r.code = 0x9; r.size = 8; return r; }
    else if (strcmp(reg, "bg9") == 0) { r.code = 0x10; r.size = 8; return r; }
    else if (strcmp(reg, "bg10") == 0) { r.code = 0x11; r.size = 8; return r; }
    else if (strcmp(reg, "bg11") == 0) { r.code = 0x12; r.size = 8; return r; }
    else if (strcmp(reg, "bg12") == 0) { r.code = 0x13; r.size = 8; return r; }
    else if (strcmp(reg, "bg13") == 0) { r.code = 0x14; r.size = 8; return r; }
    else if (strcmp(reg, "bg14") == 0) { r.code = 0x15; r.size = 8; return r; }
    else if (strcmp(reg, "bg15") == 0) { r.code = 0x16; r.size = 8; return r; }
    else if (strcmp(reg, "bg16") == 0) { r.code = 0x17; r.size = 8; return r; }
    else if (strcmp(reg, "bg17") == 0) { r.code = 0x18; r.size = 8; return r; }
    else if (strcmp(reg, "bg18") == 0) { r.code = 0x19; r.size = 8; return r; }
    else if (strcmp(reg, "bg19") == 0) { r.code = 0x20; r.size = 8; return r; }
    else if (strcmp(reg, "bg20") == 0) { r.code = 0x21; r.size = 8; return r; }
    else if (strcmp(reg, "bg21") == 0) { r.code = 0x22; r.size = 8; return r; }
    else if (strcmp(reg, "bg22") == 0) { r.code = 0x23; r.size = 8; return r; }
    else if (strcmp(reg, "bg23") == 0) { r.code = 0x24; r.size = 8; return r; }
    else if (strcmp(reg, "bg24") == 0) { r.code = 0x25; r.size = 8; return r; }
    else if (strcmp(reg, "bg25") == 0) { r.code = 0x26; r.size = 8; return r; }
    else if (strcmp(reg, "bg26") == 0) { r.code = 0x27; r.size = 8; return r; }
    else if (strcmp(reg, "bg27") == 0) { r.code = 0x28; r.size = 8; return r; }
    else if (strcmp(reg, "bg28") == 0) { r.code = 0x29; r.size = 8; return r; }
    else if (strcmp(reg, "bg29") == 0) { r.code = 0x30; r.size = 8; return r; }
    else if (strcmp(reg, "bg30") == 0) { r.code = 0x31; r.size = 8; return r; }
    else if (strcmp(reg, "blr") == 0) { r.code = 0x32; r.size = 8; return r; }
    else if (strcmp(reg, "bsf") == 0) { r.code = 0x33; r.size = 8; return r; }
    else if (strcmp(reg, "bsp") == 0) { r.code = 0x34; r.size = 8; return r; }
    // Default
    else if (strcmp(reg, "null") == 0) { r.code = 0x0; return r; }
    else if (strcmp(reg, "g0") == 0) { r.code = 0x1; r.size = 64; return r; }
    else if (strcmp(reg, "g1") == 0) { r.code = 0x2; r.size = 64; return r; }
    else if (strcmp(reg, "g2") == 0) { r.code = 0x3; r.size = 64; return r; }
    else if (strcmp(reg, "g3") == 0) { r.code = 0x4; r.size = 64; return r; }
    else if (strcmp(reg, "g4") == 0) { r.code = 0x5; r.size = 64; return r; }
    else if (strcmp(reg, "g5") == 0) { r.code = 0x6; r.size = 64; return r; }
    else if (strcmp(reg, "g6") == 0) { r.code = 0x7; r.size = 64; return r; }
    else if (strcmp(reg, "g7") == 0) { r.code = 0x8; r.size = 64; return r; }
    else if (strcmp(reg, "g8") == 0) { r.code = 0x9; r.size = 64; return r; }
    else if (strcmp(reg, "g9") == 0) { r.code = 0x10; r.size = 64; return r; }
    else if (strcmp(reg, "g10") == 0) { r.code = 0x11; r.size = 64; return r; }
    else if (strcmp(reg, "g11") == 0) { r.code = 0x12; r.size = 64; return r; }
    else if (strcmp(reg, "g12") == 0) { r.code = 0x13; r.size = 64; return r; }
    else if (strcmp(reg, "g13") == 0) { r.code = 0x14; r.size = 64; return r; }
    else if (strcmp(reg, "g14") == 0) { r.code = 0x15; r.size = 64; return r; }
    else if (strcmp(reg, "g15") == 0) { r.code = 0x16; r.size = 64; return r; }
    else if (strcmp(reg, "g16") == 0) { r.code = 0x17; r.size = 64; return r; }
    else if (strcmp(reg, "g17") == 0) { r.code = 0x18; r.size = 64; return r; }
    else if (strcmp(reg, "g18") == 0) { r.code = 0x19; r.size = 64; return r; }
    else if (strcmp(reg, "g19") == 0) { r.code = 0x20; r.size = 64; return r; }
    else if (strcmp(reg, "g20") == 0) { r.code = 0x21; r.size = 64; return r; }
    else if (strcmp(reg, "g21") == 0) { r.code = 0x22; r.size = 64; return r; }
    else if (strcmp(reg, "g22") == 0) { r.code = 0x23; r.size = 64; return r; }
    else if (strcmp(reg, "g23") == 0) { r.code = 0x24; r.size = 64; return r; }
    else if (strcmp(reg, "g24") == 0) { r.code = 0x25; r.size = 64; return r; }
    else if (strcmp(reg, "g25") == 0) { r.code = 0x26; r.size = 64; return r; }
    else if (strcmp(reg, "g26") == 0) { r.code = 0x27; r.size = 64; return r; }
    else if (strcmp(reg, "g27") == 0) { r.code = 0x28; r.size = 64; return r; }
    else if (strcmp(reg, "g28") == 0) { r.code = 0x29; r.size = 64; return r; }
    else if (strcmp(reg, "g29") == 0) { r.code = 0x30; r.size = 64; return r; }
    else if (strcmp(reg, "g30") == 0) { r.code = 0x31; r.size = 64; return r; }
    else if (strcmp(reg, "lr") == 0) { r.code = 0x32; r.size = 64; return r; }
    else if (strcmp(reg, "sf") == 0) { r.code = 0x33; r.size = 64; return r; }
    else if (strcmp(reg, "sp") == 0) { r.code = 0x34; r.size = 64; return r; }

    // Privilaged
    if (unlocked) {
        if (strcmp(reg, "bi0") == 0) { r.code = 0x36; r.size = 8; return r; }
        else if (strcmp(reg, "bi1") == 0) { r.code = 0x37; r.size = 8; return r; }
        else if (strcmp(reg, "bi2") == 0) { r.code = 0x38; r.size = 8; return r; }
        else if (strcmp(reg, "wi0") == 0) { r.code = 0x36; r.size = 8; return r; }
        else if (strcmp(reg, "wi1") == 0) { r.code = 0x37; r.size = 16; return r; }
        else if (strcmp(reg, "wi2") == 0) { r.code = 0x38; r.size = 16; return r; }
        else if (strcmp(reg, "di0") == 0) { r.code = 0x36; r.size = 8; return r; }
        else if (strcmp(reg, "di1") == 0) { r.code = 0x37; r.size = 32; return r; }
        else if (strcmp(reg, "di2") == 0) { r.code = 0x38; r.size = 32; return r; }
        else if (strcmp(reg, "qi0") == 0) { r.code = 0x36; r.size = 8; return r; }
        else if (strcmp(reg, "qi1") == 0) { r.code = 0x37; r.size = 64; return r; }
        else if (strcmp(reg, "qi2") == 0) { r.code = 0x38; r.size = 64; return r; }
        else if (strcmp(reg, "i0") == 0) { r.code = 0x36; r.size = 8; return r; }
        else if (strcmp(reg, "i1") == 0) { r.code = 0x37; r.size = 64; return r; }
        else if (strcmp(reg, "i2") == 0) { r.code = 0x38; r.size = 64; return r; }
    }

    fprintf(stderr, COLOR_RED "Unknown register: %s\n" COLOR_CYAN "\tTip: If the register is privilaged, try re-assembling with --unlock\n" COLOR_RESET, reg);
    r.code = 0xFF;
    r.valid = false;
    return r;
}

static uint64_t get_opcode(TokenType opcode, bool* valid, int op_size, bool unlocked, uint8_t* mode) {
    *valid = true;
    switch (opcode) {
        case ASM_NOP: return 0x0;
        // ALU
        case ASM_ADD: return 0x1;
        case ASM_SUB: return 0x2;
        case ASM_MUL: return 0x3;
        case ASM_DIV: return 0x4;
        case ASM_CMP: return 0x5;
        case ASM_UCMP: return 0x6;
        case ASM_AND: return 0x7;
        case ASM_OR: return 0x8;
        case ASM_NOT: return 0x9;
        case ASM_NAND: return 0xA;
        case ASM_NOR: return 0xB;
        case ASM_XOR: return 0xC;
        case ASM_SHL: return 0xE;
        case ASM_SHR: return 0xF;
        case ASM_ROTL: return 0x10;
        case ASM_ROTR: return 0x11;
        case ASM_ASHL: return 0x12;
        case ASM_ASHR: return 0x13;
        case ASM_INC: return 0x14;
        case ASM_DEC: return 0x15;
        case ASM_TEST: return 0x16;

        // Memory
        case ASM_LOAD: return 0x100;
        case ASM_STORE: return 0x101;
        case ASM_PUSH: return 0x102;
        case ASM_POP: return 0x103;
        case ASM_PUSH16: return 0x104;
        case ASM_POP16: return 0x105;
        case ASM_PUSH32: return 0x106;
        case ASM_POP32: return 0x107;
        case ASM_PUSH64: return 0x108;
        case ASM_POP64: return 0x109;
        case ASM_MSET: return 0x10A;
        case ASM_MCPY: return 0x10B;
        case ASM_MCMP: return 0x10C;

        // Movement
        case ASM_MOV: // for 4-bit
            if (op_size == 64) return 0x119;
            else if (op_size == 32) return 0x118;
            else if (op_size == 16) return 0x117;
            else if (op_size == 8) return 0x116;
            else return 0x115;
        case ASM_MOVB: return 0x116;
        case ASM_MOVW: return 0x117;
        case ASM_MOVD: return 0x118;
        case ASM_MOVQ: return 0x119;
        case ASM_XCHG: return 0x11A;
        case ASM_RREG: return 0x11B;

        // Jumping and more
        case ASM_JMP: 
            *mode = MODE_SRC_IMM;
            return 0x12C;
        case ASM_CALL: 
            *mode = MODE_SRC_IMM;
            return 0x12D;
        case ASM_RET:
            *mode = MODE_SRC_IMM;
            return 0x12E;
        case ASM_EXCEPTION:
            if (!unlocked) {
                fprintf(stderr, COLOR_RED "Privilaged Instruction is not allowed!\n" COLOR_CYAN "\tTip: Try re-assembling with '--unlock'\n" COLOR_RESET);
                break;
            }
            *mode = MODE_SRC_IMM;
            return 0x12F;
        case ASM_JZ: return 0x130;
        case ASM_JNZ: return 0x131;
        case ASM_JL: return 0x132;
        case ASM_JLE: return 0x133;
        case ASM_JG: return 0x134;
        case ASM_JGE: return 0x135;
        case ASM_JE: return 0x136;
        case ASM_JNE: return 0x137;

        default:
            *valid = false;
            return 0x0; // Default ASM_NOP but with valid flag off
    }
    *valid = false;
    return 0;
}

static OperandType classify_operand(const char* op) {
    if (op[0] == '0' && op[1] == 'x') return OPERAND_LABEL; // print, exit
    if (op[0] == '[') return OPERAND_MEMORY; // [0x1234], [var], [%qg0 + 0x1234], [%qg1 - 0x1234]
    if (isdigit(op[0])) return OPERAND_LIT_INT; // 42, 0x1234
    if (isalpha(op[0])) return OPERAND_REGISTER; // %qg0, %qg16
    return (OperandType)-1;
}

static void parse_memory_operand(const char* op, RegInfo* src, RegInfo* dest, uint64_t* imm, uint8_t* flags, uint8_t* mode, bool* is_symbol, bool unlocked) {
    // remove brackets
    char buf[128]; 
    size_t len = strlen(op);
    if (len < 3 || op[0] != '[' || op[len - 1] != ']') {
        *mode = (uint8_t)-1; // INVALID
        return;
    }

    memcpy(buf, op + 1, len - 2);
    buf[len - 2] = '\0';

    char* w = buf;
    for (char* r = buf; *r; r++) {
        if (!isspace((unsigned char)*r))
            *w++ = *r;
    }
    *w = '\0';

    *imm = 0;
    *mode = MODE_REG_DISP;
    *flags = 0;
    *flags |= FLAGS_VALID;
    *flags |= FLAGS_DISP;

    char* p = buf;
    while (*p) {
        int sign = +1;
        if (*p == '+') {
            sign = +1;
            p++;
        } else if (*p == '-') {
            sign = -1;
            p++;
        }

        char term[64];
        int ti = 0;

        while (*p && *p != '+' && *p != '-') {
            term[ti++] = *p++;
        }
        term[ti] = '\0';

        if (term[0] == '\0') continue;

        if (isalpha(term[0])) {
            RegInfo r = encode_register(term, unlocked);
            if (r.valid) {
                if (dest->valid) *src = r;
                else *dest = r;
                continue;
            }
        }

        int base = 10;
        if (term[0] == '0' && (term[1] == 'x' || term[1] == 'X')) {
            base = 16;
            *is_symbol = true; // Parser auto-resolves all hex/bin/dec numbers by the user to decimal, only assembler uses hex, that so for only memory addresses
        } else {
            *is_symbol = false;
        }

        *imm += sign * strtoll(term, NULL, base);
    }

}

static size_t get_sym_index_via_addr(SymbolTable* symtab, size_t addr) {
    for (size_t i = 0; i < symtab->count; i++) {
        Symbol sym = symtab->symbols[i];
        if (sym.addr == addr) { // match
            // we found it
            return i;
        }
    }
    return 0;
}

bool encode_pvcpu(Assembler* ctx, const char* output_file, IRList* irlist, int bits, bool unlocked) {
    FILE* out = fopen(output_file, "wb");
    if (!out) {
        printf(COLOR_RED "Error: Unable to open output file!\n" COLOR_RESET);
        return false;
    }

    if (bits != 64) {
        printf(COLOR_RED "Error: Cannot make a ELF Object file of architecture x86_64 with the specified bits [%d]\n" COLOR_RESET, bits);
        return false;
    }

    // Header
    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB; // Little Endian
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    eh.e_ident[EI_ABIVERSION] = 0;
    eh.e_type = ET_REL;
    eh.e_machine =  EM_PVCPU;
    eh.e_version = EV_CURRENT;
    eh.e_entry = (Elf64_Addr)(ctx->entry ? ctx->entry : 0);
    eh.e_phoff = 0; // no program header
    eh.e_shoff = 0;
    eh.e_flags = 0;
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = 0;
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = 0;
    eh.e_shstrndx = 0;

    size_t rsection_count = ctx->sections->count;
    size_t section_count = rsection_count + 5; // +3 for null section, .symtab, .strtab, .shstrtab, .reloc.text
    Elf64_Shdr* shdrs = calloc(section_count, sizeof(Elf64_Shdr));

    // Section string table
    char secname[64];
    char* shstrtab = calloc(section_count, sizeof(secname));
    size_t shstrtab_off = 0;
    size_t shstrtab_size = section_count * sizeof(secname);

    // Normal String table
    char symname[128];
    char* strtab = calloc(ctx->symbols->count + 1, sizeof(symname));
    size_t strtab_off = 0;
    size_t strtab_size = (ctx->symbols->count + 1) * sizeof(symname);
    
    size_t roffset = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Shdr) * section_count) + shstrtab_size + strtab_size + (sizeof(Elf64_Sym) * (ctx->symbols->count + 1)) + 64; // leave 64 bytes for safety
    size_t offset = roffset;
    size_t text_off = offset;
    Section* text_sec;
    size_t text_sec_idx = 0;

    // Null section
    shdrs[0].sh_type = SHT_NULL;

    memcpy(shstrtab + shstrtab_off, ".null", 6);
    shdrs[0].sh_name = shstrtab_off;
    shstrtab_off += 6;

    // Symbol Section
    shdrs[1].sh_type = SHT_SYMTAB;
    shdrs[1].sh_addralign = 8;
    shdrs[1].sh_entsize = sizeof(Elf64_Sym);
    shdrs[1].sh_size = (ctx->symbols->count + 1) * sizeof(Elf64_Sym);
    shdrs[1].sh_link = 2;
    shdrs[1].sh_info = ctx->symbols->count + 1;
    shdrs[1].sh_offset = sizeof(Elf64_Ehdr) + (section_count * sizeof(Elf64_Shdr)) + shstrtab_size + strtab_size;

    memcpy(shstrtab + shstrtab_off, ".symtab", 8);
    shdrs[1].sh_name = shstrtab_off;
    shstrtab_off += 8;

    shdrs[2].sh_type = SHT_STRTAB;
    shdrs[2].sh_addralign = 1;
    shdrs[2].sh_entsize = 0;
    shdrs[2].sh_size = strtab_size;
    shdrs[2].sh_offset = sizeof(Elf64_Ehdr) + (section_count * sizeof(Elf64_Shdr)) + shstrtab_size;
    
    memcpy(shstrtab + shstrtab_off, ".strtab", 8);
    shdrs[2].sh_name = shstrtab_off;
    shstrtab_off += 8;

    memcpy(shstrtab + shstrtab_off, ".shstrtab", 10);
    shdrs[3].sh_name = shstrtab_off;
    shstrtab_off += 10;
    
    shdrs[3].sh_type = SHT_STRTAB;
    shdrs[3].sh_offset = (Elf64_Xword)(sizeof(Elf64_Ehdr) + (section_count * sizeof(Elf64_Shdr)));
    shdrs[3].sh_size = (Elf64_Xword)shstrtab_size;
    shdrs[3].sh_addralign = 1;

    for (size_t i = 0; i < ctx->sections->count; i++) {
        Section* sec = &ctx->sections->sections[i];
        Elf64_Shdr* sh = &shdrs[i + 5];

        size_t len = strlen(sec->name) + 1;
        memcpy(shstrtab + shstrtab_off, sec->name, len);
        sh->sh_name = shstrtab_off;
        shstrtab_off += len;

        if (strcmp(sec->name, ".text") == 0) {
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            text_off = offset;
            text_sec = &ctx->sections->sections[i];
            text_sec_idx = i + 5;
        } else if (strcmp(sec->name, ".data") == 0) {
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC | SHF_WRITE;
        } else if (strcmp(sec->name, ".bss") == 0) {
            sh->sh_type = SHT_NOBITS;
            sh->sh_flags = SHF_ALLOC | SHF_WRITE;
            sh->sh_addr = (Elf64_Addr)sec->base;
            sh->sh_addralign = (Elf64_Xword)sec->alignment;
            continue;
        } else if (strcmp(sec->name, ".rodata") == 0) {
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC;
        } else {
            sh->sh_type = SHT_NULL;
            sh->sh_flags = 0;
        }

        sh->sh_addr = (Elf64_Addr)sec->base;
        sh->sh_offset = (Elf64_Xword)offset;
        sh->sh_size = (Elf64_Xword)sec->size;
        sh->sh_link = 0;
        sh->sh_info = 0;
        sh->sh_addralign = (Elf64_Xword)sec->alignment;
        sh->sh_entsize = 0;

        offset += sec->size;
    }

    // Write data
    for (size_t i = 0; i < ctx->sections->count; i++) {
        Elf64_Shdr* sh = &shdrs[i + 5];

        Section sec = ctx->sections->sections[i];
        size_t written = 0;
        
        if (strcmp(sec.name, ".bss") == 0) {
            continue;
        }

        fseek(out, sh->sh_offset, SEEK_SET);

        for (size_t j = 0; j < ctx->symbols->count; j++) {
            Symbol sym = ctx->symbols->symbols[j];
            if (sym.section_index != i) continue;

            if (sym.type == SYM_IDENTIFIER) { // Only for identifier/allocated stuff
                int use = 0;
                long long intval = 0;
                double floatval = 0;
                if (sym.type_of_data >= T_BYTE && sym.type_of_data <= T_ULONG) {
                    intval = atoll(sym.value);
                    use = 0;
                } else if (sym.type_of_data >= T_FLOAT && sym.type_of_data <= T_DOUBLE) {
                    floatval = atof(sym.value);
                    use = 1;
                } else if (sym.type_of_data == T_ARRAY) {
                    use = 2; // NULL it
                    char* data = sym.value;
                    fwrite(data, 1, strlen(data), out);
                } else {
                    // PTR
                }

                if (use == 0) {
                    fwrite(&intval, sym.size, 1, out);
                } else if (use == 1) {
                    fwrite(&floatval, sym.size, 1, out);
                }
                written += sym.size;
            }
        }

        if (written > sec.size) {
            fprintf(stderr, COLOR_RED "Error: Somehow the contents of an section exceed the section's size!" COLOR_RESET);
            fclose(out);

            if (remove(output_file) != 0) {
                perror("Error deleting file");
            }

            free(shdrs);
            free(strtab);
            free(shstrtab);

            return false;
        } else if (written < sec.size) {
            for (size_t i = 0; i < (sec.size - written); i++) {
                fwrite("\0", 1, 1, out);
            }
        }
    }

    size_t inst_written = 0;

    fseek(out, text_off, SEEK_SET);
    for (size_t i = 0; i < irlist->count; i++) {
        IRInstruction inst = irlist->instructions[i];

        if (inst.arch != PVCPU) {
            fprintf(stderr, COLOR_RED "Error: Instructions contain an Architecture unsupported instruction!" COLOR_RESET);
            fclose(out);

            if (remove(output_file) != 0) {
                perror("Error deleting file");
            }

            free(shdrs);
            free(strtab);
            free(shstrtab);

            return false;
        }

        RegInfo src = {0};
        RegInfo dest = {0};
        uint64_t imm = 0;

        uint8_t flags = 0;
        uint8_t mode = MODE_REG_REG;
        uint8_t rsrc = 0;
        uint8_t rdest = 0;

        bool issrc = false;
        bool valid_qm = true; // valid?
        bool is_symbol = true;

        for (size_t j = 0; j < inst.operand_count; j++) {
            char* operand = inst.operands[j];
            OperandType optype = classify_operand((const char*)operand);

            switch (optype) {
                case OPERAND_REGISTER:
                    if (issrc) { src = encode_register(operand, unlocked); issrc = false; }
                    else {dest = encode_register(operand, unlocked); issrc = true; }
                    break;
                case OPERAND_LIT_INT:
                    imm = strtoul(operand, NULL, 10);
                    mode = MODE_REG_IMM;
                    if (imm > 0b111111) {
                        mode = MODE_REG_EXTIMM;
                    }
                    break;
                case OPERAND_MEMORY:
                    parse_memory_operand(operand, &src, &dest, &imm, &flags, &mode, &is_symbol, unlocked);
                    break;
                case OPERAND_LABEL:
                    size_t addr = strtoul(operand, NULL, 16); // resolve symbol
                    imm = get_sym_index_via_addr(ctx->symbols, addr);
                    mode = MODE_REG_EXTIMM;
                    break;
                default:
                    fprintf(stderr, COLOR_RED "Error: Unknown operand: %s\n" COLOR_RESET, operand);
                    fclose(out);
                    if (remove(output_file) != 0)
                        perror("Error Deleting file");
                    free(shdrs);
                    free(strtab);
                    free(shstrtab);
                    return false;
            }
        }

        rsrc = src.valid ? src.code : 0;
        rdest = dest.valid ? dest.code : 0;

        // something like - push16 %g0
        if (dest.valid && !src.valid && mode == MODE_REG_REG) { mode = MODE_SRC_REG; src = dest; dest.valid = false; }
        else if (dest.valid && !src.valid && mode == MODE_REG_IMM) { mode = MODE_SRC_IMM; src = dest; dest.valid = false; }
        else if (dest.valid && !src.valid && mode == MODE_REG_EXTIMM) { mode = MODE_SRC_REG_IMM; src = dest; dest.valid = false; }

        int op_size = 0;
        if (src.valid && dest.valid) op_size = (int)dest.size;
        else if (src.valid && !dest.valid) op_size = (int)src.size;
        else if (!src.valid && dest.valid) op_size = (int)dest.size;
        uint64_t opcode_full = get_opcode(inst.opcode, &valid_qm, op_size, unlocked, &mode);

        if (!(flags & FLAGS_VALID) && !valid_qm) flags = 0; // Empty it out
        else if (flags & FLAGS_VALID && !valid_qm) flags &= ~FLAGS_VALID; // Clear valid bit
        else if (!(flags & FLAGS_VALID) && valid_qm) flags |= FLAGS_VALID; // Add valid bit

        if (!opcode_full) {
            fprintf(stderr, COLOR_RED "Error: Invalid Instruction Found [%s]!\n" COLOR_RESET, token_type_to_ogstr(inst.opcode));
            fclose(out);

            if (remove(output_file) != 0) {
                perror("Error deleting file");
            }

            free(shdrs);
            free(strtab);
            free(shstrtab);

            return false;
        } 

        if (mode == MODE_SRC_IMM && imm < 0b111111) mode = MODE_SRC_REG_IMM;
        if (mode == MODE_REG_IMM || mode == MODE_SRC_REG_IMM) {
            if (src.valid) dest = src;
            src.code = (uint8_t)imm;
            if (flags & FLAGS_IMM) flags &= ~(FLAGS_IMM);
        }
        
        uint32_t outbytes = 0x0;
        outbytes |= (uint32_t)(opcode_full & OPCODE_BITS) << OPCODE_SHIFT;
        outbytes |= (uint32_t)(mode & MODE_BITS) << MODE_SHIFT;
        outbytes |= (uint32_t)(rsrc & RSRC_BITS) << RSRC_SHIFT;
        outbytes |= (uint32_t)(rdest & RDEST_BITS) << RDEST_SHIFT;
        outbytes |= (uint32_t)(flags & FLAGS_BITS) << FLAGS_SHIFT;

        emit_bytes(out, (uint8_t*)&outbytes, 4);

        if (flags & FLAGS_IMM) {
            emit_bytes(out, (uint8_t*)&imm, 8);
        }
        if (flags & FLAGS_DISP) {
            int64_t disp64 = 0;
            if (is_symbol) {
                size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);
                emit_bytes(out, (uint8_t*)&disp64, 8);
                add_reloc(text_sec, ftell(out) - text_off, symindex, R_PVCPU_64, 0);
            } else {
                disp64 = (int64_t)imm;
                emit_bytes(out, (uint8_t*)&disp64, 8);
            }
        }
    }

    if (inst_written > text_sec->size) {
        fprintf(stderr, COLOR_RED "Error: Somehow the contents of an section exceed the section's size!\n\tCurrent Size: %llu bytes\n\tAllocated Size: %llu bytes\n" COLOR_RESET, (unsigned long long)inst_written, (unsigned long long)text_sec->size);
        fclose(out);

        if (remove(output_file) != 0) {
            perror("Error deleting file");
        }

        free(shdrs);
        free(strtab);
        free(shstrtab);

        return false;
    } else if (inst_written < text_sec->size) {
        for (size_t i = 0; i < (text_sec->size - inst_written); i++) {
            fwrite("\0", 1, 1, out);
        }
    }

    char padding[256];
    fwrite(padding, 1, 256, out);

    fseek(out, 0, SEEK_SET);
    eh.e_shoff = sizeof(Elf64_Ehdr);
    eh.e_shnum = section_count;
    eh.e_shstrndx = 3;

    memcpy(shstrtab + shstrtab_off, ".reloc.text", 12);
    shdrs[4].sh_name = shstrtab_off;
    shstrtab_off += 12;
    
    shdrs[4].sh_type = SHT_RELA;
    shdrs[4].sh_flags = SHF_INFO_LINK;
    shdrs[4].sh_link = 1;
    shdrs[4].sh_info = text_sec_idx;
    shdrs[4].sh_entsize = sizeof(Elf64_Rela);
    Section last_sec = ctx->sections->sections[ctx->sections->count - 1];
    shdrs[4].sh_offset = (Elf64_Xword)(roffset + last_sec.base + last_sec.size + 16); // +16 for safety
    shdrs[4].sh_size = (Elf64_Xword)(text_sec->reloc_count * sizeof(Elf64_Rela));
    shdrs[4].sh_addralign = 1;

    fwrite(&eh, sizeof(eh), 1, out);
    fwrite(shdrs, sizeof(Elf64_Shdr), section_count, out);

    Elf64_Sym* elfsymtab = calloc(ctx->symbols->count + 1, sizeof(Elf64_Sym)); // +1 for Null

    elfsymtab[0].st_name = 0;
    elfsymtab[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    elfsymtab[0].st_shndx = SHN_UNDEF;
    strtab_off += 1;

    for (size_t i = 0; i < ctx->symbols->count; i++) {
        Symbol sym = ctx->symbols->symbols[i];
        Elf64_Sym* esym = &elfsymtab[i + 1];
        
        // Add name
        esym->st_shndx = sym.section_index + 5;
        if (sym.type == SYM_IDENTIFIER) esym->st_size = (Elf64_Xword)sym.size;
        else esym->st_size = 0;
        if (sym.type == SYM_LABEL) esym->st_info = ELF64_ST_INFO(sym.is_global == false ? STB_LOCAL : STB_GLOBAL, STT_FUNC);
        else if (sym.type == SYM_FILE) esym->st_info = ELF64_ST_INFO(sym.is_global == false ? STB_LOCAL : STB_GLOBAL, STT_FILE);
        else esym->st_info = ELF64_ST_INFO(sym.is_global == false ? STB_LOCAL : STB_GLOBAL, STT_OBJECT);
        esym->st_other = 0;
        esym->st_value = (Elf64_Addr)(sym.addr - ctx->sections->sections[sym.section_index].base);

        size_t len = strlen(sym.name) + 1;
        memcpy(strtab + strtab_off, sym.name, len);
        esym->st_name = strtab_off; 
        strtab_off += len;
    }

    fwrite(shstrtab, 1, shstrtab_size, out);
    fwrite(strtab, 1, strtab_size, out);
    fwrite(elfsymtab, sizeof(Elf64_Sym), ctx->symbols->count + 1, out);

    free(shstrtab);
    free(strtab);
    free(elfsymtab);

    fseek(out, shdrs[4].sh_offset, SEEK_SET);
    
    // add relocs of .text section
    for (size_t i = 0; i < text_sec->reloc_count; i++) {
        Relocation* reloc = &text_sec->relocs[i];
        Elf64_Rela r = {0};

        r.r_addend = reloc->addend;
        r.r_offset = reloc->offset;
        r.r_info = ELF64_R_INFO(reloc->symbol + 1, reloc->type);
        
        fwrite(&r, sizeof(r), 1, out);
    }

    fclose(out);
    free(shdrs);

    return true;
}
