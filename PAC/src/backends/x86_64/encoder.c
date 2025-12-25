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
#include <pac-x86_64-encoder.h>

#define MODRM_MOD_MEMORY 0 // Special Case: MODRM == 0, R/M=101 | It means [disp32] not [rbp].
#define MODRM_MOD_MEM_PLUS_DISP8 1
#define MODRM_MOD_MEM_PLUS_DISP32 2
#define MODRM_MOD_REG_TO_REG 3

// For program
#define OPERAND_REG_TO_REG 0
#define OPERAND_IMM_TO_REG 1
#define OPERAND_IMM_TO_MEM 2
#define OPERAND_IMM32_TO_REG 3
#define OPERAND_MEM_DISP32_TO_REG 4
#define OPERAND_MEM_DISP8_TO_REG 4
#define OPERAND_MEM_DISP32 6
#define OPERAND_REG_TO_MEM 7
#define OPERAND_MEM_TO_REG 8
#define OPERAND_MEM 9
#define OPERAND_ONLY_OPCODE 10
#define OPERAND_MEM_TO_REG_WMODRM 11 // WMODRM stands for With ModR/M
#define OPERAND_REG_TO_MEM_WMODRM 12
#define OPERAND_IMM8 13
#define OPERAND_IMM32 14

typedef struct {
    uint8_t code; // 3-bit ID
    bool rex_needed; // Needs a REX prefix at all?
    bool rex_b; // Set REX.B
    bool rex_r; // Set REX.R
    bool rex_x; // Set REX.X (rarely for registers)
    bool rex_w; // Set REX.W (64-bit op)
    char name[8]; // Name of register
    uint8_t size; // Operand size (8, 16, 32, 64)
    bool valid;
} RegInfo;

static void emit_bytes(FILE* out, uint8_t* bytes, size_t count) {
    fwrite(bytes, 1, count, out);
}

static RegInfo encode_register(const char *reg) {
    RegInfo r = {0};

    r.valid = true;
    strncpy(r.name, reg, sizeof(r.name));

    // 64-bit (Need REX.W=1)
    if (strcmp(reg, "rax") == 0) { r.code=0; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    if (strcmp(reg, "rcx") == 0) { r.code=1; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    if (strcmp(reg, "rdx") == 0) { r.code=2; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    if (strcmp(reg, "rbx") == 0) { r.code=3; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    if (strcmp(reg, "rsp") == 0) { r.code=4; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    if (strcmp(reg, "rbp") == 0) { r.code=5; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    if (strcmp(reg, "rsi") == 0) { r.code=6; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    if (strcmp(reg, "rdi") == 0) { r.code=7; r.rex_w=1; r.size=64; r.rex_needed = 1; return r; }
    // Extended 64-bit (Need REX.W=1 and REX.B=1)
    if (strcmp(reg, "r8") == 0)  { r.code=0; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9") == 0)  { r.code=1; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10") == 0)  { r.code=2; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11") == 0)  { r.code=3; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12") == 0)  { r.code=4; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13") == 0)  { r.code=5; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14") == 0)  { r.code=6; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15") == 0)  { r.code=7; r.rex_b=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }

    // 32-bit
    if (strcmp(reg, "eax") == 0) { r.code=0; r.size=32; return r; }
    if (strcmp(reg, "ecx") == 0) { r.code=1; r.size=32; return r; }
    if (strcmp(reg, "edx") == 0) { r.code=2; r.size=32; return r; }
    if (strcmp(reg, "ebx") == 0) { r.code=3; r.size=32; return r; }
    if (strcmp(reg, "esp") == 0) { r.code=4; r.size=32; return r; }
    if (strcmp(reg, "ebp") == 0) { r.code=5; r.size=32; return r; }
    if (strcmp(reg, "esi") == 0) { r.code=6; r.size=32; return r; }
    if (strcmp(reg, "edi") == 0) { r.code=7; r.size=32; return r; }
    // Extended 32-bit (Need REX.B=1)
    if (strcmp(reg, "r8d") == 0) { r.code=0; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9d") == 0) { r.code=1; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10d") == 0) { r.code=2; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11d") == 0) { r.code=3; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12d") == 0) { r.code=4; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13d") == 0) { r.code=5; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14d") == 0) { r.code=6; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15d") == 0) { r.code=7; r.rex_b=1; r.size=32; r.rex_needed=1; return r; }
    
    // 16-bit (Need prefix=0x66)
    if (strcmp(reg, "ax") == 0) { r.code=0; r.size=16; return r; }
    if (strcmp(reg, "cx") == 0) { r.code=1; r.size=16; return r; }
    if (strcmp(reg, "dx") == 0) { r.code=2; r.size=16; return r; }
    if (strcmp(reg, "bx") == 0) { r.code=3; r.size=16; return r; }
    if (strcmp(reg, "sp") == 0) { r.code=4; r.size=16; return r; }
    if (strcmp(reg, "bp") == 0) { r.code=5; r.size=16; return r; }
    if (strcmp(reg, "si") == 0) { r.code=6; r.size=16; return r; }
    if (strcmp(reg, "di") == 0) { r.code=7; r.size=16; return r; }
    // Extended 16-bit (Need prefix=0x66 and REX.B=1)
    if (strcmp(reg, "r8w") == 0){ r.code=0; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9w") == 0){ r.code=1; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10w") == 0){ r.code=2; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11w") == 0){ r.code=3; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12w") == 0){ r.code=4; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13w") == 0){ r.code=5; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14w") == 0){ r.code=6; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15w") == 0){ r.code=7; r.rex_b=1; r.size=16; r.rex_needed=1; return r; }

    // 8-bit
    if (strcmp(reg, "al") == 0) { r.code=0; r.size=8; return r; }
    if (strcmp(reg, "cl") == 0) { r.code=1; r.size=8; return r; }
    if (strcmp(reg, "dl") == 0) { r.code=2; r.size=8; return r; }
    if (strcmp(reg, "bl") == 0) { r.code=3; r.size=8; return r; }
    // High 8-bit, only w/o REX
    if (strcmp(reg, "ah") == 0) { r.code=4; r.size=8; return r; }
    if (strcmp(reg, "ch") == 0) { r.code=5; r.size=8; return r; }
    if (strcmp(reg, "dh") == 0) { r.code=6; r.size=8; return r; }
    if (strcmp(reg, "bh") == 0) { r.code=7; r.size=8; return r; }

    // New 8-bit
    if (strcmp(reg, "spl") == 0){ r.code=4; r.size=8; r.rex_needed=1; return r; }
    if (strcmp(reg, "bpl") == 0){ r.code=5; r.size=8; r.rex_needed=1; return r; }
    if (strcmp(reg, "sil") == 0){ r.code=6; r.size=8; r.rex_needed=1; return r; }
    if (strcmp(reg, "dil") == 0){ r.code=7; r.size=8; r.rex_needed=1; return r; }
    // Extended 8-bit (Need REX.B=1)
    if (strcmp(reg, "r8b") == 0){ r.code=0; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9b") == 0){ r.code=1; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10b") == 0){ r.code=2; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11b") == 0){ r.code=3; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12b") == 0){ r.code=4; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13b") == 0){ r.code=5; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14b") == 0){ r.code=6; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15b") == 0){ r.code=7; r.size=8; r.rex_b=1; r.rex_needed=1; return r; }

    fprintf(stderr, COLOR_RED "Unknown register: %s\n" COLOR_RESET, reg);
    r.code = 0xFF;
    r.valid = false;
    return r;
}

static uint8_t make_rex(RegInfo reg, RegInfo rm) {
    uint8_t rex = 0b01000000;
    bool needed = false;

    if (reg.valid && !reg.rex_needed) return 0;
    if (rm.valid && !rm.rex_needed) return 0;

    if (reg.valid == false) {
        if (rm.rex_w || rm.size == 64) {
            rex |= 0b00001000;
            needed = true;
        }
        if (rm.rex_x) {
            rex |= 0b00000010;
            needed = true;
        }
        if (rm.rex_b) {
            rex |= 0b00000001;
            needed = true;
        }
    } else if (rm.valid == false) { 
        if (reg.rex_w || reg.size == 64) {
            rex |= 0b00001000;
            needed = true;
        }
        
        if (reg.rex_r) {
            rex |= 0b00000100;
            needed = true;
        }
        if (reg.rex_x) {
            rex |= 0b00000010;
            needed = true;
        }
        if (reg.rex_b) {
            rex |= 0b00000001;
            needed = true;
        }
    } else {
        if (reg.rex_w || rm.rex_w || reg.size == 64 || rm.size == 64) {
            rex |= 0b00001000;
            needed = true;
        }
        
        if (reg.rex_r || (rm.rex_b && reg.rex_b)) {
            rex |= 0b00000100;
            needed = true;
        }
        if (rm.rex_x) {
            rex |= 0b00000010;
            needed = true;
        }
        if (rm.rex_b) {
            rex |= 0b00000001;
            needed = true;
        }
    }

    return needed ? rex : 0;
}

static uint8_t make_modrm(RegInfo reg, RegInfo rm, uint8_t mod) {
    // MODRM.mod (2 bits) MODRM.rm (3 bits) MODRM.reg (3 bits)
    uint8_t mod_bits = mod & 0b11;
    uint8_t reg_bits = reg.code & 0b111;
    uint8_t rm_bits = rm.code & 0b111;

    uint8_t modrm = 0;
    modrm |= (mod_bits << 6);
    modrm |= (reg_bits << 3);
    modrm |= rm_bits;

    return modrm;
}

static uint64_t get_opcode(TokenType opcode, int* no_bytes, int* operand_mod, RegInfo reg, RegInfo rm) {
    int modrm = *operand_mod;
    (void)reg;
    switch (opcode) {
        case ASM_MOV: 
            if (modrm == OPERAND_REG_TO_REG) {
                *no_bytes = 1;
                return 0x89; // reg -> reg
            } else if (modrm == OPERAND_IMM_TO_REG) {
                *no_bytes = 1;
                if (rm.valid){
                if (rm.code == 1) return 0xB9; // cx
                if (rm.code == 2) return 0xBA; // dx
                if (rm.code == 3) return 0xBB; // bx
                if (rm.code == 4) return 0xBC; // sp
                if (rm.code == 5) return 0xBD; // bp
                if (rm.code == 6) return 0xBE; // si
                if (rm.code == 7) return 0xBF; // di
                }
                return 0xB8; // ax
            } else if (modrm == OPERAND_MEM_TO_REG || modrm == OPERAND_MEM_TO_REG_WMODRM || modrm == OPERAND_MEM_DISP32_TO_REG || modrm == OPERAND_MEM_DISP8_TO_REG) {
                *no_bytes = 1;
                return 0x8B; // mem -> reg
            } else if (modrm == OPERAND_REG_TO_MEM || modrm == OPERAND_REG_TO_MEM_WMODRM) {
                *no_bytes = 1;
                return 0x89; // reg -> mem
            }
            break;

        case ASM_ADD:
            *no_bytes = 1;
            if (modrm == OPERAND_REG_TO_REG) return 0x01;
            if (modrm == OPERAND_REG_TO_MEM) return 0x03;
            if (modrm == OPERAND_IMM_TO_REG) return 0x05;
            break;

        case ASM_SUB:
            *no_bytes = 1;
            if (modrm == OPERAND_REG_TO_REG) return 0x29;
            if (modrm == OPERAND_REG_TO_MEM) return 0x2B;
            if (modrm == OPERAND_IMM_TO_REG) return 0x81; // /5 or 83 for 8-bit imm
            break;

        case ASM_MUL:
            *no_bytes = 1;
            return 0xF7; // /4

        case ASM_DIV:
            *no_bytes = 1;
            return 0xF7; // /6

        case ASM_PUSH:
            *no_bytes = 1;
            if (*operand_mod == OPERAND_IMM8) return 0x6A;
            else if (*operand_mod == OPERAND_IMM32) return 0x68;
            *operand_mod = OPERAND_ONLY_OPCODE;
            uint64_t code = 0x50;
            return (uint64_t)(code + rm.code);

        case ASM_POP:
            *no_bytes = 1;
            *operand_mod = OPERAND_ONLY_OPCODE;
            code = 0x58;
            return (uint64_t)(code + rm.code);

        case ASM_CALL:
            *no_bytes = 1;
            return 0xE8;

        case ASM_RET:
            *no_bytes = 1;
            return 0xC3;

        case ASM_JMP:
            *no_bytes = 1;
            return 0xE9;

        case ASM_JE:
            *no_bytes = 2;
            return 0x0F84;

        case ASM_JNE:
            *no_bytes = 2;
            return 0x0F85;

        case ASM_JG:
            *no_bytes = 2;
            return 0x0F8F;

        case ASM_JGE:
            *no_bytes = 2;
            return 0x0F8D;

        case ASM_JL:
            *no_bytes = 2;
            return 0x0F8C;

        case ASM_JLE:
            *no_bytes = 2;
            return 0x0F8E;

        case ASM_CMP:
            *no_bytes = 1;
            if (modrm == OPERAND_REG_TO_REG) return 0x39;
            if (modrm == OPERAND_REG_TO_MEM) return 0x3B;
            if (modrm == OPERAND_IMM_TO_REG) { *operand_mod = OPERAND_IMM32_TO_REG; return 0x3D; }
            break;

        case ASM_TEST:
            *no_bytes = 1;
            if (modrm == OPERAND_REG_TO_REG) return 0x85;
            if (modrm == OPERAND_REG_TO_MEM) return 0x85;
            if (modrm == OPERAND_IMM_TO_REG) return 0xF7; // /0
            break;

        case ASM_AND:
            *no_bytes = 1;
            if (modrm == OPERAND_REG_TO_REG) return 0x23;
            if (modrm == OPERAND_REG_TO_MEM) return 0x21;
            if (modrm == OPERAND_IMM_TO_REG) return 0x81; // /4
            break;

        case ASM_OR:
            *no_bytes = 1;
            if (modrm == OPERAND_REG_TO_REG) return 0x0B;
            if (modrm == OPERAND_REG_TO_MEM) return 0x09;
            if (modrm == OPERAND_IMM_TO_REG) return 0x81; // /1
            break;

        case ASM_XOR:
            *no_bytes = 1;
            if (modrm == OPERAND_REG_TO_REG) return 0x33;
            if (modrm == OPERAND_REG_TO_MEM) return 0x31;
            if (modrm == OPERAND_IMM_TO_REG) return 0x81; // /6
            break;

        case ASM_NOT:
            *no_bytes = 1;
            return 0xF7; // /2

        case ASM_SHL:
            *no_bytes = 1;
            return 0xC1; // /4

        case ASM_SHR:
            *no_bytes = 1;
            return 0xC1; // /5

        case ASM_SYSCALL:
            *no_bytes = 2;
            return 0x0F05;

        case ASM_LEA:
            *no_bytes = 1;
            return 0x8D;

        case ASM_NOP:
            *no_bytes = 1;
            return 0x90;

        default:
            *no_bytes = 0;
            return 0;
    }
    *no_bytes = 0;
    return 0;
}

static OperandType classify_operand(const char* op) {
    if (op[0] == '0' && op[1] == 'x') return OPERAND_LABEL; // print, exit
    if (op[0] == '[') return OPERAND_MEMORY; // [0x1234], [var], [%rax + 0x1234], [%rax - 0x1234]
    if (isdigit(op[0])) return OPERAND_LIT_INT; // 42, 0x1234
    if (isalpha(op[0])) return OPERAND_REGISTER; // %rax, %r8
    return (OperandType)-1;
}

static void parse_memory_operand(const char* op, RegInfo* src, RegInfo* dest, int64_t* imm, int* modrm_mod, int* operand_mod, bool* is_symbol) {
    // remove brackets
    char buf[128]; 
    size_t len = strlen(op);
    if (len < 3 || op[0] != '[' || op[len - 1] != ']') {
        *operand_mod = -1; // INVALID
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
            RegInfo r = encode_register(term);
            if (r.valid) {
                *src = r;
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

    if (!src->valid) {
        *modrm_mod = MODRM_MOD_MEM_PLUS_DISP32;
    } else if (*imm == 0) {
        *modrm_mod = MODRM_MOD_MEMORY;
    } else if (*imm >= -128 && *imm <= 127) {
        *modrm_mod = MODRM_MOD_MEM_PLUS_DISP8;
    } else {
        *modrm_mod = MODRM_MOD_MEM_PLUS_DISP32;
    }

    if (dest && dest->valid)
        *operand_mod = OPERAND_MEM_TO_REG;
    else
        *operand_mod = OPERAND_REG_TO_MEM;
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

bool encode_x86_64(Assembler* ctx, FILE* out, IRList* irlist, int bits, bool unlocked, size_t text_off, Section* text_sec) {
    // [REX prefix] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
    // REX prefix = 0100WRXB
    size_t inst_written = 0;

    fseek(out, text_off, SEEK_SET);
    for (size_t i = 0; i < irlist->count; i++) {
        IRInstruction inst = irlist->instructions[i];

        if (inst.arch != x86_64 && inst.arch != x86) {
            char archs[128];
            archenum_to_archs(inst.arch, archs);
            fprintf(stderr, COLOR_RED "Error: Instructions contain an Architecture unsupported instruction: [%s]\n" COLOR_RESET, archs);
            return false;
        }

        RegInfo src = {0};
        RegInfo dest = {0};
        int64_t imm = 0;

        bool issrc = false;
        bool is_symbol = true;
        int modrm_mod = MODRM_MOD_REG_TO_REG;
        int operand_mod = OPERAND_REG_TO_REG;

        for (size_t j = 0; j < inst.operand_count; j++) {
            char* operand = inst.operands[j];
            OperandType optype = classify_operand((const char*)operand);

            switch (optype) {
                case OPERAND_REGISTER:
                    if (issrc) { src = encode_register(operand); issrc = false; }
                    else {dest = encode_register(operand); issrc = true; }
                    break;
                case OPERAND_LIT_INT:
                    imm = strtoul(operand, NULL, 10);
                    if (modrm_mod == MODRM_MOD_REG_TO_REG) modrm_mod = MODRM_MOD_MEMORY;
                    if (operand_mod == OPERAND_REG_TO_REG) operand_mod = OPERAND_IMM_TO_REG;
                    break;
                case OPERAND_MEMORY:
                    parse_memory_operand(operand, &src, &dest, &imm, &modrm_mod, &operand_mod, &is_symbol);
                    if (operand_mod == OPERAND_MEM_TO_REG) {
                        modrm_mod = MODRM_MOD_MEMORY;
                        operand_mod = OPERAND_MEM_TO_REG_WMODRM;
                    } else if (operand_mod == OPERAND_REG_TO_MEM) {
                        modrm_mod = MODRM_MOD_MEMORY;
                        operand_mod = OPERAND_REG_TO_MEM_WMODRM;
                    }
                    break;
                case OPERAND_LABEL:
                    imm = strtoul(operand, NULL, 16); // resolve symbol
                    if (inst.opcode >= ASM_CALL && inst.opcode <= ASM_JLE) {
                        modrm_mod = MODRM_MOD_MEMORY; // relative disp handled later
                        operand_mod = OPERAND_MEM_DISP32;
                    } else {
                        // could be imm
                        modrm_mod = MODRM_MOD_MEM_PLUS_DISP32;
                        operand_mod = OPERAND_IMM_TO_REG;
                    }
                    break;
                default:
                    fprintf(stderr, COLOR_RED "Error: Unknown operand: %s\n" COLOR_RESET, operand);
                    return false;
            }
        }

        if (src.valid && src.size > 32 && bits < 64) {
            fprintf(stderr, COLOR_RED "Error: Invalid Register Found [%s]!\n" COLOR_RESET, src.name);
            return false;
        }
        if (dest.valid && dest.size > 32 && bits < 64) {
            fprintf(stderr, COLOR_RED "Error: Invalid Register Found [%s]!\n" COLOR_RESET, dest.name);
            return false;
        }

        if (inst.operand_count == 0) operand_mod = OPERAND_ONLY_OPCODE;

        if (operand_mod == OPERAND_IMM_TO_REG && !src.valid && !dest.valid) {
            operand_mod = bits == 8 ? OPERAND_IMM8 : OPERAND_IMM32;
            if (imm > 0xFFFFFFFF) {
                fprintf(stderr, COLOR_YELLOW "Warning: Imm is truncated to fit 32-bit!\n" COLOR_RESET);
            }
        }

        int no_bytes = 0;
        uint64_t opcode_full = get_opcode(inst.opcode, &no_bytes, &operand_mod, src, dest);

        // for memory imm will be used for address
        uint8_t rex = 0;
        if (operand_mod != OPERAND_ONLY_OPCODE) {
            rex = make_rex(src, dest);
            if (rex) { emit_bytes(out, &rex, 1); inst_written += 1; }
        }

        if (!opcode_full) {
            fprintf(stderr, COLOR_RED "Error: Invalid Instruction Found [%s]!\n" COLOR_RESET, token_type_to_ogstr(inst.opcode));
            return false;
        } 
        for (int i = no_bytes - 1; i >= 0; i--) {
            uint8_t opcode = (opcode_full >> (i * 8)) & 0xFF;
            emit_bytes(out, &opcode, 1);
            inst_written += 1;
        }
        
        if (operand_mod == OPERAND_REG_TO_REG) {
            uint8_t modrm_b = make_modrm(src, dest, modrm_mod);
            emit_bytes(out, &modrm_b, 1);
            inst_written += 1;
        } else if (modrm_mod == MODRM_MOD_MEMORY && operand_mod == OPERAND_MEM_DISP32) { // label, just emit disp32
            size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);

            add_reloc(text_sec, ftell(out) - text_off, symindex, R_X86_64_PC32, -4);
            emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
            inst_written += 4;
        } else if (operand_mod == OPERAND_IMM_TO_REG) {
            for (size_t i = 0; i < (dest.size / 8); i++) {
                uint8_t imm_part = (imm >> (i * 8)) & 0xFF;
                emit_bytes(out, &imm_part, 1);
                inst_written += 1;
            }
        } else if (operand_mod == OPERAND_IMM8 || operand_mod == OPERAND_IMM32) {
            size_t imm_parts = operand_mod == OPERAND_IMM8 ? 1 : 4;
            for (size_t i = 0; i < imm_parts; i++) {
                uint8_t imm_part = (imm >> (i * 8)) & 0xFF;
                emit_bytes(out, &imm_part, 1);
                inst_written += 1;
            }
        } else if (operand_mod == OPERAND_MEM_TO_REG || operand_mod == OPERAND_REG_TO_MEM) {
            if (is_symbol) {
                size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);

                if (modrm_mod == MODRM_MOD_MEM_PLUS_DISP8) {
                    add_reloc(text_sec, ftell(out) - text_off, symindex, R_X86_64_PC8, 0);
                    emit_bytes(out, (uint8_t*)"\0", 1);
                    inst_written += 1;
                } else {
                    add_reloc(text_sec, ftell(out) - text_off, symindex, R_X86_64_PC32, 0);
                    emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    inst_written += 4;
                }
            } else {
                if (modrm_mod == MODRM_MOD_MEM_PLUS_DISP8) {
                    emit_bytes(out, (uint8_t*)&imm, 1);
                    inst_written += 1;
                } else {
                    emit_bytes(out, (uint8_t*)&imm, 4);
                    inst_written += 4;
                }
            }
        } else if (operand_mod == OPERAND_IMM32_TO_REG) {
            for (size_t i = 0; i < 4; i++) {
                uint8_t imm_part = (imm >> (i * 8)) & 0xFF;
                emit_bytes(out, &imm_part, 1);
                inst_written += 1;
            }
        } else if (operand_mod == OPERAND_MEM_TO_REG_WMODRM || operand_mod == OPERAND_REG_TO_MEM_WMODRM) {
            uint8_t modrm_bytes = make_modrm(dest, (RegInfo){.valid = true, .code = 101, .rex_needed = false}, modrm_mod); // using the special case
            emit_bytes(out, &modrm_bytes, 1);
            if (is_symbol) {
                size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);

                if (modrm_mod == MODRM_MOD_MEM_PLUS_DISP8) {
                    add_reloc(text_sec, ftell(out) - text_off, symindex, R_X86_64_PC8, 0);
                    emit_bytes(out, (uint8_t*)"\0", 1);
                    inst_written += 1;
                } else {
                    add_reloc(text_sec, ftell(out) - text_off, symindex, R_X86_64_PC32, -4);
                    emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    inst_written += 4;
                }
            } else {
                if (modrm_mod == MODRM_MOD_MEM_PLUS_DISP8) {
                    emit_bytes(out, (uint8_t*)&imm, 1);
                    inst_written += 1;
                } else {
                    emit_bytes(out, (uint8_t*)&imm, 4);
                    inst_written += 4;
                }
            }
        }
    }

    if (inst_written > text_sec->size) {
        fprintf(stderr, COLOR_RED "Error: Somehow the contents of an section exceed the section's size!\n\tCurrent Size: %llu bytes\n\tAllocated Size: %llu bytes\n" COLOR_RESET, (unsigned long long)inst_written, (unsigned long long)text_sec->size);
        return false;
    } else if (inst_written < text_sec->size) {
        for (size_t i = 0; i < (text_sec->size - inst_written); i++) {
                fwrite("\0", 1, 1, out);
            }
    }

    return true;
}
