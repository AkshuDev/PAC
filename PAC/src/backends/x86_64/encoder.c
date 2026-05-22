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
#define OPERAND_REG_TO_REG 0 // Reg -> Reg
#define OPERAND_IMM_TO_REG 1 // Imm -> Reg
#define OPERAND_IMM_TO_MEM 2 // Imm -> Mem
#define OPERAND_IMM32_TO_REG 3 // Imm32 -> Reg
#define OPERAND_MEM_DISP32_TO_REG 4 // [Disp32 + Base] -> Reg
#define OPERAND_MEM_DISP8_TO_REG 5 // [Disp8 + Base] -> Reg
#define OPERAND_MEM_DISP32 6 // Basically Label in short form
#define OPERAND_REG_TO_MEM 7 // Reg -> [Mem]
#define OPERAND_MEM_TO_REG 8 // [Mem] -> Reg
#define OPERAND_ONLY_OPCODE 9 // Only OP
#define OPERAND_IMM8 10
#define OPERAND_IMM32 11
#define OPERAND_REG_TO_MEM_DISP32 12 // Reg -> [Disp32 + Base]
#define OPERAND_REG_TO_MEM_DISP8 13 // Reg -> [Disp8 + Base]
#define OPERAND_RIP_DISP32_TO_REG 14 // [Disp32 + RIP] -> Reg
#define OPERAND_RIP_DISP8_TO_REG 15 // [Disp8 + RIP] -> Reg
#define OPERAND_REG_TO_RIP_DISP32 16 // Reg -> [Disp32 + RIP]
#define OPERAND_REG_TO_RIP_DISP8 17 // Reg -> [Disp8 + RIP]
#define OPERAND_REG_TO_MEM_SIB 18 // Reg -> [SIB]
#define OPERAND_MEM_SIB_TO_REG 18 // [SIB] -> Reg

#define MAX_INST_BUF_SIZE 4096

#define ALIGN_UP(num, align) (((num) + ((align) - 1)) & ~((align) - 1))

typedef struct {
    uint8_t code; // 3-bit ID
    bool rex_needed; // Needs a REX prefix at all?
    bool rex_ex; // Set by reg encoder to specify reg/rm == extended
    bool rex_b; // Set REX.B
    bool rex_r; // Set REX.R
    bool rex_x; // Set REX.X (rarely for registers as it extends RIB.index field)
    bool rex_w; // Set REX.W (64-bit op)
    char name[8]; // Name of register
    uint8_t size; // Operand size (8, 16, 32, 64)
    bool valid;
} RegInfo;

static size_t inst_buf_off = 0;
static uint8_t* inst_buf = NULL;
static bool inst_buf_init = false;
static size_t inst_buf_capacity = 0;

static size_t out_text_off = 0;
static size_t inst_text_off = 0;

static size_t inst_written = 0;
static bool no_update_inst_written_in_pad = false;

static void emit_bytes(FILE* out, uint8_t* bytes, size_t count) {
    if (!inst_buf_init) return;
    if (inst_buf_off >= MAX_INST_BUF_SIZE) {
        fseek(out, out_text_off + inst_text_off, SEEK_SET);
        fwrite(inst_buf, 1, inst_buf_off, out);
        fwrite(bytes, 1, count, out);
        if (!no_update_inst_written_in_pad) inst_written += count;
        inst_text_off += inst_buf_off + count;
        inst_buf_off = 0;
        return;
    }

    if (inst_buf_capacity < inst_buf_off + count) {
        uint8_t* new_buf = realloc(inst_buf, inst_buf_capacity * 2);
        if (!new_buf) return;

        inst_buf = new_buf;
        inst_buf_capacity *= 2;
    }

    memcpy(inst_buf + inst_buf_off, bytes, count);
    if (!no_update_inst_written_in_pad) inst_written += count;
    inst_buf_off += count;
}

static void flush_everything(FILE* out) {
    if (inst_buf_off > 0 && inst_buf) {
        fseek(out, out_text_off + inst_text_off, SEEK_SET);
        fwrite(inst_buf, 1, inst_buf_off, out);
        inst_buf_off = 0;
    }

    fflush(out);
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
    if (strcmp(reg, "r8") == 0)  { r.code=0; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9") == 0)  { r.code=1; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10") == 0)  { r.code=2; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11") == 0)  { r.code=3; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12") == 0)  { r.code=4; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13") == 0)  { r.code=5; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14") == 0)  { r.code=6; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15") == 0)  { r.code=7; r.rex_ex=1; r.rex_w=1; r.size=64; r.rex_needed=1; return r; }
    // Special 64-bit
    if (strcmp(reg, "rip") == 0) { r.code=5, r.rex_b=0; r.rex_w=0; r.size=64; r.rex_needed=0; return r; }

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
    if (strcmp(reg, "r8d") == 0) { r.code=0; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9d") == 0) { r.code=1; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10d") == 0) { r.code=2; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11d") == 0) { r.code=3; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12d") == 0) { r.code=4; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13d") == 0) { r.code=5; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14d") == 0) { r.code=6; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15d") == 0) { r.code=7; r.rex_ex=1; r.size=32; r.rex_needed=1; return r; }
    
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
    if (strcmp(reg, "r8w") == 0){ r.code=0; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9w") == 0){ r.code=1; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10w") == 0){ r.code=2; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11w") == 0){ r.code=3; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12w") == 0){ r.code=4; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13w") == 0){ r.code=5; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14w") == 0){ r.code=6; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15w") == 0){ r.code=7; r.rex_ex=1; r.size=16; r.rex_needed=1; return r; }

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
    if (strcmp(reg, "r8b") == 0){ r.code=0; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r9b") == 0){ r.code=1; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r10b") == 0){ r.code=2; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r11b") == 0){ r.code=3; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r12b") == 0){ r.code=4; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r13b") == 0){ r.code=5; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r14b") == 0){ r.code=6; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }
    if (strcmp(reg, "r15b") == 0){ r.code=7; r.size=8; r.rex_ex=1; r.rex_needed=1; return r; }

    fprintf(stderr, COLOR_RED "Unknown register: %s\n" COLOR_RESET, reg);
    r.code = 0xFF;
    r.valid = false;
    return r;
}

static uint8_t make_rex(RegInfo reg, RegInfo rm) {
    uint8_t rex = 0b01000000;
    bool needed = false;

    if (reg.valid && reg.rex_needed) needed = true;
    if (rm.valid && rm.rex_needed) needed = true;
    if (!needed) return 0;

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
    bool _8bit = (reg.valid && reg.size == 8) || (rm.valid && rm.size == 8);
    switch (opcode) {
        case ASM_MOV: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x88;
                    return 0x89; // reg -> reg
                }
                case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x88 + (reg.valid ? reg.code : 0); // al
                    return 0xB8 + (reg.valid ? reg.code : 0); // ax/eax/rax
                }
                case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG:
                case OPERAND_MEM_DISP8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x8A;
                    return 0x8B; // mem -> reg
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
                    *no_bytes = 1;
                    if (_8bit) return 0x88;
                    return 0x89; // reg -> mem
                }
                default: break;
            }
            break;
        case ASM_ADD:
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x00;
                    return 0x01; // reg + reg
                }
                case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
                case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG:
                case OPERAND_MEM_DISP8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x02;
                    return 0x03; // mem -> reg
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
                    *no_bytes = 1;
                    if (_8bit) return 0x00;
                    return 0x01; // reg -> mem
                }
                default: break;
            }
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

static uint8_t make_sib(RegInfo index, RegInfo base, uint8_t mult) {
    uint8_t sib = 0;
    if (!index.valid || !base.valid) return sib;

    sib |= base.code & 0b00000111;
    sib |= (index.code & 0b00000111) << 3;
    sib |= (mult & 0b00000011) << 6;
    return sib;
}

static bool parse_memory_operand(const char* op, bool* issrc, RegInfo* src, RegInfo* dest, RegInfo* sib_index, uint8_t* sib_scale, int64_t* imm, int* operand_mod, bool* is_symbol) {
    // remove brackets
    char buf[128]; 
    size_t len = strlen(op);
    if (len < 3 || op[0] != '[' || op[len - 1] != ']') {
        printf(COLOR_RED "Error: Invalid Memory Operand!\n" COLOR_RESET);
        return false;
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

    RegInfo base_r = {0};
    
    char* p = buf;
    bool sib = false;
    while (*p) {
        int sign = +1;
        if (*p == '+') {
            sign = +1;
            p++;
        } else if (*p == '-') {
            sign = -1;
            p++;
        } else if (*p == '*') {
            sib = true;
            p++;
        }

        char term[64];
        int ti = 0;

        while (*p && *p != '+' && *p != '-' && *p != '*') {
            term[ti++] = *p++;
        }
        term[ti] = '\0';

        if (term[0] == '\0') continue;

        if (isalpha(term[0])) {
            RegInfo r = encode_register(term);
            if (base_r.valid) {
                if (r.valid) {
                    *sib_index = r;
                    continue;
                }
            } else {
                if (r.valid) {
                    base_r = r;
                    continue;
                }
            }
        }

        int base = 10;
        if (term[0] == '0' && (term[1] == 'x' || term[1] == 'X')) {
            base = 16;
            *is_symbol = true; // Parser auto-resolves all hex/bin/dec numbers by the user to decimal, only assembler uses hex, that so for only memory addresses
        } else {
            *is_symbol = false;
        }

        if (!sib) {
            *imm += sign * strtoll(term, NULL, base);
        } else {
            uint64_t sib_mult = strtoll(term, NULL, base);
            if (sib_mult != 1 && sib_mult != 2 && sib_mult != 4 && sib_mult != 8) {
                printf(COLOR_RED "Error: Invalid SIB Scale - %lu\n" COLOR_RESET, sib_mult);
                return false;
            }
            *sib_scale = (uint8_t)sib_mult;
        }
    }

    if (!base_r.valid) {
        if (src->valid) {
            *operand_mod = OPERAND_REG_TO_MEM_DISP32;
            *dest = (RegInfo){0};
        } else {
            *operand_mod = OPERAND_MEM_DISP32_TO_REG;
            *src = (RegInfo){0};
        }
    } else if (*imm == 0) {
        if (!*issrc) {
            *operand_mod = OPERAND_REG_TO_MEM;
            *dest = base_r;
            *issrc = true;
        } else {
            *operand_mod = OPERAND_MEM_TO_REG;
            *src = base_r;
            *issrc = false;
        }
    } else if (*imm >= -128 && *imm <= 127) {
        if (!*issrc) {
            *operand_mod = OPERAND_REG_TO_MEM_DISP8;
            *dest = base_r;
            *issrc = true;
        } else {
            *operand_mod = OPERAND_MEM_DISP8_TO_REG;
            *src = base_r;
            *issrc = false;
        }
    } else {
        if (!*issrc) {
            *operand_mod = OPERAND_REG_TO_MEM_DISP32;
            *dest = base_r;
            *issrc = true;
        } else {
            *operand_mod = OPERAND_MEM_DISP32_TO_REG;
            *src = base_r;
            *issrc = false;
        }
    }
    return true;
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

bool encode_x86_64(Assembler* ctx, FILE* out, IRList* irlist, int bits, bool unlocked, size_t text_off, Section* text_sec, uint64_t* symbol_list, size_t symbol_list_size) {
    // [REX prefix] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
    // REX prefix = 0100WRXB
    size_t cur_symbol_idx = 0;

    inst_buf_capacity = MAX_INST_BUF_SIZE;
    inst_buf = (uint8_t*)malloc(inst_buf_capacity);
    inst_buf_init = true;
    inst_buf_off = 0;
    inst_text_off = 0;
    out_text_off = text_off;

    for (size_t i = 0; i < irlist->count; i++) {
        IRInstruction inst = irlist->instructions[i];

        for (size_t si = cur_symbol_idx; si < symbol_list_size; si++) {
            uint64_t ent = symbol_list[si];
            uint64_t sym_idx = (uint64_t)((uint32_t)ent);
            uint64_t ir_idx = (uint64_t)((uint32_t)(ent >> 32));

            if (ir_idx > i) break;

            if (ir_idx == i && sym_idx < ctx->symbols->count) {
                Symbol* sym = &ctx->symbols->symbols[sym_idx];
                sym->addr = inst_written;
                cur_symbol_idx = si;
            }
        }

        if (inst.arch != x86_64 && inst.arch != x86) {
            char archs[128];
            archenum_to_archs(inst.arch, archs);
            fprintf(stderr, COLOR_RED "Error: Instructions contain an Architecture unsupported instruction: [%s]\n" COLOR_RESET, archs);
            return false;
        }

        RegInfo src = {0};
        RegInfo dest = {0};
        RegInfo sib_index = {0};
        uint8_t sib_scale = 0;
        int64_t imm = 0;

        bool issrc = false;
        bool is_symbol = true;
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
                    if (operand_mod == OPERAND_REG_TO_REG) operand_mod = OPERAND_IMM_TO_REG;
                    break;
                case OPERAND_MEMORY:
                    if (!parse_memory_operand(operand, &issrc, &src, &dest, &sib_index, &sib_scale, &imm, &operand_mod, &is_symbol)) return false;
                    break;
                case OPERAND_LABEL:
                    imm = strtoul(operand, NULL, 16); // resolve symbol
                    if (inst.opcode >= ASM_CALL && inst.opcode <= ASM_JLE) {
                        operand_mod = OPERAND_MEM_DISP32;
                    } else {
                        // could be imm
                        operand_mod = OPERAND_IMM_TO_REG;
                    }
                    break;
                default:
                    fprintf(stderr, COLOR_RED "Error: Unknown operand: %s\n" COLOR_RESET, operand);
                    return false;
            }
        }

        if (src.valid && src.size > bits) {
            if (src.size == 32 && bits == 16) {
            } else {
                fprintf(stderr, COLOR_RED "Error: Invalid Register Found [%s]!\n" COLOR_RESET, src.name);
                return false;
            }
        }
        if (dest.valid && dest.size > bits) {
            if (src.size == 32 && bits == 16) {
            } else {
                fprintf(stderr, COLOR_RED "Error: Invalid Register Found [%s]!\n" COLOR_RESET, dest.name);
                return false;
            }
        }

        if (inst.operand_count == 0) operand_mod = OPERAND_ONLY_OPCODE;

        RegInfo* r_reg = &src;
        RegInfo* r_rm = &dest;

        switch (operand_mod) {
            case OPERAND_REG_TO_REG: {
                if (src.valid && dest.valid && src.size != dest.size) {
                    printf(COLOR_RED "Error: Size mismatch between '%s' and '%s' registers!\n" COLOR_RESET, src.name, dest.name);
                    return false;
                }
                if (src.valid && src.rex_ex) src.rex_r = true;
                if (dest.valid && dest.rex_ex) dest.rex_b = true;
                
                if (bits > 16 && (src.valid && src.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (src.valid && src.size == 32)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                }
                break;
            }
            case OPERAND_MEM_DISP32: { // label, just emit disp32
                break;
            }
            case OPERAND_IMM_TO_REG: {
                r_reg = &dest;
                r_rm = &src;
                uint64_t sz = 0xFF;
                if (dest.size == 16) sz = 0xFFFF;
                else if (dest.size == 32) sz = 0xFFFFFFFF;
                else if (dest.size == 64) sz = 0xFFFFFFFFFFFFFFFF;
                if (dest.valid && sz < (uint64_t)imm) {
                    printf(COLOR_RED "Error: Size mismatch between '%s' reg and '%lu' imm!\n" COLOR_RESET, dest.name, imm);
                    return false;
                }
                
                if (dest.valid && dest.rex_ex) {
                    switch (inst.opcode) {
                        case ASM_MOV: dest.rex_r = true; break;
                        default: dest.rex_b = true; break;
                    }
                }
                
                if (bits > 16 && (dest.valid && dest.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (dest.valid && dest.size == 32)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                }
                break;
            }
            case OPERAND_MEM_TO_REG: {
                r_reg = &dest;
                r_rm = &src;
                if (dest.valid && dest.rex_ex) dest.rex_r = true;
                if (src.valid && src.code != 0b100 && src.rex_ex) src.rex_b = true;
                else if (src.valid && src.code == 0b100 && src.rex_ex) src.rex_x = true;
                
                if (bits > 16 && (dest.valid && dest.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (dest.valid && dest.size == 32)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                }
                break;
            }
            case OPERAND_REG_TO_MEM: {
                if (src.valid && src.rex_ex) src.rex_r = true;
                if (dest.valid && dest.code != 0b100 && dest.rex_ex) dest.rex_b = true;
                else if (dest.valid && dest.code == 0b100 && dest.rex_ex) dest.rex_x = true;
                
                if (bits > 16 && (src.valid && src.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (src.valid && src.size == 32)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                }
                break;
            }
            case OPERAND_IMM32_TO_REG: {
                r_reg = &dest;
                r_rm = &src;
                uint64_t sz = 0xFF;
                if (dest.size == 16) sz = 0xFFFF;
                else if (dest.size == 32) sz = 0xFFFFFFFF;
                else if (dest.size == 64) sz = 0xFFFFFFFFFFFFFFFF;
                if (dest.valid && sz < (uint64_t)imm) {
                    printf(COLOR_RED "Error: Size mismatch between '%s' reg and '%lu' imm!\n" COLOR_RESET, dest.name, imm);
                    return false;
                }
                
                if (dest.valid && dest.rex_ex) {
                    switch (inst.opcode) {
                        case ASM_MOV: dest.rex_r = true; break;
                        default: dest.rex_b = true; break;
                    }
                }
                
                if (bits > 16 && (dest.valid && dest.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (dest.valid && dest.size == 32)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                }
                break;
            }
            case OPERAND_MEM_DISP8_TO_REG:
            case OPERAND_MEM_DISP32_TO_REG: {
                r_reg = &dest;
                r_rm = &src;
                if (dest.valid && dest.rex_ex) dest.rex_r = true;
                if (src.valid && src.code != 0b100 && src.rex_ex) src.rex_b = true;
                else if (src.valid && src.code == 0b100 && src.rex_ex) src.rex_x = true;
                
                if (bits > 16 && (dest.valid && dest.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (dest.valid && dest.size == 32)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                }
                break;
            }
            case OPERAND_REG_TO_MEM_DISP8:
            case OPERAND_REG_TO_MEM_DISP32: {
                if (src.valid && src.rex_ex) src.rex_r = true;
                if (dest.valid && dest.code != 0b100 && dest.rex_ex) dest.rex_b = true;
                else if (dest.valid && dest.code == 0b100 && dest.rex_ex) dest.rex_x = true;
                
                if (bits > 16 && (src.valid && src.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (src.valid && src.size == 32)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                }
                break;
            }
            default: break;
        }

        uint8_t rex = make_rex(*r_reg, *r_rm);
        if (rex) emit_bytes(out, &rex, 1);

        int no_bytes = 0;

        uint64_t opcode_full = get_opcode(inst.opcode, &no_bytes, &operand_mod, *r_reg, *r_rm);

        if (no_bytes == 0) {
            fprintf(stderr, COLOR_RED "Error: Invalid Instruction Found [%s]!\n" COLOR_RESET, token_type_to_ogstr(inst.opcode));
            return false;
        }
        for (int i = no_bytes - 1; i >= 0; i--) {
            uint8_t opcode = (opcode_full >> (i * 8)) & 0xFF;
            emit_bytes(out, &opcode, 1);
        }
        
        switch (operand_mod) {
            case OPERAND_REG_TO_REG: {
                uint8_t modrm_b = make_modrm(*r_reg, *r_rm, MODRM_MOD_REG_TO_REG);
                emit_bytes(out, &modrm_b, 1);
                break;
            }
            case OPERAND_MEM_DISP32: { // label, just emit disp32
                size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);

                add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_PC32, -4);
                emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                break;
            }
            case OPERAND_IMM_TO_REG: {
                size_t sz = dest.size == 64 ? 4 : dest.size / 8;
                switch (inst.opcode) {
                    case ASM_ADD:
                        uint8_t modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
                    case ASM_MOV:
                        sz = (dest.size / 8);
                        break;
                    default: break;
                }
                for (size_t i = 0; i < sz; i++) {
                    uint8_t imm_part = (imm >> (i * 8)) & 0xFF;
                    emit_bytes(out, &imm_part, 1);
                }
                break;
            }
            case OPERAND_MEM_TO_REG:{
                bool rip_mode = false;
                bool rbp_mode = false;
                bool rsp_sib = false;
                if (dest.valid && dest.code == 0b101 && !dest.rex_w) {
                    printf(COLOR_RED "Error: Cannot use %%rip as a destination register!\n" COLOR_RESET);
                    return false;
                }
                if (src.valid && src.code == 0b101) {
                    if (src.rex_w) rbp_mode = true;
                    else rip_mode = true;
                }
                if (src.valid && src.code == 0b100) rsp_sib = true;

                if (rbp_mode) {
                    uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEM_PLUS_DISP8);
                    emit_bytes(out, &modrm, 1);
                    if (sib_index.valid) {
                        uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                        emit_bytes(out, &sib, 1);
                    } else if (rsp_sib) {
                        uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                        emit_bytes(out, &sib, 1);
                        emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    } else {
                        emit_bytes(out, (uint8_t*)"\0", 1);
                    }
                } else if (rip_mode) {
                    uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
                    emit_bytes(out, &modrm, 1);
                    if (sib_index.valid) {
                        uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                        emit_bytes(out, &sib, 1);
                    } else if (rsp_sib) {
                        uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                        emit_bytes(out, &sib, 1);
                    }
                    emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                } else {
                    uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
                    emit_bytes(out, &modrm, 1);
                    if (sib_index.valid) {
                        uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                        emit_bytes(out, &sib, 1);
                    } else if (rsp_sib) {
                        uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                        emit_bytes(out, &sib, 1);
                        emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    }
                }
                break;
            }
            case OPERAND_REG_TO_MEM: {
                bool rip_mode = false;
                bool rbp_mode = false;
                bool rsp_sib = false;
                if (src.valid && src.code == 0b101 && !src.rex_w) {
                    printf(COLOR_RED "Error: Cannot use %%rip as a source register!\n" COLOR_RESET);
                    return false;
                }
                if (dest.valid && dest.code == 0b101) {
                    if (dest.rex_w) rbp_mode = true;
                    else rip_mode = true;
                }
                if (dest.valid && dest.code == 0b100) rsp_sib = true;

                if (rbp_mode) {
                    uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEM_PLUS_DISP8);
                    emit_bytes(out, &modrm, 1);
                    if (sib_index.valid) {
                        uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                        emit_bytes(out, &sib, 1);
                    } else if (rsp_sib) {
                        uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                        emit_bytes(out, &sib, 1);
                        emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    } else {
                        emit_bytes(out, (uint8_t*)"\0", 1);
                    }
                } else if (rip_mode) {
                    uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
                    emit_bytes(out, &modrm, 1);
                    if (sib_index.valid) {
                        uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                        emit_bytes(out, &sib, 1);
                    } else if (rsp_sib) {
                        uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                        emit_bytes(out, &sib, 1);
                    }
                    emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                } else {
                    uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
                    emit_bytes(out, &modrm, 1);
                    if (sib_index.valid) {
                        uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                        emit_bytes(out, &sib, 1);
                    } else if (rsp_sib) {
                        uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                        emit_bytes(out, &sib, 1);
                        emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    }
                }
                break;
            }
            case OPERAND_IMM32_TO_REG: {
                switch (inst.opcode) {
                    case ASM_ADD:
                        uint8_t modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
                    default: break;
                }
                for (size_t i = 0; i < 4; i++) {
                    uint8_t imm_part = (imm >> (i * 8)) & 0xFF;
                    emit_bytes(out, &imm_part, 1);
                }
                break;
            }
            case OPERAND_REG_TO_MEM_DISP8:
            case OPERAND_REG_TO_MEM_DISP32: {
                bool rip_mode = false;
                bool rsp_sib = false;
                if (src.valid && src.code == 0b101 && !src.rex_w) {
                    printf(COLOR_RED "Error: Cannot use %%rip as a source register!\n" COLOR_RESET);
                    return false;
                }
                if (dest.valid && dest.code == 0b101 && !dest.rex_ex) rip_mode = true;
                if (dest.valid && dest.code == 0b100) rsp_sib = true;

                if (rip_mode) {
                    uint8_t modrm_bytes = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
                    emit_bytes(out, &modrm_bytes, 1);
                } else {
                    uint8_t modrm_bytes = make_modrm(*r_reg, *r_rm, operand_mod == OPERAND_REG_TO_MEM_DISP32 ? MODRM_MOD_MEM_PLUS_DISP32 : MODRM_MOD_MEM_PLUS_DISP8);
                    emit_bytes(out, &modrm_bytes, 1);
                }
                if (sib_index.valid) {
                    uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                    emit_bytes(out, &sib, 1);
                } else if (rsp_sib) {
                    uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                    emit_bytes(out, &sib, 1);
                }
                if (is_symbol) {
                    size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);

                    if (operand_mod == OPERAND_REG_TO_MEM_DISP8 && !rip_mode && !rsp_sib) {
                        add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_PC8, 0);
                        emit_bytes(out, (uint8_t*)"\0", 1);
                    } else {
                        add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_PC32, -4);
                        emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    }
                } else {
                    if (operand_mod == OPERAND_REG_TO_MEM_DISP8 && !rip_mode && !rsp_sib) {
                        emit_bytes(out, (uint8_t*)&imm, 1);
                    } else {
                        emit_bytes(out, (uint8_t*)&imm, 4);
                    }
                }
                break;
            }
            case OPERAND_MEM_DISP8_TO_REG:
            case OPERAND_MEM_DISP32_TO_REG: {
                bool rip_mode = false;
                bool rsp_sib = false;
                if (dest.valid && dest.code == 0b101 && !dest.rex_w) {
                    printf(COLOR_RED "Error: Cannot use %%rip as a destination register!\n" COLOR_RESET);
                    return false;
                }
                if (src.valid && src.code == 0b101 && !src.rex_ex) rip_mode = true;
                if (src.valid && src.code == 0b100) rsp_sib = true;

                if (rip_mode) {
                    uint8_t modrm_bytes = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
                    emit_bytes(out, &modrm_bytes, 1);
                } else {
                    uint8_t modrm_bytes = make_modrm(*r_reg, *r_rm, operand_mod == OPERAND_MEM_DISP32_TO_REG ? MODRM_MOD_MEM_PLUS_DISP32 : MODRM_MOD_MEM_PLUS_DISP8);
                    emit_bytes(out, &modrm_bytes, 1);
                }
                if (sib_index.valid) {
                    uint8_t sib = make_sib(sib_index, *r_rm, sib_scale);
                    emit_bytes(out, &sib, 1);
                } else if (rsp_sib) {
                    uint8_t sib = make_sib((RegInfo){.code=0b100, .valid=true}, (RegInfo){.valid=true, .code=0b101}, 0);
                    emit_bytes(out, &sib, 1);
                }
                if (is_symbol) {
                    size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);

                    if (operand_mod == OPERAND_MEM_DISP8_TO_REG && !rip_mode && !rsp_sib) {
                        add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_PC8, 0);
                        emit_bytes(out, (uint8_t*)"\0", 1);
                    } else {
                        add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_PC32, -4);
                        emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    }
                } else {
                    if (operand_mod == OPERAND_MEM_DISP8_TO_REG && !rip_mode && !rsp_sib) {
                        emit_bytes(out, (uint8_t*)&imm, 1);
                    } else {
                        emit_bytes(out, (uint8_t*)&imm, 4);
                    }
                }
                break;
            }
            default: break;
        }
    }

    if (inst_written > text_sec->size) {
        fprintf(stderr, COLOR_RED "Error: Somehow the contents of an section exceed the section's reserved size!\n\tCurrent Size: %lu bytes\n\tReserved Size: %lu bytes\n" COLOR_RESET, inst_written, text_sec->size);
        return false;
    } else if (inst_written < text_sec->size) {
        text_sec->size = ALIGN_UP(inst_written, 16);
        no_update_inst_written_in_pad = true;
        for (uint64_t i = 0; i < (text_sec->size - inst_written); i++) {
            emit_bytes(out, (uint8_t*)"\x90", 1); // use nop
        }
    }
    no_update_inst_written_in_pad = false;

    flush_everything(out);

    return true;
}
