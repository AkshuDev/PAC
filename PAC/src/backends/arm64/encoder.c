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

static uint32_t encode_reg(RegInfo* r) {
    // SP and ZR both encode as 31
    if (r->is_sp || r->is_zr)
        return 31;

    return r->id & 0x1F;
}

static uint32_t encode_sf(RegInfo* r) {
    return (r->bits == 64) ? 1 : 0;
}

static bool build_register(const char* op, RegInfo* r) {
    // x0–x30
    if (op[0] == 'x' && isdigit(op[1])) {
        int id = atoi(op + 1);
        if (id < 0 || id > 30) goto invalid;

        r->id = id;
        r->bits = 64;
        return true;
    }

    // w0–w30
    if (op[0] == 'w' && isdigit(op[1])) {
        int id = atoi(op + 1);
        if (id < 0 || id > 30) goto invalid;

        r->id = id;
        r->bits = 32;
        return true;
    }

    // sp
    if (strcmp(op, "sp") == 0) {
        r->id = 31;
        r->bits = 64;
        r->is_sp = true;
        return true;
    }

    // xzr / wzr
    if (strcmp(op, "xzr") == 0 || strcmp(op, "wzr") == 0) {
        r->id = 31;
        r->bits = (op[0] == 'x') ? 64 : 32;
        r->is_zr = true;
        return true;
    }

    fprintf(stderr, COLOR_RED "Error: Invalid register: %s\n" COLOR_RESET, op);
    return false;
}

static OperandType classify_operand(const char* op) {
    if (op[0] == '0' && op[1] == 'x') return OPERAND_LABEL; // print, exit
    if (op[0] == '[') return OPERAND_MEMORY; // [0x1234], [var], [%rax + 0x1234], [%rax - 0x1234]
    if (isdigit(op[0])) return OPERAND_LIT_INT; // 42, 0x1234
    if (isalpha(op[0])) return OPERAND_REGISTER; // %rax, %r8
    return (OperandType)-1;
}


static bool encode_add_sub(Assembler* ctx, IRInstruction* inst, uint32_t* out) {
    RegInfo rd = {0};
    RegInfo rn = {0};
    RegInfo rm = {0};

    int64_t imm = 0;
    bool has_imm = false;
    bool is_src = false;

    for (size_t i = 0; i < inst->operand_count; i++) {
        char* op = inst->operands[i];
        OperandType type = classify_operand(op);
        switch (type) {
            case OPERAND_REGISTER:
                if (!is_src) {
                    if (!build_register(op, &rd)) return false;
                    is_src = true;
                } else if (!rn.bits) {
                    if (!build_register(op, &rn)) return false;
                } else {
                    if (!build_register(op, &rm)) return false;
                }
                break;
            case OPERAND_LIT_INT:
                imm = strtoll(op, NULL, 0);
                has_imm = true;
                break;
            default:
                fprintf(stderr, COLOR_RED "Error: Invalid operand [%s]\n" COLOR_RESET, op);
                return false;
        }
    }

    if (!rd.bits || !rn.bits) {
        fprintf(stderr, COLOR_RED "Error: Missing registers\n" COLOR_RESET);
        return false;
    }

    uint32_t sf = encode_sf(rd);
    uint32_t op = (inst->opcode == ASM_SUB);

    uint32_t word = 0;

    if (has_imm) {
        if (imm < 0 || imm > 0xFFF) {
            fprintf(stderr, COLOR_RED "Error: Immediate out of range\n" COLOR_RESET);
            return false;
        }

        // add/sub (imm)
        word |= sf << 31;
        word |= op << 30;
        word |= 0 << 29;
        word |= 0b10001 << 24;
        word |= (imm & 0xFFF) << 10;
        word |= encode_reg(&rn) << 5;
        word |= encode_reg(&rd);
    } else {
        // add/sub (shifted reg)
        word |= sf << 31;
        word |= op << 30;
        word |= 0 << 29;
        word |= 0b01011 << 24;
        word |= encode_reg(&rm) << 16;
        word |= encode_reg(&rn) << 5;
        word |= encode_reg(&rd);
    }

    *out = word;
    return true;
}

static bool encode_instruction(Assembler* ctx, IRInstruction* inst, uint32_t* out) {
    switch (inst->opcode) {
        case ASM_ADD:
        case ASM_SUB:
            return encode_add_sub(ctx, inst, out);
        case ASM_LDR:
        case ASM_STR:
            return encode_ldr_str(ctx, inst, out);
        case ASM_B:
        case ASM_BL:
            return encode_branch(ctx, inst, out);
        default:
            fprintf(stderr, COLOR_RED "Error: Unknown Instruction [%s]\n" COLOR_RESET, token_type_to_ogstr(inst->opcode));
            return false;
    }
}


bool encode_x86_64(Assembler* ctx, FILE* out, IRList* irlist, int bits, bool unlocked, size_t text_off, Section* text_sec) {
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

        uint32_t encoded = 0;

        if (!encode_instruction(ctx, &inst, &word, text_sec, out, text_off)) {
            fprintf(stderr, COLOR_RED "Error: Encoding failed!\n" COLOR_RESET);
            return false;
        }

        fwrite(&encoded, sizeof(uint32_t), 1, out);
        inst_written += 4;
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
