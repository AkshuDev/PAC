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
#define OPERAND_IMM_TO_MEM 2 // Imm -> [Mem]
#define OPERAND_IMM32_TO_REG 3 // Imm32 -> Reg
#define OPERAND_MEM_DISP32_TO_REG 4 // [Disp32 + Base] -> Reg
#define OPERAND_MEM_DISP8_TO_REG 5 // [Disp8 + Base] -> Reg
#define OPERAND_MEM_DISP32 6 // Basically Label in short form
#define OPERAND_REG_TO_MEM 7 // Reg -> [Mem]
#define OPERAND_MEM_TO_REG 8 // [Mem] -> Reg
#define OPERAND_ONLY_OPCODE 9 // Only OP
#define OPERAND_IMM8_TO_REG 10
#define OPERAND_REG_TO_MEM_DISP32 11 // Reg -> [Disp32 + Base]
#define OPERAND_REG_TO_MEM_DISP8 12 // Reg -> [Disp8 + Base]
#define OPERAND_IMM_TO_MEM_DISP8 13 // Imm -> [Disp8 + Base]
#define OPERAND_IMM_TO_MEM_DISP32 14 // Imm -> [Disp32 + Base]
#define OPERAND_CALL_REG 15 // call reg
#define OPERAND_RET_IMM 16 // ret imm16

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

static RegInfo encode_register(int bits, const char *reg, bool* error) {
    RegInfo r = {0};

	*error = false;
    r.valid = true;
    strncpy(r.name, reg, sizeof(r.name));

    // 64-bit (Need REX.W=1)
	if (bits == 64) {
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
	}

    // 32-bit
	if (bits >= 32 || bits == 16) {
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
	}

    // 16-bit (Need prefix=0x66)
	if (bits >= 16) {
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
	}

    // 8-bit
	if (bits >= 8) {
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
	}

    fprintf(stderr, COLOR_RED "Unknown register: %s\n" COLOR_RESET, reg);
    r.code = 0xFF;
    r.valid = false;
	*error = true;
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

static uint64_t get_opcode(int bits, PAC_TokenType opcode, int* no_bytes, int* operand_mod, RegInfo reg, RegInfo rm) {
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
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (!_8bit) {
                        *operand_mod = OPERAND_IMM_TO_REG;
                        return 0xB8 + (reg.valid ? reg.code : 0); // ax/eax/rax
                    }
                    return 0xB0 + (reg.valid ? reg.code : 0); // al
                }
                case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0xB0 + (reg.valid ? reg.code : 0); // al
                    return 0xB8 + (reg.valid ? reg.code : 0); // ax/eax/rax
                }
                case OPERAND_MEM_DISP32:
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
                case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP8:
				case OPERAND_IMM_TO_MEM_DISP32: {
					*no_bytes = 1;
                    if (_8bit) return 0xC6;
                    return 0xC7; // imm -> mem
				}
				default: break;
            }
            break;
        case ASM_ADD: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x00;
                    return 0x01; // reg + reg
                }
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x83;
                }
                case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP8:
				case OPERAND_IMM_TO_MEM_DISP32:
				case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
                case OPERAND_MEM_DISP32:
				case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG:
                case OPERAND_MEM_DISP8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x02;
                    return 0x03;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
                    *no_bytes = 1;
                    if (_8bit) return 0x00;
                    return 0x01;
                }
                default: break;
            }
            break;

        case ASM_SUB: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x28;
                    return 0x29;
                }
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x83;
                }
                case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP8:
				case OPERAND_IMM_TO_MEM_DISP32:
				case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
                case OPERAND_MEM_DISP32:
				case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG:
                case OPERAND_MEM_DISP8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x2A;
                    return 0x2B;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
                    *no_bytes = 1;
                    if (_8bit) return 0x28;
                    return 0x29;
                }
                default: break;
            }
            break;
			
        case ASM_PUSH: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    *operand_mod = OPERAND_ONLY_OPCODE;
                    if (_8bit) break;
                    return 0x50 + rm.code;
                }
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    return 0x6A;
                }
                case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x6A;
                    return 0x68;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    return 0xFF;
                }
                default: break;
            }
            break;

        case ASM_POP: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    *operand_mod = OPERAND_ONLY_OPCODE;
                    if (_8bit) break;
                    return 0x58 + rm.code;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    return 0x8F;
                }
                default: break;
            }
            break;

        case ASM_CALL: // Works
            switch (modrm) {
                case OPERAND_CALL_REG:
                case OPERAND_REG_TO_REG: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    *operand_mod = OPERAND_CALL_REG;
                    return 0xFF;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    return 0xFF;
                }
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    return 0xE8;
                }
                default: break;
            }
            break;

        case ASM_RET: // Works
            switch (modrm) {
                case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    *operand_mod = OPERAND_RET_IMM;
                    return 0xC2;
                }
                default: break;
            }
            *no_bytes = 1;
            return 0xC3;

        case ASM_JMP: // Works
            switch (modrm) {
                case OPERAND_CALL_REG:
                case OPERAND_REG_TO_REG: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    *operand_mod = OPERAND_CALL_REG;
                    return 0xFF;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    return 0xFF;
                }
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 1;
                    return 0xE9;
                }
                default: break;
            }
            break;

        case ASM_JZ:
		case ASM_JE: // Works
            switch (modrm) {
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 2;
                    return 0x0F84;
                }
                default: break;
            }
			break;

        case ASM_JNZ:
		case ASM_JNE: // Works
           switch (modrm) {
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 2;
                    return 0x0F85;
                }
                default: break;
            }
			break;

        case ASM_JG: // Works
            switch (modrm) {
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 2;
                    return 0x0F8F;
                }
                default: break;
            }
			break;

        case ASM_JGE: // Works
            switch (modrm) {
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 2;
                    return 0x0F8D;
                }
                default: break;
            }
			break;

        case ASM_JL: // Works
            switch (modrm) {
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 2;
                    return 0x0F8C;
                }
                default: break;
            }
			break;

        case ASM_JLE: // Works
            switch (modrm) {
                case OPERAND_MEM_DISP32: {
                    if (_8bit) break;
                    *no_bytes = 2;
                    return 0x0F8E;
                }
                default: break;
            }
			break;

        case ASM_CMP: // Works
            switch (modrm) {
				case OPERAND_REG_TO_MEM:
				case OPERAND_REG_TO_MEM_DISP8:
				case OPERAND_REG_TO_MEM_DISP32: {
					*no_bytes = 1;
					if (_8bit) return 0x38;
					return 0x39;
				}
				case OPERAND_MEM_DISP32:
				case OPERAND_MEM_TO_REG:
				case OPERAND_MEM_DISP8_TO_REG:
				case OPERAND_MEM_DISP32_TO_REG:
				case OPERAND_REG_TO_REG: {
					*no_bytes = 1;
					if (_8bit) return 0x3A;
					return 0x3B;
				}
				case OPERAND_IMM8_TO_REG: {
					if (!_8bit) *operand_mod = OPERAND_IMM_TO_REG;
					*no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
				}
				case OPERAND_IMM32_TO_REG:
				case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP32:
				case OPERAND_IMM_TO_MEM_DISP8:
                case OPERAND_IMM_TO_REG: {
					*no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
				default: break;
            }
			break;

        case ASM_TEST: // Works
            switch (modrm) {
				case OPERAND_REG_TO_MEM:
				case OPERAND_REG_TO_MEM_DISP8:
				case OPERAND_REG_TO_MEM_DISP32: {
					*no_bytes = 1;
					if (_8bit) return 0x84;
					return 0x85;
				}
				case OPERAND_MEM_DISP32:
				case OPERAND_MEM_TO_REG:
				case OPERAND_MEM_DISP8_TO_REG:
				case OPERAND_MEM_DISP32_TO_REG:
				case OPERAND_REG_TO_REG: {
					*no_bytes = 1;
					if (_8bit) return 0x84;
					return 0x85;
				}
				case OPERAND_IMM8_TO_REG: {
					if (!_8bit) *operand_mod = OPERAND_IMM_TO_REG;
					*no_bytes = 1;
                    if (_8bit) return 0xF6;
                    return 0xF7;
				}
				case OPERAND_IMM32_TO_REG:
                case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP8:
				case OPERAND_IMM_TO_MEM_DISP32:
				case OPERAND_IMM_TO_REG: {
					*no_bytes = 1;
                    if (_8bit) return 0xF6;
                    return 0xF7;
                }
                default: break;
            }
			break;

        case ASM_AND: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x20;
                    return 0x21;
                }
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
				case OPERAND_IMM32_TO_REG:
                case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP8:
				case OPERAND_IMM_TO_MEM_DISP32:
				case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
                case OPERAND_MEM_DISP32:
				case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG:
                case OPERAND_MEM_DISP8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x22;
                    return 0x23;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
                    *no_bytes = 1;
                    if (_8bit) return 0x20;
                    return 0x21;
                }
                default: break;
            }
            break;

        case ASM_OR: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x08;
                    return 0x09;
                }
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
				case OPERAND_IMM32_TO_REG:
                case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP8:
				case OPERAND_IMM_TO_MEM_DISP32:
				case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
                case OPERAND_MEM_DISP32:
				case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG:
                case OPERAND_MEM_DISP8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x0A;
                    return 0x0B;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
                    *no_bytes = 1;
                    if (_8bit) return 0x08;
                    return 0x09;
                }
                default: break;
            }
            break;

        case ASM_XOR: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x30;
                    return 0x31;
                }
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
				case OPERAND_IMM32_TO_REG:
                case OPERAND_IMM_TO_MEM:
				case OPERAND_IMM_TO_MEM_DISP8:
				case OPERAND_IMM_TO_MEM_DISP32:
				case OPERAND_IMM_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x80;
                    return 0x81;
                }
                case OPERAND_MEM_DISP32:
				case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG:
                case OPERAND_MEM_DISP8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0x32;
                    return 0x33;
                }
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
                    *no_bytes = 1;
                    if (_8bit) return 0x30;
                    return 0x31;
                }
                default: break;
            }
            break;

        case ASM_NOT: // Works
            switch (modrm) {
                case OPERAND_REG_TO_REG: {
					if (reg.valid) break;
                    *no_bytes = 1;
                    if (_8bit) return 0xF6;
                    return 0xF7;
                }
                case OPERAND_MEM_DISP32:
				case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
					if (reg.valid) break;
                    *no_bytes = 1;
                    if (_8bit) return 0xF6;
                    return 0xF7;
                }
                default: break;
            }
            break;

        case ASM_SHL: // Works
            switch (modrm) {
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0xC0;
                    return 0xC1;
                }
                default: break;
            }
            break;

        case ASM_SHR: // Works
            switch (modrm) {
                case OPERAND_IMM8_TO_REG: {
                    *no_bytes = 1;
                    if (_8bit) return 0xC0;
                    return 0xC1;
                }
                default: break;
            }
            break;

		case ASM_INC: // Works
			switch (modrm) {
                case OPERAND_REG_TO_REG: {
					if (reg.valid) break;
                    *no_bytes = 1;
                    if (_8bit) return 0xFE;
                    return 0xFF;
                }
                case OPERAND_MEM_DISP32:
				case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
					if (reg.valid) break;
                    *no_bytes = 1;
                    if (_8bit) return 0xFE;
                    return 0xFF;
                }
                default: break;
            }
            break;

		case ASM_DEC: // Works
			switch (modrm) {
                case OPERAND_REG_TO_REG: {
					if (reg.valid) break;
                    *no_bytes = 1;
                    if (_8bit) return 0xFE;
                    return 0xFF;
                }
				case OPERAND_MEM_DISP32:
                case OPERAND_REG_TO_MEM:
                case OPERAND_REG_TO_MEM_DISP32:
                case OPERAND_REG_TO_MEM_DISP8: {
					if (reg.valid) break;
                    *no_bytes = 1;
                    if (_8bit) return 0xFE;
                    return 0xFF;
                }
                default: break;
            }
            break;

        case ASM_SYSCALL: // Works
			if (bits != 64) break;
            *operand_mod = OPERAND_ONLY_OPCODE;
            *no_bytes = 2;
            return 0x0F05;

		case ASM_INT: // Works
			switch (modrm) {
				case OPERAND_IMM8_TO_REG: {
					*no_bytes = 1;
					return 0xCD;
				}
				default: break;
			}
			break;

        case ASM_LEA: // Works
            switch (modrm) {
                case OPERAND_MEM_TO_REG:
                case OPERAND_MEM_DISP32:
				case OPERAND_MEM_DISP8_TO_REG:
                case OPERAND_MEM_DISP32_TO_REG: {
                    *no_bytes = 1;
                    return 0x8D;
                }
                default: break;
            }
            break;
        case ASM_NOP: // Works
            *operand_mod = OPERAND_ONLY_OPCODE;
            *no_bytes = 1;
            return 0x90;

        default:
            *no_bytes = 0;
            return 0;
    }
    *no_bytes = 0;
    return 0;
}

static uint8_t make_sib(RegInfo index, RegInfo base, uint8_t mult) {
    uint8_t sib = 0;
    if (!index.valid || !base.valid) return sib;

    sib |= base.code & 0b00000111;
    sib |= (index.code & 0b00000111) << 3;
    sib |= (mult & 0b00000011) << 6;
    return sib;
}

static bool parse_memory_operand(Assembler* ctx, IRInstruction* ir, const char* op, bool* issrc, RegInfo* src, RegInfo* dest, RegInfo* sib_index, uint8_t* sib_scale, int64_t* imm, int* operand_mod, bool* is_symbol) {
    // remove brackets
    char buf[128]; 
    size_t len = strlen(op);
    if (len < 3 || op[0] != '[' || op[len - 1] != ']') {
		PAC_ERRORF(ctx->cur_file, ir->line, ir->col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Invalid Memory Operand!");
		fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
		print_ir(ir);
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
			bool err = false;
            RegInfo r = encode_register(ctx->bits, term, &err);
			if (err) return false;
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
				PAC_ERRORF(ctx->cur_file, ir->line, ir->col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Invalid SIB Scale!");
                fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
				print_ir(ir);
				return false;
            }
            *sib_scale = (uint8_t)sib_mult;
        }
    }

    if (!base_r.valid && !*is_symbol) {
        if (src->valid) {
            *operand_mod = OPERAND_REG_TO_MEM_DISP32;
            *dest = (RegInfo){0};
        } else {
            *operand_mod = OPERAND_MEM_DISP32_TO_REG;
            *src = (RegInfo){0};
        }
    } else if (*imm == 0 && !*is_symbol) {
        if (!*issrc) {
            *operand_mod = OPERAND_REG_TO_MEM;
            *dest = base_r;
            *issrc = true;
        } else {
            *operand_mod = OPERAND_MEM_TO_REG;
            *src = base_r;
            *issrc = false;
        }
    } else if (*imm >= -128 && *imm <= 127 && !*is_symbol) {
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
        if (*is_symbol && !base_r.valid) {
            *operand_mod = OPERAND_MEM_DISP32;
        } else if (!*issrc) {
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

bool encode_x86_64(Assembler* ctx, FILE* out, IRList* irlist, int bits, bool unlocked, size_t text_off, Section* text_sec, uint64_t* symbol_list, size_t symbol_list_size) {
    // [REX prefix] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
    // REX prefix = 0100WRXB
    size_t cur_symbol_idx = 0;

	(void)unlocked;

	// Reset
    inst_buf_capacity = MAX_INST_BUF_SIZE;
    inst_buf = (uint8_t*)malloc(inst_buf_capacity);
	if (!inst_buf) {
		fprintf(stderr, COLOR_RED "Error: Allocation failed!\n" COLOR_RESET);
		return false;
	}
    inst_buf_init = true;
    inst_buf_off = 0;
    inst_text_off = 0;
    out_text_off = text_off;
	inst_written = 0;
	no_update_inst_written_in_pad = false;

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
			PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Architecture Unsupported Instruction!");
			fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
			print_ir(&inst);
			if (inst_buf) free(inst_buf);
			return false;
        }

        RegInfo src = {0};
        RegInfo dest = {0};
        RegInfo sib_index = {0};
        uint8_t sib_scale = 0;
        int64_t imm = 0;
		int64_t simm = 0;

        bool issrc = false;
        bool is_symbol = true;
        int operand_mod = OPERAND_REG_TO_REG;

        for (size_t j = 0; j < inst.operand_count; j++) {
            char* operand = inst.operands[j];
            OperandType optype = classify_operand((const char*)operand);

            switch (optype) {
                case OPERAND_REGISTER:
					bool err = false;
                    if (issrc) { src = encode_register(bits, operand, &err); issrc = false; }
                    else {dest = encode_register(bits, operand, &err); issrc = true; }

					if (err) {
						printf(COLOR_RED "Error At: \n\t" COLOR_RESET);
						print_ir(&inst);
						if (inst_buf) free(inst_buf);
						return false;
					}
                    break;
                case OPERAND_LIT_INT:
                    if (operand_mod == OPERAND_REG_TO_REG) {
						imm = strtoul(operand, NULL, 10);
						operand_mod = OPERAND_IMM_TO_REG;
					} else {
						simm = strtoul(operand, NULL, 10);

						if (operand_mod == OPERAND_REG_TO_MEM) operand_mod = OPERAND_IMM_TO_MEM;
						else if (operand_mod == OPERAND_MEM_DISP32) operand_mod = OPERAND_IMM_TO_MEM_DISP32;
						else if (operand_mod == OPERAND_REG_TO_MEM_DISP8) operand_mod = OPERAND_IMM_TO_MEM_DISP8; 
						else if (operand_mod == OPERAND_REG_TO_MEM_DISP32) operand_mod = OPERAND_IMM_TO_MEM_DISP32; 
						else imm = simm;
					}
					break;
                case OPERAND_MEMORY:
                    if (!parse_memory_operand(ctx, &inst, operand, &issrc, &src, &dest, &sib_index, &sib_scale, &imm, &operand_mod, &is_symbol)) {
						if (inst_buf) free(inst_buf);
						return false;
					}
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
					PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, operand, 0, "Unknown Operand");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
					return false;
            }
        }

        if (src.valid && src.size > bits) {
            if (src.size == 32 && bits == 16) {
            } else {
				PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, src.name, 0, "Invalid Register");
                fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
				print_ir(&inst);
				if (inst_buf) free(inst_buf);
				return false;
            }
        }
        if (dest.valid && dest.size > bits) {
            if (src.size == 32 && bits == 16) {
            } else {
				PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, dest.name, 0, "Invalid Register");
                fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
				print_ir(&inst);
				if (inst_buf) free(inst_buf);
				return false;
            }
        }

        if (inst.operand_count == 0) operand_mod = OPERAND_ONLY_OPCODE;

        RegInfo* r_reg = &src;
        RegInfo* r_rm = &dest;

        switch (operand_mod) {
            case OPERAND_REG_TO_REG: {
				switch (inst.opcode) {
					case ASM_CALL: {
						operand_mod = OPERAND_CALL_REG;
						break;
					}
					default: break;
				}
                break;
            }
            case OPERAND_IMM32_TO_REG:
            case OPERAND_IMM_TO_REG: {
                if (imm < 0xFF) operand_mod = OPERAND_IMM8_TO_REG;
                break;
            }
            default: break;
        }

        switch (operand_mod) {
            case OPERAND_REG_TO_REG: {
                if (src.valid && dest.valid && src.size != dest.size) {
					PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, src.name, 0, "Size Mismatch between registers!");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
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
            case OPERAND_IMM8_TO_REG:
            case OPERAND_IMM_TO_REG: {
                r_reg = &dest;
                r_rm = &src;
                uint64_t sz = 0xFF;
                if (dest.size == 16) sz = 0xFFFF;
                else if (dest.size == 32) sz = 0xFFFFFFFF;
                else if (dest.size == 64) sz = 0xFFFFFFFFFFFFFFFF;
                if (dest.valid && sz < (uint64_t)imm) {
                    PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, dest.name, 0, "Size Mismatch between IMM and Register!");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
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
			case OPERAND_IMM_TO_MEM_DISP8:
			case OPERAND_IMM_TO_MEM_DISP32:
			case OPERAND_IMM_TO_MEM: {
                if (dest.valid && dest.code != 0b100 && dest.rex_ex) dest.rex_b = true;
                else if (dest.valid && dest.code == 0b100 && dest.rex_ex) dest.rex_x = true;
                
                if (bits > 16 && (dest.valid && dest.size == 16)) {
                    emit_bytes(out, (uint8_t*)"\x66", 1);
                } else if (bits == 16 && (dest.valid && dest.size == 32)) {
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
					PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, dest.name, 0, "Size Mismatch between IMM and Register!");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
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
            case OPERAND_CALL_REG: {
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

        uint64_t opcode_full = get_opcode(bits, inst.opcode, &no_bytes, &operand_mod, *r_reg, *r_rm);

        if (no_bytes == 0) {
            PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Invalid Instruction");
            fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
			print_ir(&inst);
			if (inst_buf) free(inst_buf);
			return false;
        }
        for (int i = no_bytes - 1; i >= 0; i--) {
            uint8_t opcode = (opcode_full >> (i * 8)) & 0xFF;
            emit_bytes(out, &opcode, 1);
        }
        
        switch (operand_mod) {
            case OPERAND_REG_TO_REG: {
				switch (inst.opcode) {
					case ASM_NOT:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 2;
                        break;
					case ASM_INC:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        break;
					case ASM_DEC:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 1;
                        break;
					default: break;
				}
                uint8_t modrm_b = make_modrm(*r_reg, *r_rm, MODRM_MOD_REG_TO_REG);
                emit_bytes(out, &modrm_b, 1);
                break;
            }
            case OPERAND_MEM_DISP32: { // label, just emit disp32
                uint8_t modrm = 0;
				switch (inst.opcode) {
					case ASM_JMP:
					case ASM_JE:
					case ASM_JNE:
					case ASM_JG:
					case ASM_JGE:
					case ASM_JL:
					case ASM_JLE:
					case ASM_JNZ:
					case ASM_JZ:
					case ASM_CALL: break;
					case ASM_NOT:
						modrm = make_modrm((RegInfo){.code=2, .valid=true},(RegInfo){.code=0b101, .valid=true}, MODRM_MOD_MEMORY);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_INC:
						modrm = make_modrm((RegInfo){.code=0, .valid=true},(RegInfo){.code=0b101, .valid=true}, MODRM_MOD_MEMORY);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_DEC:
						modrm = make_modrm((RegInfo){.code=1, .valid=true},(RegInfo){.code=0b101, .valid=true}, MODRM_MOD_MEMORY);
                        emit_bytes(out, &modrm, 1);
                        break;
					default: {
                        modrm = make_modrm(dest, (RegInfo){.code=0b101, .valid=true}, MODRM_MOD_MEMORY);
                        emit_bytes(out, &modrm, 1);
                        break;
                    }
                }
                size_t symindex = get_sym_index_via_addr(ctx->symbols, imm);

                add_reloc(text_sec, inst_written + text_off, symindex, bits == 64 ? R_X86_64_PC32 : R_X86_64_32, bits == 64 ? -4 : 0);
                emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                break;
            }
            case OPERAND_IMM8_TO_REG: {
                uint8_t modrm = 0;
                switch (inst.opcode) {
                    case ASM_ADD:
                        modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_SHL:
                        modrm = make_modrm((RegInfo){.code=4,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_SHR:
                        modrm = make_modrm((RegInfo){.code=5,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_OR:
                        modrm = make_modrm((RegInfo){.code=1,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_XOR:
                        modrm = make_modrm((RegInfo){.code=6,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
                    case ASM_SUB:
                        modrm = make_modrm((RegInfo){.code=5,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_CMP:
						modrm = make_modrm((RegInfo){.code=7,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_TEST:
						modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
                    default: break;
                }
                emit_bytes(out, (uint8_t*)&imm, 1);
                break;
            }
            case OPERAND_IMM_TO_REG: {
                size_t sz = dest.size == 64 ? 4 : dest.size / 8;
                uint8_t modrm = 0;
                switch (inst.opcode) {
                    case ASM_ADD:
                        modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_OR:
                        modrm = make_modrm((RegInfo){.code=1,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_XOR:
                        modrm = make_modrm((RegInfo){.code=6,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
                    case ASM_SUB:
                        modrm = make_modrm((RegInfo){.code=5,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
                    case ASM_MOV:
                        sz = (dest.size / 8);
                        break;
					case ASM_CMP:
						modrm = make_modrm((RegInfo){.code=7,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_TEST:
						modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
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
                if (bits == 64 && dest.valid && dest.code == 0b101 && !dest.rex_w) {
                    PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Cannot use RIP as a destination register!");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
					return false;
                }
                if (bits == 64 && src.valid && src.code == 0b101) {
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
                switch (inst.opcode) {
					case ASM_JMP:
                        memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 4;
                        break;
                    case ASM_CALL:
                        memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 2;
                        break;
					case ASM_PUSH:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 6;
                        break;
					case ASM_NOT:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 2;
                        break;
					case ASM_INC:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        break;
					case ASM_DEC:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 1;
                        break;
                    default: break;
                }
                
                bool rip_mode = false;
                bool rbp_mode = false;
                bool rsp_sib = false;
                if (bits == 64 && src.valid && src.code == 0b101 && !src.rex_w) {
                    PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Cannot use RIP as a source register!");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
					return false;
                }
                if (bits == 64 && dest.valid && dest.code == 0b101) {
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
                uint8_t modrm = 0;
                switch (inst.opcode) {
                    case ASM_ADD:
                        modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
                    case ASM_SUB:
                        modrm = make_modrm((RegInfo){.code=5,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_OR:
                        modrm = make_modrm((RegInfo){.code=1,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_XOR:
                        modrm = make_modrm((RegInfo){.code=6,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_CMP:
						modrm = make_modrm((RegInfo){.code=7,.valid=true},dest,MODRM_MOD_REG_TO_REG);
                        emit_bytes(out, &modrm, 1);
                        break;
					case ASM_TEST:
						modrm = make_modrm((RegInfo){.code=0,.valid=true},dest,MODRM_MOD_REG_TO_REG);
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
                switch (inst.opcode) {
					case ASM_JMP:
                        memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 4;
                        break;
                    case ASM_CALL:
                        memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 2;
                        break;
					case ASM_PUSH:
                        r_reg->valid = true;
                        r_reg->code = 6;
                        break;
					case ASM_NOT:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 2;
                        break;
					case ASM_INC:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        break;
					case ASM_DEC:
						memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 1;
                        break;
                    default: break;
                }

                bool rip_mode = false;
                bool rsp_sib = false;
                if (bits == 64 && src.valid && src.code == 0b101 && !src.rex_w) {
                    PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Cannot use RIP as a source register!");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
					return false;
                }
                if (bits == 64 && dest.valid && dest.code == 0b101 && !dest.rex_ex) rip_mode = true;
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
                        add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_8, 0);
                        emit_bytes(out, (uint8_t*)"\0", 1);
                    } else {
                        add_reloc(text_sec, inst_written + text_off, symindex, rip_mode ? R_X86_64_PC32 : R_X86_64_32, rip_mode ? -4 : 0);
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
                if (bits == 64 && dest.valid && dest.code == 0b101 && !dest.rex_w) {
                    PAC_ERRORF(ctx->cur_file, inst.line, inst.col, ctx->cur_file_src, ctx->cur_file_len, NULL, 0, "Cannot use RIP as a destination register!");
                    fprintf(stderr, COLOR_RED "Generated IR of this Instruction: \n\t" COLOR_RESET);
					print_ir(&inst);
					if (inst_buf) free(inst_buf);
					return false;
                }
                if (bits == 64 && src.valid && src.code == 0b101 && !src.rex_ex) rip_mode = true;
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
                        add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_8, 0);
                        emit_bytes(out, (uint8_t*)"\0", 1);
                    } else {
                        add_reloc(text_sec, inst_written + text_off, symindex, rip_mode ? R_X86_64_PC32 : R_X86_64_32, rip_mode ? -4 : 0);
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
            case OPERAND_CALL_REG: {
				switch (inst.opcode) {
					case ASM_JMP:
                        memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 4;
                        break;
                    case ASM_CALL:
                        memset(r_reg, 0, sizeof(RegInfo));
                        r_reg->valid = true;
                        r_reg->code = 2;
                        break;
					default: break;
				}
                uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_REG_TO_REG);
                emit_bytes(out, &modrm, 1);
                break;
            }
            case OPERAND_IMM_TO_MEM: {
				memset(r_reg, 0, sizeof(RegInfo));
				r_reg->code = 0x0;
				r_reg->valid = true;

                bool rip_mode = false;
                bool rbp_mode = false;
                bool rsp_sib = false;
                if (bits == 64 && dest.valid && dest.code == 0b101) {
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
				emit_bytes(out, (uint8_t*)&simm, 4);
                break;
			}
			case OPERAND_IMM_TO_MEM_DISP8:
			case OPERAND_IMM_TO_MEM_DISP32: {
				memset(r_reg, 0, sizeof(RegInfo));
				r_reg->code = 0x0;
				r_reg->valid = true;

                bool rip_mode = false;
                bool rsp_sib = false;
                if (dest.valid && dest.code == 0b101 && !dest.rex_ex) rip_mode = true;
                if (dest.valid && dest.code == 0b100) rsp_sib = true;

                if (rip_mode) {
                    uint8_t modrm_bytes = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
                    emit_bytes(out, &modrm_bytes, 1);
                } else {
					if (operand_mod == OPERAND_IMM_TO_MEM_DISP8) {
						uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEM_PLUS_DISP8);
						emit_bytes(out, &modrm, 1);
					} else {
						memset(r_rm, 0, sizeof(RegInfo));
						r_rm->valid = true;
						r_rm->code = 0b101;
						uint8_t modrm = make_modrm(*r_reg, *r_rm, MODRM_MOD_MEMORY);
						emit_bytes(out, &modrm, 1);
					}
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

                    if (operand_mod == OPERAND_IMM_TO_MEM_DISP8 && !rip_mode && !rsp_sib) {
                        add_reloc(text_sec, inst_written + text_off, symindex, R_X86_64_8, 0);
                        emit_bytes(out, (uint8_t*)"\0", 1);
                    } else {
                        add_reloc(text_sec, inst_written + text_off, symindex, rip_mode ? R_X86_64_PC32 : R_X86_64_32, rip_mode ? -4 : 0);
                        emit_bytes(out, (uint8_t*)"\0\0\0\0", 4);
                    }
                } else {
                    if (operand_mod == OPERAND_IMM_TO_MEM_DISP8 && !rip_mode && !rsp_sib) {
                        emit_bytes(out, (uint8_t*)&imm, 1);
                    } else {
                        emit_bytes(out, (uint8_t*)&imm, 4);
                    }
                }
				emit_bytes(out, (uint8_t*)&simm, 4);
                break;
			}
			default: break;
        }
    }

    if (inst_written > text_sec->size) {
        fprintf(stderr, COLOR_RED "Error: Somehow the contents of an section exceed the section's reserved size!\n\tCurrent Size: %lu bytes\n\tReserved Size: %lu bytes\n" COLOR_RESET, inst_written, text_sec->size);
		if (inst_buf) free(inst_buf);
        return false;
    } else if (inst_written < text_sec->size) {
        text_sec->size = ALIGN_UP(inst_written, 16);
        no_update_inst_written_in_pad = true;
        size_t remaining = (text_sec->size - inst_written);
        size_t triple_nops = (size_t)(remaining / 3);
        for (size_t i = 0; i < triple_nops; i++) {
            emit_bytes(out, (uint8_t*)"\x0F\x1F\x00", 3); // use nop [eax]
            remaining -= 3;
        }

        for (size_t i = 0; i < remaining; i++) {
            emit_bytes(out, (uint8_t*)"\x90", 1); // use nop
        }
    }
    no_update_inst_written_in_pad = false;

    flush_everything(out);
	if (inst_buf) free(inst_buf);

    return true;
}
