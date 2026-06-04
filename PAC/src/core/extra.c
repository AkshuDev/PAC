#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define PAC_MHDR_MAGIC 0x10AC9D11 // 10 (16) = P, A, C, (D (13) = M (skipped for 4 byte alignment)), 9 = H, D, 11 (17) = R
#define PAC_STACK_LIMIT 0x1000
#define PAC_MHDR_FLAG_STACK (0 << 1)
#define PAC_MHDR_FLAG_HEAP (1 << 1)
#define PAC_MHDR_FLAG_FREE (2 << 1)

#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#define NOMINMAX
	#include <windows.h>
#else
	#include <sys/utsname.h>
#endif

#include <pac-extra.h>
#include <pac-asm.h>

typedef struct {
	uint32_t magic;
    uint64_t size;
    uint32_t flags;
} PAC_MHDR;

enum Architecture archs_to_archenum(char* arch) {
    if (!arch) {
        return UNKNOWN_ARCH;
    }

    if (strcmp(arch, "x86_64") == 0 || strcmp(arch, "x64") == 0) {
        return x86_64;
    } else if (strcmp(arch, "arm64") == 0 || strcmp(arch, "aarch64") == 0) {
        return ARM64;
    } else if (strcmp(arch, "arm32") == 0 || strcmp(arch, "armv7l") == 0 || strcmp(arch, "armv8l") == 0 || strcmp(arch, "armv9l") == 0) {
        return ARM32;
    } else if (strcmp(arch, "riscv32") == 0) {
        return RISCV32;
    } else if (strcmp(arch, "riscv64") == 0) {
        return RISCV64;
    } else if (strcmp(arch, "x86") == 0 || strcmp(arch, "i386") == 0 || strcmp(arch, "i486") == 0 || strcmp(arch, "i586") == 0 || strcmp(arch, "i686") == 0) {
        return x86;
    } else if (strcmp(arch, "pvcpu") == 0) {
        return PVCPU;
    }

    return UNKNOWN_ARCH;
}

void archenum_to_archs(enum Architecture arch, char* archs) {
    switch (arch) {
        case x86_64:
            strcpy(archs, "x86_64");
            break;
        case x86:
            strcpy(archs, "x86");
            break;
        case ARM64:
            strcpy(archs, "arm64");
            break;
        case ARM32:
            strcpy(archs, "arm32");
            break;
        case RISCV32:
            strcpy(archs, "riscv32");
            break;
        case RISCV64:
            strcpy(archs, "riscv64");
            break;
        case PVCPU:
            strcpy(archs, "pvcpu");
            break;
        default:
            strcpy(archs, "unknown");
            break;
    }
}

void freeliness(char** lines, int num_lines) {
    if (lines == NULL) return;
    for (int i = 0; i < num_lines; i++) {
        if (lines[i] != NULL) {
            free(lines[i]);
        }
    }
    free(lines);
}

char** splitlines(const char* s, int* num_lines) {
    if (s == NULL) return NULL;

    // First pass: Count the number of lines
    int count = 0;
    const char* ptr = s;
    while (*ptr != '\0') {
        if (*ptr == '\n') {
            count++;
            if (ptr > s && *(ptr - 1) == '\r') {
                // This is part of a \r\n sequence, so don't double count
            }
        }
        ptr++;
    }
    // Add one for the last line, if the string doesn't end with a newline
    if (ptr > s && *(ptr - 1) != '\n') {
        count++;
    }

    *num_lines = count;
    if (count == 0) return NULL;

    // Allocate memory for the array of line pointers
    char** lines = (char**)malloc(count * sizeof(char*));
    if (lines == NULL) {
        return NULL;
    }

    // Second pass: Extract and copy each line
    ptr = s;
    int line_index = 0;
    const char* start_of_line = s;

    while (*ptr != '\0') {
        if (*ptr == '\n') {
            size_t line_len = ptr - start_of_line;
            // Adjust length if the sequence was \r\n
            if (line_len > 0 && *(ptr - 1) == '\r') {
                line_len--;
            }

            lines[line_index] = (char*)malloc((line_len + 1) * sizeof(char));
            if (lines[line_index] == NULL) {
                // Free previously allocated memory and return NULL to indicate failure
                freeliness(lines, line_index);
                *num_lines = 0;
                return NULL;
            }
            strncpy(lines[line_index], start_of_line, line_len);
            lines[line_index][line_len] = '\0';
            line_index++;

            start_of_line = ptr + 1;
        }
        ptr++;
    }

    // Handle the last line if it does not end with a newline
    if (ptr > start_of_line) {
        size_t line_len = ptr - start_of_line;
        lines[line_index] = (char*)malloc((line_len + 1) * sizeof(char));
        if (lines[line_index] == NULL) {
            freeliness(lines, line_index);
            *num_lines = 0;
            return NULL;
        }
        strncpy(lines[line_index], start_of_line, line_len);
        lines[line_index][line_len] = '\0';
        line_index++;
    }

    return lines;
}

void rmchr(char* str, char c) {
    size_t read = 0;
    size_t write = 0;
    while (str[read] != '\0') {
        if (str[read] != c) {
            str[write] = str[read];
            write++;
        }
        read++;
    }
    str[write] = '\0'; // null terminate
}

void pac_strdup(char* src, char* dest) {
    if (src == NULL || dest == NULL) return;
    strcpy(dest, src);
}

void* recalloc(void* ptr, size_t old_count, size_t new_count, size_t size) {
    size_t old_size = old_count * size;
    size_t new_size = new_count * size;

    void* new_ptr = realloc(ptr, new_size);
    if (!new_ptr) return NULL;

    if (new_size > old_size) {
        memset((char*)new_ptr + old_size, 0, new_size - old_size);
    }

    return new_ptr;
}

bool is_sdigit(const char *str) {
    if (*str == '\0') return false;

    while (*str) {
        if (!isdigit((unsigned char)*str)) {
            return false;
        }
        str++;
    }
    return true;
}

enum Architecture host_arch(void) {
	#ifdef _WIN32
		SYSTEM_INFO sysInfo;
		GetNativeSystemInfo(&sysInfo);

		switch (sysInfo.wProcessorArchitecture) {
			case PROCESSOR_ARCHITECTURE_AMD64: return x86_64;
			case PROCESSOR_ARCHITECTURE_ARM64: return ARM64;
			case PROCESSOR_ARCHITECTURE_INTEL: return x86;
			case PROCESSOR_ARCHITECTURE_ARM: return ARM32;
			default: return UNKNOWN_ARCH;
		}
		return UNKNOWN_ARCH;
	#else
		struct utsname buf;
		if (uname(&buf) == 0) {
			return archs_to_archenum(buf.machine);
		} else {
			return UNKNOWN_ARCH;
		}
	#endif
	return UNKNOWN_ARCH;
}

unsigned int arch_bits(enum Architecture arch) {
	switch (arch) {
		case RISCV64:
		case ARM64:
		case PVCPU:
		case x86_64: return 64;
		case RISCV32:
		case ARM32:
		case x86: return 32;
		default: return 0;
	}
}

size_t get_sym_index_via_addr(SymbolTable* symtab, size_t addr) {
    for (size_t i = 0; i < symtab->count; i++) {
        Symbol sym = symtab->symbols[i];
        if (sym.type != SYM_IDENTIFIER && sym.type != SYM_LABEL) continue;
        if (sym.addr2 == addr) { // match
            // we found it
            return i;
        }
    }
    return 0;
}

OperandType classify_operand(const char* op) {
    if (op[0] == '0' && op[1] == 'x') return OPERAND_LABEL; // print, exit
    if (op[0] == '[') return OPERAND_MEMORY; // [0x1234], [var], [%rax + 0x1234], [%rax - 0x1234]
    if (isdigit(op[0])) return OPERAND_LIT_INT; // 42, 0x1234
    if (isalpha(op[0])) return OPERAND_REGISTER; // %rax, %r8
    return (OperandType)-1;
}

