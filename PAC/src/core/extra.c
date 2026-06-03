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
	#include <windows.h>
#else
	#include <sys/utsname.h>
#endif

#include <pac-extra.h>

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

// Total 2MB
uint8_t PHDR_GPOOL[0x200000]; // 2MB worth of stack
static size_t gpool_used = 0;

static size_t find_free_stack(size_t sz, bool* found) {
	if (gpool_used == 0) {
		*found = true;
		return 0;
	}
	size_t size = align_up(sz, 8);

	size_t cfree_size = 0;
	size_t sfree_idx = 0;
	for (size_t i = 0; i < sizeof(PHDR_GPOOL); i++) {
		// this func trusts the pac_malloc allocator very very much
		if (i + sizeof(PAC_MHDR) > sizeof(PHDR_GPOOL)) break;
		if (cfree_size >= size) { *found = true; return sfree_idx; }

		PAC_MHDR* p = (PAC_MHDR*)&PHDR_GPOOL[i];
		bool valid = (p->flags & PAC_MHDR_FLAG_STACK) && p->size <= PAC_STACK_LIMIT && p->magic == PAC_MHDR_MAGIC;
		bool free = valid && (p->flags & PAC_MHDR_FLAG_FREE);

		if (free) {
			if (cfree_size <= 0) {
				cfree_size = p->size;
				sfree_idx = i;
				i += sizeof(PAC_MHDR) + p->size - 1;
			} else {
				cfree_size += sizeof(PAC_MHDR) + p->size;
				i += sizeof(PAC_MHDR) + p->size - 1;
			}
		} else {
			cfree_size = valid ? cfree_size + 1 : 0;
			sfree_idx = valid ? i : 0;
			i += valid ? sizeof(PAC_MHDR) + p->size - 1 : 0;
		}
	}

	*found = false;
	return 0;
}

void* pac_malloc(size_t sz) {
	if (sz <= 0) return NULL;

	size_t size = align_up(sz, 8);

	if (size + sizeof(PAC_MHDR) > PAC_STACK_LIMIT || gpool_used + size + sizeof(PAC_MHDR) > sizeof(PHDR_GPOOL)) {
		PAC_MHDR* ptr = (PAC_MHDR*)malloc(size + sizeof(PAC_MHDR));
		if (!ptr) return (void*)ptr; // Or NULL in simple words

		ptr->size = size;
		ptr->flags = PAC_MHDR_FLAG_HEAP;
		ptr->magic = PAC_MHDR_MAGIC;
		return (void*)((char*)ptr + sizeof(PAC_MHDR));
	} else {
		bool found = false;
		size_t idx = find_free_stack(size + sizeof(PAC_MHDR), &found);

		if (!found) {
			PAC_MHDR* ptr = (PAC_MHDR*)malloc(size + sizeof(PAC_MHDR));
			if (!ptr) return (void*)ptr; // Or NULL in simple words

			ptr->size = size;
			ptr->flags = PAC_MHDR_FLAG_HEAP;
			ptr->magic = PAC_MHDR_MAGIC;
			return (void*)((char*)ptr + sizeof(PAC_MHDR));
		}

		PAC_MHDR* ptr = (PAC_MHDR*)&PHDR_GPOOL[idx];

		ptr->size = size;
		ptr->magic = PAC_MHDR_MAGIC;
		ptr->flags = PAC_MHDR_FLAG_STACK;
    	gpool_used += size + sizeof(PAC_MHDR);

		return (void*)((char*)ptr + sizeof(PAC_MHDR));
	}
}
void pac_free(void* ptr) {
	if (!ptr)
        return;

    PAC_MHDR* hdr = (PAC_MHDR*)((char*)ptr - sizeof(PAC_MHDR));

    if (hdr->magic != PAC_MHDR_MAGIC)
        return;

    if (hdr->flags & PAC_MHDR_FLAG_HEAP) {
        free(hdr);
        return;
    }

    if (hdr->flags & PAC_MHDR_FLAG_STACK) {
        if (!(hdr->flags & PAC_MHDR_FLAG_FREE)) {
            hdr->flags |= PAC_MHDR_FLAG_FREE;

            size_t block_size = sizeof(PAC_MHDR) + hdr->size;

            if (gpool_used >= block_size)
                gpool_used -= block_size;
            else
                gpool_used = 0;
        }
    }
}
void* pac_realloc(void* ptr, size_t new_size) {
	if (!ptr) return malloc(new_size);

    if (new_size == 0) {
        free(ptr);
        return NULL;
    }

    PAC_MHDR* hdr = (PAC_MHDR*)((char*)ptr - sizeof(PAC_MHDR));

    if (hdr->magic != PAC_MHDR_MAGIC)
        return NULL;

    size_t old_size = hdr->size;

    if (old_size >= new_size) {
        hdr->size = align_up(new_size, 8);
        return ptr;
    }
    void *new_ptr = malloc(new_size);

    if (!new_ptr)
        return NULL;

    memcpy(new_ptr, ptr, old_size);
    free(ptr);

    return new_ptr;
}
void* pac_calloc(size_t nmemb, size_t size) {
    if (nmemb == 0 || size == 0)
        return malloc(0);

    if (nmemb > SIZE_MAX / size)
        return NULL;

    size_t total = nmemb * size;
    void *ptr = malloc(total);

    if (ptr) memset(ptr, 0, total);

    return ptr;
}

