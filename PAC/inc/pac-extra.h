#pragma once

#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_DIM     "\033[2m"

#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_GRAY    "\033[1;90m"

#define align_up(val, to) (((val) + (to) - 1) & ~((to) - 1))
#define max(a, b) (((a) > (b)) ? (a) : (b))

enum Architecture {
    x86_64,
    ARM64,
    ARM32,
    x86,
    RISCV32,
    RISCV64,
    PVCPU,
    UNKNOWN_ARCH,
};

enum Architecture archs_to_archenum(char* arch);
void archenum_to_archs(enum Architecture arch, char* archs);
void freeliness(char** lines, int num_lines);
char** splitlines(const char* s, int* num_lines);
void rmchr(char* str, char c);
void pac_strdup(char* src, char* dest);
void* recalloc(void* ptr, size_t old_count, size_t new_count, size_t size);
bool is_sdigit(const char *str);