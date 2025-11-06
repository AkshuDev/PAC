#pragma once

#include <string.h>

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

enum Architecture {
    x86_64,
    ARM64,
    x86,
    PVCPU,
    UNKNOWN_ARCH,
};

static inline enum Architecture archs_to_archenum(char* arch) {
    if (!arch) {
        return UNKNOWN_ARCH;
    }

    if (strcmp(arch, "x86_64") == 0) {
        return x86_64;
    } else if (strcmp(arch, "arm64") == 0) {
        return ARM64;
    } else if (strcmp(arch, "x86") == 0) {
        return x86;
    } else if (strcmp(arch, "pvcpu") == 0) {
        return PVCPU;
    }

    return UNKNOWN_ARCH;
}

static inline void archenum_to_archs(enum Architecture arch, char* archs) {
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
        case PVCPU:
            strcpy(archs, "pvcpu");
            break;
        default:
            strcpy(archs, "unknown");
            break;
    }
}

static inline void freeliness(char** lines, int num_lines) {
    if (lines == NULL) return;
    for (int i = 0; i < num_lines; i++) {
        if (lines[i] != NULL) {
            free(lines[i]);
        }
    }
    free(lines);
}

static inline char** splitlines(const char* s, int* num_lines) {
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

static inline void rmchr(char* str, char c) {
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

static inline void pac_strdup(char* src, char* dest) {
    if (src == NULL || dest == NULL) return;
    strcpy(src, dest);
}