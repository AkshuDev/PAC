#pragma once

#include <stddef.h>
#include <stdbool.h>

typedef enum {
    ELF32,
    ELF64,
    WIN32,
    WIN64,
} LinkerFormat;

char* linker_format_to_str(LinkerFormat outformat);
LinkerFormat str_to_linker_format(char* s);
bool pac_link(char* outfile, char** input_files, size_t input_file_count, LinkerFormat outformat, size_t base_vaddr);