#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

#include <pac-linker.h>
#include <pac-asm.h>
#include <pac-extra.h>

static char* linker_read_file(const char* path, size_t* len) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    char* buffer = malloc(size + 1);
    fread(buffer, 1, size, f);
    buffer[size] = '\0';
    fclose(f);
    *len = size;
    return buffer;
}

char* linker_format_to_str(LinkerFormat outformat) {
    switch (outformat) {
        case ELF64: return "elf64";
        case ELF32: return "elf32";
        case WIN32: return "win32";
        case WIN64: return "win64";
        default: return "Unknown";
    }
    return NULL;
}

LinkerFormat str_to_linker_format(char* s) {
    if (s == NULL || !s) return (LinkerFormat)-1;
    if (strcmp(s, "elf64") == 0) return ELF64;
    else if (strcmp(s, "elf32") == 0) return ELF32;
    else if (strcmp(s, "win64") == 0) return WIN64;
    else if (strcmp(s, "win32") == 0) return WIN32;

    return (LinkerFormat)-1;
}

static bool pac_link_elf64(char* outfile, char** input_files, size_t input_file_count, size_t base_vaddr) {
    if (input_files == NULL || input_file_count == 0) {
        fprintf(stderr, COLOR_RED "Error: No input files provided!\n" COLOR_RESET);
        return false;
    }
    
    size_t finput_file_len = 0;
    char* finput_file = linker_read_file(input_files[0], &finput_file_len);

    if (finput_file == NULL || finput_file_len == 0) {
        perror("An Error Occured, Quitting...\n");
        return false;
    }

    size_t total_section_count = 0;
    size_t total_program_count = 0;

    Elf64_Ehdr* input_ehdr = (Elf64_Ehdr*)finput_file;
    if (memcmp(input_ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, COLOR_RED "Error: %s file has wrong ELF Magic\n" COLOR_CYAN "Tip: Even if the output format may be different, the encoders only output ELF64, the linker then produces the desired output format using that ELF format!\n" COLOR_RESET, input_files[0]);
        free(finput_file);
        return false;
    }

    FILE* out = fopen(outfile, "wb");
    if (out == NULL) {
        perror("Could not open Output file!\n");
        free(finput_file);
        return false;
    }

    size_t cvaddr = base_vaddr;

    Elf64_Ehdr ehdr = {0};
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_entry = input_ehdr->e_entry + cvaddr;
    ehdr.e_flags = 0;
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    ehdr.e_ident[EI_ABIVERSION] = 0;
    ehdr.e_machine = input_ehdr->e_machine;
    
    free(finput_file);

    for (size_t i = 0; i < input_file_count; i++) {
        size_t flen = 0;
        char* file = linker_read_file(input_files[i], &flen);
        if (file == NULL || flen == 0) {
            perror("An Error Occured, Quitting...\n");
            return false;
        }

        Elf64_Ehdr* input_ehdr = (Elf64_Ehdr*)finput_file;
        if (memcmp(input_ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
            fprintf(stderr, COLOR_RED "Error: %s file has wrong ELF Magic\n" COLOR_CYAN "Tip: Even if the output format may be different, the encoders only output ELF64, the linker then produces the desired output format using that ELF format!\n" COLOR_RESET, input_files[0]);
            free(finput_file);
            return false;
        }
    }

    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phoff = sizeof(Elf64_Ehdr) + (total_section_count * sizeof(Elf64_Shdr));
    ehdr.e_phnum = total_program_count;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = total_section_count;
    ehdr.e_shoff = sizeof(Elf64_Ehdr);
    ehdr.e_shstrndx = 1;
    ehdr.e_type = ET_EXEC;
    ehdr.e_version = EV_CURRENT;

    fseek(out, 0, SEEK_SET);
    fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, out);

    fclose(out);

    return true;
}

bool pac_link(char* outfile, char** input_files, size_t input_file_count, LinkerFormat outformat, size_t base_vaddr) {
    switch (outformat) {
        case ELF64:
            return pac_link_elf64(outfile, input_files, input_file_count, base_vaddr);
        default:
            printf(COLOR_RED "Error: Unknown/Unsupported Link Format: %s\n", linker_format_to_str(outformat));
            return false;
    }
}