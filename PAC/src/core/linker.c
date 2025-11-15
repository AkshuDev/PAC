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

typedef struct {
    char* name;
    Elf64_Shdr sh;
    uint8_t* data;

    size_t loaded_vaddr;
    size_t loaded_off;
} InSection;

typedef struct {
    uint8_t* buffer;
    size_t size;
    size_t capacity;
    size_t out_offset; // final offset in output ELF
    size_t out_vaddr; // final virtual addr
    size_t max_align;
    size_t padded_size;
    char* name;
    size_t sh_name_off;
    size_t sh_typ;
    size_t sh_flags;
} OutSection;

typedef struct {
    InSection* sections;
    size_t section_count;

    Elf64_Sym* symbols;
    size_t symbol_count;

    Elf64_Rela* relas;
    size_t rela_count;

    char* strtab;
    char* shstrtab;
    char* data;
} ObjectFile;

typedef struct {
    char** names;
    size_t count;
} SectionOrder;

static char* linker_read_file(const char* path, size_t* len) {
    FILE* f = fopen(path, "rb");
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

void free_objfile(ObjectFile* objfiles, size_t objfile_count) {
    if (objfile_count < 1) return;
    for (size_t i = 0; i < objfile_count; i++) {
        ObjectFile* objfile = &objfiles[i];
        free(objfile->data);

        if (objfile->section_count < 1) continue;
        free(objfile->sections);
    }
    free(objfiles);
}

static bool pac_link_elf64(char* outfile, char** input_files, size_t input_file_count, size_t base_vaddr) {
    if (input_files == NULL || input_file_count == 0) {
        fprintf(stderr, COLOR_RED "Linker Error: No input files provided!\n" COLOR_RESET);
        return false;
    }

    ObjectFile* objfiles = NULL;
    size_t objfile_count = 0;
    SectionOrder order = {0};

    size_t machine;
    
    // Read all files
    for (size_t i = 0; i< input_file_count; i++) {
        size_t flen = 0;
        char* fdata = linker_read_file(input_files[i], &flen);
        if (fdata == NULL) {
            perror("Linker Error: Unknown IO Error!\n");
            free_objfile(objfiles, objfile_count);
            return false;
        }

        // Read and fill ObjectFile structure
        Elf64_Ehdr* eh = (Elf64_Ehdr*)(fdata);

        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
            free_objfile(objfiles, objfile_count);
            fprintf(stderr, COLOR_RED "Linker Error: %s file has the wrong ELF Magic! This is not a valid Elf file!\n" COLOR_RESET, input_files[i]);
            return false;
        }

        if (i == 0) machine = eh->e_machine;
        if (eh->e_shnum == 0) continue;

        objfiles = realloc(objfiles, (objfile_count + 1) * sizeof(ObjectFile));
        if (!objfiles) {
            free_objfile(objfiles, objfile_count);
            perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);
            return false;
        }
        objfile_count++;
        ObjectFile* ofile = &objfiles[objfile_count - 1];
        
        memset(ofile, 0, sizeof(ObjectFile));
        ofile->data = fdata;

        ofile->section_count = eh->e_shnum;
        ofile->sections = calloc(ofile->section_count, sizeof(InSection));

        Elf64_Shdr* shstrtab_sec = (Elf64_Shdr*)(fdata + eh->e_shoff + (eh->e_shstrndx * sizeof(Elf64_Shdr)));
        char* shstrtab = fdata + shstrtab_sec->sh_offset;
        
        for (size_t j = 0; j < eh->e_shnum; j++) {
            // Resolve Sections
            Elf64_Shdr* sh = (Elf64_Shdr*)(fdata + eh->e_shoff + (j * sizeof(Elf64_Shdr)));
            char* name = (char*)(shstrtab + sh->sh_name);

            InSection* sec = &ofile->sections[j];
            sec->name = name;
            sec->sh = *sh;

            if (sh->sh_flags & SHF_ALLOC && i == 0) {
                // load the order of the first file
                order.names = realloc(order.names, sizeof(char*) * (order.count + 1));
                order.names[order.count] = strdup(name);
                order.count++;
            } else if (sh->sh_flags & SHF_ALLOC) {
                bool found = false;
                for (size_t k = 0; k < order.count; k++) {
                    if (strcmp(name, order.names[k]) == 0) { found = true; break; }
                }
                if (!found) {
                    order.names = realloc(order.names, sizeof(char*) * (order.count + 1));
                    order.names[order.count] = strdup(name);
                    order.count++;
                }
            }

            if (sh->sh_type != SHT_NOBITS && sh->sh_size > 0) sec->data = (uint8_t*)(fdata + sh->sh_offset);
            else sec->data = NULL;

            // Load symbol table
            if (sh->sh_type == SHT_SYMTAB) {
                ofile->symbols = (Elf64_Sym*)(fdata + sh->sh_offset);
                ofile->symbol_count = sh->sh_size / sh->sh_entsize;

                Elf64_Shdr* strsec = (Elf64_Shdr*)(fdata + eh->e_shoff + sh->sh_link * eh->e_shentsize);
                ofile->strtab = fdata + strsec->sh_offset;
            }

            if (sh->sh_type == SHT_RELA) {
                ofile->relas = (Elf64_Rela*)(fdata + sh->sh_offset);
                ofile->rela_count = sh->sh_size / sh->sh_entsize;
            }
        }
    }

    OutSection* outsecs = calloc(order.count, sizeof(OutSection));
    size_t section_count = order.count;
    size_t vaddr = base_vaddr;
    size_t file_off = sizeof(Elf64_Ehdr) + (order.count * sizeof(Elf64_Shdr));

    // Precompute all addresses
    for (size_t i = 0; i < order.count; i++) {
        const char* name = order.names[i];
        OutSection* osec = &outsecs[i];
        osec->name = (char*)name;

        // Compute total size
        for (size_t a = 0; a < objfile_count; a++) {
            for (size_t b = 0; b < objfiles[a].section_count; b++) {
                InSection* s = &objfiles[a].sections[b];
                if (strcmp(s->name, name) == 0) osec->size += s->sh.sh_size;
            }
        }

        if (osec->size == 0) continue;

        // allocate
        osec->buffer = malloc(osec->size);

        // merge
        size_t off = 0;
        for (size_t a = 0; a < objfile_count; a++) {
            for (size_t b = 0; b < objfiles[a].section_count; b++) {
                InSection* s = &objfiles[a].sections[b];
                if (strcmp(s->name, name) == 0) {
                    size_t align = s->sh.sh_addralign;
                    off = align_up(off, align);

                    if (s->data) memcpy(osec->buffer + off, s->data, s->sh.sh_size);
                    s->loaded_off = file_off + off;
                    s->loaded_vaddr = vaddr + off;
                    
                    off += s->sh.sh_size;

                    osec->max_align = max(osec->max_align, s->sh.sh_addralign);
                    osec->padded_size = off;
                    osec->sh_flags = s->sh.sh_flags;
                    osec->sh_typ = s->sh.sh_type;
                }
            }
        }

        // finalize output offsets
        osec->padded_size = align_up(osec->size, osec->max_align);
        file_off = align_up(file_off, osec->max_align);
        osec->out_offset = file_off;
        osec->out_vaddr = vaddr;
        file_off += osec->padded_size;

        vaddr = align_up(vaddr, osec->max_align);
        vaddr += off;
    }

    size_t shstrtab_size = 1;
    for (size_t i = 0; i < section_count; i++) {
        shstrtab_size += strlen(outsecs[i].name) + 1;
    }
    shstrtab_size += 10 + 8 + 8; // .shstrtab, .symtab, .strtab
    char* shstrtab = malloc(shstrtab_size);
    if (!shstrtab) {
        for (size_t i = 0; i < order.count; i++) free(outsecs[i].buffer);
        free(outsecs);
        for (size_t i = 0; i < order.count; i++) free(order.names[i]);
        free(order.names);

        free_objfile(objfiles, objfile_count);
        perror(COLOR_RED "Linker Error: Allocation Failed!\n" COLOR_RESET);
        return false;
    }
    shstrtab[0] = '\0';
    size_t shstrtab_off = 1;

    size_t strtab_size = 1; // first byte is null
    for (size_t i = 0; i < objfile_count; i++) {
        for (size_t j = 0; j < objfiles[i].symbol_count; j++) {
            const char* name = objfiles[i].strtab + objfiles[i].symbols[j].st_name;
            strtab_size += strlen(name) + 1;
        }
    }
    char* strtab = malloc(strtab_size);
    strtab[0] = '\0';
    size_t strtab_off = 1;

    for (size_t i = 0; i < section_count; i++) {
        strcpy(&shstrtab[shstrtab_off], outsecs[i].name);
        outsecs[i].sh_name_off = shstrtab_off;
        shstrtab_off += strlen(outsecs[i].name) + 1;
    }

    OutSection shstr_section = {0};
    shstr_section.name = ".shstrtab";
    shstr_section.buffer = (uint8_t*)shstrtab;
    shstr_section.size = shstrtab_size;
    shstr_section.padded_size = shstrtab_size;
    shstr_section.max_align = 1;
    shstr_section.out_offset = 0; // will compute later
    shstr_section.out_vaddr = 0; // not loaded in memory
    shstr_section.sh_name_off = shstrtab_off;
    shstr_section.sh_typ = SHT_STRTAB;
    strcpy(&shstrtab[shstrtab_off], ".shstrtab");
    shstrtab_off += 10;
    size_t shstr_index = section_count; // index in section header table

    size_t total_sections = section_count + 1;

    file_off = align_up(file_off, shstr_section.max_align);
    shstr_section.out_offset = file_off;
    file_off += shstr_section.padded_size;

    // Resolve symbols
    size_t total_symbols = 0;
    for (size_t i = 0; i < objfile_count; i++)
        total_symbols += objfiles[i].symbol_count;

    Elf64_Sym* outsyms = calloc(total_symbols, sizeof(Elf64_Sym));

    size_t sym_index = 0;
    for (size_t i = 0; i < objfile_count; i++) {
        ObjectFile* ofile = &objfiles[i];
        for (size_t j = 0; j < ofile->symbol_count; j++) {
            Elf64_Sym* insym = &ofile->symbols[j];
            Elf64_Sym* outsym = &outsyms[sym_index];

            // copy basic fields
            outsym->st_info = insym->st_info;
            outsym->st_other = insym->st_other;
            outsym->st_size = insym->st_size;

            // remap section index
            if (insym->st_shndx < SHN_LORESERVE) {
                // find the output section that matches input section
                InSection* sec = &ofile->sections[insym->st_shndx];
                for (size_t k = 0; k < section_count; k++) {
                    if (strcmp(sec->name, outsecs[k].name) == 0) {
                        outsym->st_shndx = k;
                        break;
                    }
                }
            } else {
                outsym->st_shndx = insym->st_shndx; // e.g., SHN_UNDEF
            }

            // remap symbol value
            if (outsym->st_shndx != SHN_UNDEF)
                outsym->st_value = ofile->sections[insym->st_shndx].loaded_vaddr + insym->st_value;
            else
                outsym->st_value = 0;

            // copy name to output strtab
            const char* name = ofile->strtab + insym->st_name;
            outsym->st_name = strtab_off;
            strcpy(&strtab[strtab_off], name);
            strtab_off += strlen(name) + 1;

            sym_index++;
        }
    }

    OutSection sym_section = {0};
    sym_section.name = ".symtab";
    sym_section.buffer = (uint8_t*)outsyms;
    sym_section.size = total_symbols * sizeof(Elf64_Sym);
    sym_section.padded_size = sym_section.size;
    sym_section.max_align = 8; // ELF64 alignment for symbols
    sym_section.sh_name_off = shstrtab_off;
    sym_section.sh_typ = SHT_SYMTAB;
    sym_section.capacity = total_symbols; // used as total count
    strcpy(&shstrtab[shstrtab_off], ".symtab");
    sym_section.out_vaddr = 0;
    shstrtab_off += 8;
    file_off = align_up(file_off, sym_section.max_align);
    sym_section.out_offset = file_off;
    file_off += sym_section.padded_size;
    size_t symtab_idx = shstr_index + 1;

    OutSection str_section = {0};
    str_section.name = ".strtab";
    str_section.buffer = (uint8_t*)strtab;
    str_section.size = strtab_size;
    str_section.padded_size = strtab_size;
    str_section.max_align = 1;
    str_section.sh_name_off = shstrtab_off;
    str_section.sh_typ = SHT_STRTAB;
    strcpy(&shstrtab[shstrtab_off], ".strtab");
    shstrtab_off += 8;
    str_section.out_vaddr = 0;
    file_off = align_up(file_off, str_section.max_align);
    str_section.out_offset = file_off;
    file_off += str_section.padded_size;
    size_t strtab_idx = symtab_idx + 1;

    total_sections += 2;

    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_type = ET_EXEC;
    eh.e_machine = (Elf64_Half)machine;
    eh.e_version = EV_CURRENT;
    eh.e_entry = base_vaddr; // entry point
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = total_sections;
    eh.e_shoff = sizeof(Elf64_Ehdr);
    eh.e_shstrndx = shstr_index;
    
    FILE* f = fopen(outfile, "wb");
    if (!f) {
        free(shstrtab);
        free(outsyms);
        free(strtab);

        for (size_t i = 0; i < order.count; i++) free(outsecs[i].buffer);
        free(outsecs);
        for (size_t i = 0; i < order.count; i++) free(order.names[i]);
        free(order.names);

        free_objfile(objfiles, objfile_count);

        perror(COLOR_RED "Linker Error: Failed to open output file!\n" COLOR_RESET);
        return false;
    }

    fwrite(&eh, sizeof(eh), 1, f);

    Elf64_Shdr* shdrs = calloc(total_sections, sizeof(Elf64_Shdr));
    if (!shdrs) {
        fclose(f);
        free(shstrtab);
        free(outsyms);
        free(strtab);

        for (size_t i = 0; i < order.count; i++) free(outsecs[i].buffer);
        free(outsecs);
        for (size_t i = 0; i < order.count; i++) free(order.names[i]);
        free(order.names);

        free_objfile(objfiles, objfile_count);

        perror(COLOR_RED "Linker Error: Allocation Failed!\n" COLOR_RESET);
        return false;
    }
    fwrite(shdrs, sizeof(Elf64_Shdr), total_sections, f);
    free(shdrs);

    for (size_t i = 0; i < section_count; i++) {
        fseek(f, outsecs[i].out_offset, SEEK_SET);
        if (outsecs[i].buffer && outsecs[i].size > 0) fwrite(outsecs[i].buffer, 1, outsecs[i].size, f);
        if (outsecs[i].padded_size > outsecs[i].size) {
            for (size_t j = 0; j < (outsecs[i].padded_size - outsecs[i].size); j++) {
                fwrite("\0", 1, 1, f);
            }
        }
    }

    fseek(f, shstr_section.out_offset, SEEK_SET);
    fwrite(shstr_section.buffer, 1, shstr_section.size, f);
    if (shstr_section.padded_size > shstr_section.size) {
        for (size_t i = 0; i < (shstr_section.padded_size - shstr_section.size); i++) {
            fwrite("\0", 1, 1, f);
        }
    }

    fseek(f, sym_section.out_offset, SEEK_SET);
    fwrite(sym_section.buffer, 1, sym_section.size, f);
    if (sym_section.padded_size > sym_section.size) {
        for (size_t i = 0; i < (sym_section.padded_size - sym_section.size); i++) {
            fwrite("\0", 1, 1, f);
        }
    }

    fseek(f, str_section.out_offset, SEEK_SET);
    fwrite(str_section.buffer, 1, str_section.size, f);
    if (str_section.padded_size > str_section.size) {
        for (size_t i = 0; i < (str_section.padded_size - str_section.size); i++) {
            fwrite("\0", 1, 1, f);
        }
    }

    shdrs = calloc(total_sections, sizeof(Elf64_Shdr));
    if (!shdrs) {
        fclose(f);
        free(shstrtab);
        free(outsyms);
        free(strtab);

        for (size_t i = 0; i < order.count; i++) free(outsecs[i].buffer);
        free(outsecs);
        for (size_t i = 0; i < order.count; i++) free(order.names[i]);
        free(order.names);

        free_objfile(objfiles, objfile_count);

        perror(COLOR_RED "Linker Error: Allocation Failed!\n" COLOR_RESET);
        return false;
    }

    for (size_t i = 0; i < section_count; i++) {
        shdrs[i].sh_name = outsecs[i].sh_name_off;
        shdrs[i].sh_type = outsecs[i].sh_typ;
        shdrs[i].sh_flags = outsecs[i].sh_flags;
        shdrs[i].sh_offset = outsecs[i].out_offset;
        shdrs[i].sh_addr = outsecs[i].out_vaddr;
        shdrs[i].sh_size = outsecs[i].padded_size;
        shdrs[i].sh_addralign = outsecs[i].max_align;
    }
    // .shstrtab header
    shdrs[shstr_index].sh_name = shstr_section.sh_name_off;
    shdrs[shstr_index].sh_type = shstr_section.sh_typ;
    shdrs[shstr_index].sh_flags = shstr_section.sh_flags;
    shdrs[shstr_index].sh_offset = shstr_section.out_offset;
    shdrs[shstr_index].sh_addr = shstr_section.out_vaddr;
    shdrs[shstr_index].sh_size = shstr_section.padded_size;
    shdrs[shstr_index].sh_addralign = shstr_section.max_align;

    // .symtab header
    shdrs[symtab_idx].sh_name = sym_section.sh_name_off;
    shdrs[symtab_idx].sh_type = sym_section.sh_typ;
    shdrs[symtab_idx].sh_flags = sym_section.sh_flags;
    shdrs[symtab_idx].sh_offset = sym_section.out_offset;
    shdrs[symtab_idx].sh_addr = sym_section.out_vaddr;
    shdrs[symtab_idx].sh_size = sym_section.padded_size;
    shdrs[symtab_idx].sh_addralign = sym_section.max_align;
    shdrs[symtab_idx].sh_link = strtab_idx;
    shdrs[symtab_idx].sh_info = sym_section.capacity;
    shdrs[symtab_idx].sh_entsize = sizeof(Elf64_Sym);

    // .strtab header
    shdrs[strtab_idx].sh_name = str_section.sh_name_off;
    shdrs[strtab_idx].sh_type = str_section.sh_typ;
    shdrs[strtab_idx].sh_flags = str_section.sh_flags;
    shdrs[strtab_idx].sh_offset = str_section.out_offset;
    shdrs[strtab_idx].sh_addr = str_section.out_vaddr;
    shdrs[strtab_idx].sh_size = str_section.padded_size;
    shdrs[strtab_idx].sh_addralign = str_section.max_align;

    fseek(f, sizeof(Elf64_Ehdr), SEEK_SET);
    fwrite(shdrs, sizeof(Elf64_Shdr), total_sections, f);

    fclose(f);

    free(shdrs);
    free(shstrtab);
    free(outsyms);
    free(strtab);

    for (size_t i = 0; i < order.count; i++) free(outsecs[i].buffer);
    free(outsecs);
    for (size_t i = 0; i < order.count; i++) free(order.names[i]);
    free(order.names);

    free_objfile(objfiles, objfile_count);

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