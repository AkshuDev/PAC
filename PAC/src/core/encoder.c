#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <elf.h>
#include <pac-extra.h>
#include <pac-asm.h>
#include <pac-pvcpu-encoder.h>
#include <pac-x86_64-encoder.h>
#include <pac-encoder.h>

bool encode(Assembler* ctx, const char* output_file, IRList* irlist, int bits, bool unlocked, enum Architecture arch) {
    FILE* out = fopen(output_file, "wb");
    if (!out) {
        printf(COLOR_RED "Error: Unable to open output file!\n" COLOR_RESET);
        return false;
    } 

    char archs[64];
    archenum_to_archs(arch, archs);

    int machine = 0;
    switch (arch) {
        case x86_64:
            machine = EM_X86_64;
            break;
        case x86:
            machine = EM_386;
            break;
        case PVCPU:
            machine = EM_PVCPU;
            break;
        default:
            fprintf(stderr, COLOR_RED "Error: Unknown/Unsupported Architecture: %s\n" COLOR_RESET, archs);
            fclose(out);

            if (remove(output_file) != 0) {
                fprintf(stderr, COLOR_RED "Error: Unable to delete output file!\n" COLOR_RESET);
            }

            return false;
    }

    // Header
    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB; // Little Endian
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    eh.e_ident[EI_ABIVERSION] = 0;
    eh.e_type = ET_REL;
    eh.e_machine = machine;
    eh.e_version = EV_CURRENT;
    eh.e_entry = (Elf64_Addr)(ctx->entry ? ctx->entry : 0);
    eh.e_phoff = 0; // no program header
    eh.e_shoff = 0;
    eh.e_flags = 0;
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = 0;
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = 0;
    eh.e_shstrndx = 0;

    size_t rsection_count = ctx->sections->count;
    size_t section_count = rsection_count + 5; // +3 for null section, .symtab, .strtab, .shstrtab, .reloc.text
    Elf64_Shdr* shdrs = calloc(section_count, sizeof(Elf64_Shdr));

    // Section string table
    char secname[64];
    char* shstrtab = calloc(section_count, sizeof(secname));
    size_t shstrtab_off = 0;
    size_t shstrtab_size = section_count * sizeof(secname);

    // Normal String table
    char symname[128];
    char* strtab = calloc(ctx->symbols->count + 1, sizeof(symname));
    size_t strtab_off = 0;
    size_t strtab_size = (ctx->symbols->count + 1) * sizeof(symname);
    
    size_t roffset = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Shdr) * section_count) + shstrtab_size + strtab_size + (sizeof(Elf64_Sym) * (ctx->symbols->count + 1)) + 64; // leave 64 bytes for safety
    size_t offset = roffset;
    size_t text_off = offset;
    Section* text_sec;
    size_t text_sec_idx = 0;

    // Null section
    shdrs[0].sh_type = SHT_NULL;

    memcpy(shstrtab + shstrtab_off, ".null", 6);
    shdrs[0].sh_name = shstrtab_off;
    shstrtab_off += 6;

    // Symbol Section
    shdrs[1].sh_type = SHT_SYMTAB;
    shdrs[1].sh_addralign = 8;
    shdrs[1].sh_entsize = sizeof(Elf64_Sym);
    shdrs[1].sh_size = (ctx->symbols->count + 1) * sizeof(Elf64_Sym);
    shdrs[1].sh_link = 2;
    shdrs[1].sh_info = ctx->symbols->count + 1;
    shdrs[1].sh_offset = sizeof(Elf64_Ehdr) + (section_count * sizeof(Elf64_Shdr)) + shstrtab_size + strtab_size;

    memcpy(shstrtab + shstrtab_off, ".symtab", 8);
    shdrs[1].sh_name = shstrtab_off;
    shstrtab_off += 8;

    shdrs[2].sh_type = SHT_STRTAB;
    shdrs[2].sh_addralign = 1;
    shdrs[2].sh_entsize = 0;
    shdrs[2].sh_size = strtab_size;
    shdrs[2].sh_offset = sizeof(Elf64_Ehdr) + (section_count * sizeof(Elf64_Shdr)) + shstrtab_size;
    
    memcpy(shstrtab + shstrtab_off, ".strtab", 8);
    shdrs[2].sh_name = shstrtab_off;
    shstrtab_off += 8;

    memcpy(shstrtab + shstrtab_off, ".shstrtab", 10);
    shdrs[3].sh_name = shstrtab_off;
    shstrtab_off += 10;
    
    shdrs[3].sh_type = SHT_STRTAB;
    shdrs[3].sh_offset = (Elf64_Xword)(sizeof(Elf64_Ehdr) + (section_count * sizeof(Elf64_Shdr)));
    shdrs[3].sh_size = (Elf64_Xword)shstrtab_size;
    shdrs[3].sh_addralign = 1;

    for (size_t i = 0; i < ctx->sections->count; i++) {
        Section* sec = &ctx->sections->sections[i];
        Elf64_Shdr* sh = &shdrs[i + 5];

        size_t len = strlen(sec->name) + 1;
        memcpy(shstrtab + shstrtab_off, sec->name, len);
        sh->sh_name = shstrtab_off;
        shstrtab_off += len;

        if (strcmp(sec->name, ".text") == 0) {
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            text_off = offset;
            text_sec = &ctx->sections->sections[i];
            text_sec_idx = i + 5;
        } else if (strcmp(sec->name, ".data") == 0) {
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC | SHF_WRITE;
        } else if (strcmp(sec->name, ".bss") == 0) {
            sh->sh_type = SHT_NOBITS;
            sh->sh_flags = SHF_ALLOC | SHF_WRITE;
            sh->sh_addr = (Elf64_Addr)sec->base;
            sh->sh_addralign = (Elf64_Xword)sec->alignment;
            continue;
        } else if (strcmp(sec->name, ".rodata") == 0) {
            sh->sh_type = SHT_PROGBITS;
            sh->sh_flags = SHF_ALLOC;
        } else {
            sh->sh_type = SHT_NULL;
            sh->sh_flags = 0;
        }

        sh->sh_addr = (Elf64_Addr)sec->base;
        sh->sh_offset = (Elf64_Xword)offset;
        sh->sh_size = (Elf64_Xword)sec->size;
        sh->sh_link = 0;
        sh->sh_info = 0;
        sh->sh_addralign = (Elf64_Xword)sec->alignment;
        sh->sh_entsize = 0;

        offset += sec->size;
    } 

    // Write data
    for (size_t i = 0; i < ctx->sections->count; i++) {
        Elf64_Shdr* sh = &shdrs[i + 5];

        Section sec = ctx->sections->sections[i];
        size_t written = 0;
        
        if (strcmp(sec.name, ".bss") == 0) {
            continue;
        }

        fseek(out, sh->sh_offset, SEEK_SET);

        for (size_t j = 0; j < ctx->symbols->count; j++) {
            Symbol sym = ctx->symbols->symbols[j];
            if (sym.section_index != i) continue;

            if (sym.type == SYM_IDENTIFIER) { // Only for identifier/allocated stuff
                int use = 0;
                long long intval = 0;
                double floatval = 0;
                if (sym.type_of_data >= T_BYTE && sym.type_of_data <= T_ULONG) {
                    intval = atoll(sym.value);
                    use = 0;
                } else if (sym.type_of_data >= T_FLOAT && sym.type_of_data <= T_DOUBLE) {
                    floatval = atof(sym.value);
                    use = 1;
                } else if (sym.type_of_data == T_ARRAY) {
                    use = 2; // NULL it
                    char* data = sym.value;
                    fwrite(data, 1, strlen(data), out);
                } else {
                    // PTR
                }

                if (use == 0) {
                    fwrite(&intval, sym.size, 1, out);
                } else if (use == 1) {
                    fwrite(&floatval, sym.size, 1, out);
                }
                written += sym.size;
            }
        }

        if (written > sec.size) {
            fprintf(stderr, COLOR_RED "Error: Somehow the contents of an section exceed the section's size!" COLOR_RESET);
            fclose(out);
            if (remove(output_file) != 0) {
                fprintf(stderr, COLOR_RED "Error: Unable to remove output file!\n" COLOR_RESET);
            }
            free(shstrtab);
            free(strtab);
            free(shdrs);
            return false;
        } else if (written < sec.size) {
            for (size_t i = 0; i < (sec.size - written); i++) {
                fwrite("\0", 1, 1, out);
            }
        }
    }

    bool ret = false;

    switch (arch) {
        case x86_64:
            ret = encode_x86_64(ctx, out, irlist, bits, unlocked, text_off, text_sec);
            break;
        case x86:
            ret = encode_x86_64(ctx, out, irlist, bits, unlocked, text_off, text_sec);
            break;
        case PVCPU:
            ret = encode_pvcpu(ctx, out, irlist, bits, unlocked, text_off, text_sec);
            break;
        default:
            break;
    }

    if (!ret) {
        fclose(out);
        if (remove(output_file) != 0) {
            fprintf(stderr, COLOR_RED "Error: Unable to remove output file!\n" COLOR_RESET);
        }
        free(shstrtab);
        free(strtab);
        free(shdrs);
        return false;
    }

    char padding[256];
    fwrite(padding, 1, 256, out);

    fseek(out, 0, SEEK_SET);
    eh.e_shoff = sizeof(Elf64_Ehdr);
    eh.e_shnum = section_count;
    eh.e_shstrndx = 3;

    memcpy(shstrtab + shstrtab_off, ".reloc.text", 12);
    shdrs[4].sh_name = shstrtab_off;
    shstrtab_off += 12;
    
    shdrs[4].sh_type = SHT_RELA;
    shdrs[4].sh_flags = SHF_INFO_LINK;
    shdrs[4].sh_link = 1;
    shdrs[4].sh_info = text_sec_idx;
    shdrs[4].sh_entsize = sizeof(Elf64_Rela);
    Section last_sec = ctx->sections->sections[ctx->sections->count - 1];
    shdrs[4].sh_offset = (Elf64_Xword)(roffset + last_sec.base + last_sec.size + 16); // +16 for safety
    shdrs[4].sh_size = (Elf64_Xword)(text_sec->reloc_count * sizeof(Elf64_Rela));
    shdrs[4].sh_addralign = 1;

    fwrite(&eh, sizeof(eh), 1, out);
    fwrite(shdrs, sizeof(Elf64_Shdr), section_count, out);

    Elf64_Sym* elfsymtab = calloc(ctx->symbols->count + 1, sizeof(Elf64_Sym)); // +1 for Null

    elfsymtab[0].st_name = 0;
    elfsymtab[0].st_info = ELF64_ST_INFO(STB_LOCAL, STT_NOTYPE);
    elfsymtab[0].st_shndx = SHN_UNDEF;
    strtab_off += 1;

    for (size_t i = 0; i < ctx->symbols->count; i++) {
        Symbol sym = ctx->symbols->symbols[i];
        Elf64_Sym* esym = &elfsymtab[i + 1];
        
        // Add name
        esym->st_shndx = sym.section_index + 5;
        if (sym.type == SYM_IDENTIFIER) esym->st_size = (Elf64_Xword)sym.size;
        else esym->st_size = 0;
        if (sym.type == SYM_LABEL) esym->st_info = ELF64_ST_INFO(sym.is_global == false ? STB_LOCAL : STB_GLOBAL, STT_FUNC);
        else if (sym.type == SYM_FILE) esym->st_info = ELF64_ST_INFO(sym.is_global == false ? STB_LOCAL : STB_GLOBAL, STT_FILE);
        else esym->st_info = ELF64_ST_INFO(sym.is_global == false ? STB_LOCAL : STB_GLOBAL, STT_OBJECT);
        esym->st_other = 0;
        esym->st_value = (Elf64_Addr)(sym.addr - ctx->sections->sections[sym.section_index].base);

        size_t len = strlen(sym.name) + 1;
        memcpy(strtab + strtab_off, sym.name, len);
        esym->st_name = strtab_off; 
        strtab_off += len;
    }

    fwrite(shstrtab, 1, shstrtab_size, out);
    fwrite(strtab, 1, strtab_size, out);
    fwrite(elfsymtab, sizeof(Elf64_Sym), ctx->symbols->count + 1, out);

    free(shstrtab);
    free(strtab);
    free(elfsymtab);

    fseek(out, shdrs[4].sh_offset, SEEK_SET);
    
    // add relocs of .text section
    for (size_t i = 0; i < text_sec->reloc_count; i++) {
        Relocation* reloc = &text_sec->relocs[i];
        Elf64_Rela r = {0};

        r.r_addend = reloc->addend;
        r.r_offset = reloc->offset;
        r.r_info = ELF64_R_INFO(reloc->symbol + 1, reloc->type);
        
        fwrite(&r, sizeof(r), 1, out);
    }

    fclose(out);
    free(shdrs);

    return true;
}
