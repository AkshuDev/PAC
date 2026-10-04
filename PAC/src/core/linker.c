#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>

#include <sys/stat.h>

#include <pac-linker.h>
#include <pac-asm.h>
#include <pac-extra.h>
#include <pac-pvcpu-encoder.h>

#define PAGE_SIZE 0x1000

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
	size_t memalign; // vaddr Memory Alignment
    size_t padded_size;
    char* name;

    size_t sh_name_off;
    size_t sh_type;
    size_t sh_flags;
	size_t sh_info;
} OutSection;

typedef struct {
	Elf64_Rela* rela;
	Elf64_Shdr* sec;
	InSection* isec;
	size_t rela_count;
} InRelocation;

typedef struct {
	SymbolVisibility vis;
	InSection* section;

	Elf64_Sym sym;
} ObjectSymbol;

typedef struct {
    InSection* sections;
    size_t section_count;

    ObjectSymbol* symbols;
    size_t symbol_count;
	size_t external_symbol_count;

	InRelocation relas[20];
    size_t rela_count;

    char* strtab;
    char* shstrtab;
    char* data;
	char* name;

	size_t data_len;
} ObjectFile;

typedef struct {
    char** names;
    size_t count;
} SectionOrder;

static char* linker_read_file(const char* path, size_t* len) {
	if (!path || !len) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, COLOR_RED "Linker Error: Cannot open file '%s'\n" COLOR_RESET, path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    char* buffer = malloc(size + 1);
	if (!buffer) {
		fclose(f);
		return NULL;
	}

    fread(buffer, 1, size, f);
    buffer[size] = '\0';
    fclose(f);
    *len = size;
    return buffer;
}

const char* linker_format_to_str(LinkerFormat outformat) {
    switch (outformat) {
        case ELF64: return "elf64";
        case ELF32: return "elf32";
        case WIN32: return "win32";
        case WIN64: return "win64";
        case BINARY: return "binary";
        default: return "Unknown";
    }
    return NULL;
}

LinkerFormat str_to_linker_format(char* s) {
    if (!s) return (LinkerFormat)-1;

    if (strcmp(s, "elf64") == 0) return ELF64;
    else if (strcmp(s, "elf32") == 0) return ELF32;
    else if (strcmp(s, "win64") == 0) return WIN64;
    else if (strcmp(s, "win32") == 0) return WIN32;
    else if (strcmp(s, "binary") == 0) return BINARY;

    return (LinkerFormat)-1;
}

static void free_objfile(ObjectFile* objfiles, size_t objfile_count) {
    if (objfile_count < 1 || !objfiles) return;

    for (size_t i = 0; i < objfile_count; i++) {
        ObjectFile* objfile = &objfiles[i];
        if (objfile->data) free(objfile->data);

        if (objfile->section_count < 1) continue;
        if (objfile->sections) free(objfile->sections);
		if (objfile->symbols) free(objfile->symbols);
    }
    free(objfiles);
}

static void resolve_relocs(InRelocation* irel, ObjectFile* ofile, size_t j) {
	if (!irel || !ofile) return;

	for (size_t k = 0; k < irel->rela_count; k++) {
		Elf64_Rela* reloc = &irel->rela[k];
		
		if (irel->sec->sh_info > ofile->section_count) {
			printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' needs relocation written to an unknown section, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
			continue;
		} 

		InSection* isec = &ofile->sections[irel->sec->sh_info];
		if (reloc->r_offset > isec->sh.sh_size) {
			printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside section, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
			continue;
		}

		size_t rsym = ELF64_R_SYM(reloc->r_info);
		size_t rtype = ELF64_R_TYPE(reloc->r_info);

		if (rsym + 1 > ofile->symbol_count) {
			printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' requires unknown symbol, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
			continue;
		}

		ObjectSymbol* osym = &ofile->symbols[rsym];
		Elf64_Sym* sym = &osym->sym;

		if (ELF64_ST_TYPE(sym->st_info) != STT_OBJECT && ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
			printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' uses symbol whose type is neither Func or Object, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
			continue;
		} else if (!osym->section) {
			printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' uses symbol which is placed in an unknown section, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
			continue;
		}

		InSection* sec = osym->section;
		int64_t addr = sym->st_value + sec->loaded_vaddr + reloc->r_addend;
		size_t off = reloc->r_offset + isec->sh.sh_offset;
		switch (rtype) {
			case R_PVCPU_8:
			case R_X86_64_8: {
				if (off + sizeof(uint8_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7F) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				*(uint8_t*)(&ofile->data[off]) = (uint8_t)addr;
				break;
			}
			case R_PVCPU_16:
			case R_X86_64_16: {
				if (off + sizeof(uint16_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7FFF) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				memcpy(&ofile->data[off], &addr, sizeof(uint16_t));
				break;
			}
			case R_PVCPU_32:
			case R_X86_64_32: {
				if (off + sizeof(uint32_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7FFFFFFF) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				memcpy(&ofile->data[off], &addr, sizeof(uint32_t));
				break;
			}
			case R_PVCPU_64:
			case R_X86_64_64: {
				if (off + sizeof(uint64_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7FFFFFFFFFFFFFFF) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				memcpy(&ofile->data[off], &addr, sizeof(uint64_t));
				break;
			}
			case R_PVCPU_PC_8:
			case R_X86_64_PC8: {
				addr = addr - (isec->loaded_vaddr + reloc->r_offset);
				if (off + sizeof(uint8_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7F) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				*(uint8_t*)(&ofile->data[off]) = (uint8_t)addr;
				break;
			}
			case R_PVCPU_PC_16:
			case R_X86_64_PC16: {
				addr = addr - (isec->loaded_vaddr + reloc->r_offset);
				if (off + sizeof(uint16_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7FFF) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				memcpy(&ofile->data[off], &addr, sizeof(uint16_t));
				break;
			}
			case R_PVCPU_PC_32:
			case R_X86_64_PC32: {
				addr = addr - (isec->loaded_vaddr + reloc->r_offset);
				if (off + sizeof(uint32_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7FFFFFFF) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				memcpy(&ofile->data[off], &addr, sizeof(uint32_t));
				break;
			}
			case R_PVCPU_PC_64:
			case R_X86_64_PC64: {
				addr = addr - (isec->loaded_vaddr + reloc->r_offset);
				if (off + sizeof(uint64_t) > ofile->data_len) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' is outside file, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				} else if (addr > 0x7FFFFFFFFFFFFFFF) {
					printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' cannot be fulfilled since ADDR cannot fit, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
					continue;
				}
				memcpy(&ofile->data[off], &addr, sizeof(uint64_t));
				break;
			}
			default: {
				printf(COLOR_YELLOW "Linker Warning: Relocation %llu within Reloc Section %llu file '%s' has invalid/unsupported type, skipping\n" COLOR_RESET, (unsigned long long)k, (unsigned long long)j, ofile->name);
				continue;
			}
		}
	}
}

static bool create_ofiles(char** input_files, size_t input_file_count, ObjectFile** objfiles, size_t* objfile_count, size_t* machine, SectionOrder* order) {
	if (!input_files || input_file_count < 1 || !objfiles || !objfile_count || !machine || !order) return false;

	// Read all files
    for (size_t i = 0; i < input_file_count; i++) {
        size_t flen = 0;
        char* fdata = linker_read_file(input_files[i], &flen);
        if (!fdata) {
            perror(COLOR_RED "Linker Error: Unknown IO Error!\n" COLOR_RESET);

			goto cleanup_n_fail;
            return false;
        }

        // Read and fill ObjectFile structure
        Elf64_Ehdr* eh = (Elf64_Ehdr*)(fdata);

        if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
			free(fdata);
            fprintf(stderr, COLOR_RED "Linker Error: %s file has the wrong ELF Magic! This is not a valid Elf file!\n" COLOR_RESET, input_files[i]);

			goto cleanup_n_fail;
            return false;
        }

        if (i == 0) *machine = eh->e_machine;
        if (eh->e_shnum == 0) continue;

        *objfiles = realloc(*objfiles, (*objfile_count + 1) * sizeof(ObjectFile));
        if (!*objfiles) {
			free(fdata);
            perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

			goto cleanup_n_fail;
            return false;
        }
        (*objfile_count)++;
        ObjectFile* ofile = &(*objfiles)[*objfile_count - 1];
        
        memset(ofile, 0, sizeof(ObjectFile));
		ofile->name = input_files[i];
        ofile->data = fdata;
		ofile->data_len = flen;

        ofile->section_count = eh->e_shnum;
        ofile->sections = ofile->section_count > 0 ? calloc(ofile->section_count, sizeof(InSection)) : NULL;
		if (!ofile->sections && ofile->section_count > 0) {
			free(fdata);
			perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

			goto cleanup_n_fail;
			return false;
		}

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
                char** nptr_order_names = realloc(order->names, sizeof(char*) * (order->count + 1));
				if (!nptr_order_names) {
					free(fdata);
					perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

					goto cleanup_n_fail;
					return false;
				}

				order->names = nptr_order_names;
                order->names[order->count] = strdup(name);
                order->count++;
            } else if (sh->sh_flags & SHF_ALLOC) {
                bool found = false;
                for (size_t k = 0; k < order->count; k++) {
                    if (strcmp(name, order->names[k]) == 0) { found = true; break; }
                }
                if (!found) {
                    char** nptr_order_names = realloc(order->names, sizeof(char*) * (order->count + 1));
					if (!nptr_order_names) {
						free(fdata);
						perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

						goto cleanup_n_fail;
						return false;
					}

					order->names = nptr_order_names;
					order->names[order->count] = strdup(name);
					order->count++;
                }
            }

            if (!(sh->sh_type & SHT_NOBITS) && sh->sh_size > 0) sec->data = (uint8_t*)(fdata + sh->sh_offset);
            else sec->data = NULL;

            // Load symbol table
            if (sh->sh_type == SHT_SYMTAB) {
                Elf64_Sym* symbols = (Elf64_Sym*)(fdata + sh->sh_offset);
                ofile->symbol_count = sh->sh_size / sh->sh_entsize;

				ofile->symbols = (ObjectSymbol*)calloc(ofile->symbol_count, sizeof(ObjectSymbol));
				if (!ofile->symbols) {
					free(fdata);
					perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

					goto cleanup_n_fail;
					return false;
				}

				for (size_t sidx = 0; sidx < ofile->symbol_count; sidx++) {
					ObjectSymbol* s = &ofile->symbols[sidx];
					s->sym = symbols[sidx];

					unsigned char bind = ELF64_ST_BIND(s->sym.st_info);
					s->vis = bind == STB_GLOBAL ? SYM_VIS_GLOBAL : SYM_VIS_LOCAL;
					if (s->sym.st_shndx == SHN_UNDEF && s->vis == SYM_VIS_GLOBAL) s->vis = SYM_VIS_EXTERNAL;
					if (s->vis == SYM_VIS_EXTERNAL) ofile->external_symbol_count++;

					s->section = &ofile->sections[s->sym.st_shndx >= ofile->section_count ? 0 : s->sym.st_shndx];
				}

                Elf64_Shdr* strsec = (Elf64_Shdr*)(fdata + eh->e_shoff + sh->sh_link * eh->e_shentsize);
                ofile->strtab = fdata + strsec->sh_offset;
            }

            if (sh->sh_type == SHT_RELA) {
				InRelocation* irel = &ofile->relas[ofile->rela_count++];
                irel->rela = (Elf64_Rela*)(fdata + sh->sh_offset);
				irel->rela_count = sh->sh_size / sh->sh_entsize;
				irel->sec = sh;
				irel->isec = sec;
            }
        }
    }

	return true;

	cleanup_n_fail: {
		free_objfile(*objfiles, *objfile_count);
		
		for (size_t i = 0; i < order->count; i++) {
			if (order->names[i]) free(order->names[i]);
		}
		if (order->names) free(order->names);
		order->names = NULL;
		order->count = 0;
		
		return false;
	}
}

static bool precompute_addresses(SectionOrder* order, OutSection* outsecs, ObjectFile* objfiles, size_t objfile_count, size_t* vaddr, size_t* file_off) {
	if (!order || !outsecs || !objfiles || objfile_count < 1 || !vaddr || !file_off) return false;

	for (size_t i = 0; i < order->count; i++) {
        const char* name = order->names[i];
        OutSection* osec = &outsecs[i];
        osec->name = (char*)name;

		bool alloc = true;

        // Compute total size and merge
		size_t off = 0;
        for (size_t a = 0; a < objfile_count; a++) {
            for (size_t b = 0; b < objfiles[a].section_count; b++) {
                InSection* s = &objfiles[a].sections[b];
                if (strcmp(s->name, name) == 0) {
					osec->size += s->sh.sh_size;
					if (s->sh.sh_type == SHT_NOBITS) alloc = false;

					osec->max_align = max(osec->max_align, s->sh.sh_addralign);
                    osec->padded_size = off;
                    osec->sh_flags = s->sh.sh_flags;
                    osec->sh_type = s->sh.sh_type;
					osec->memalign = osec->max_align;

                    s->loaded_off = align_up(*file_off, osec->memalign) + off;
                    s->loaded_vaddr = align_up(*vaddr, osec->memalign) + off;
                    
                    off += s->sh.sh_size;
				}
            }
        }

        if (osec->size == 0) continue;

        // allocate
        if (alloc) {
			osec->buffer = malloc(osec->size);
			if (!osec->buffer) {
				perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);
				goto cleanup_n_fail;
				return false;
			}
		} else osec->buffer = NULL;

        // finalize output offsets
		*vaddr = align_up(*vaddr, osec->memalign);
		*file_off = align_up(*file_off, osec->memalign);
		
        osec->padded_size = align_up(osec->size, osec->max_align);
        osec->out_offset = *file_off;
        osec->out_vaddr = *vaddr;
        *file_off += osec->padded_size;

        *vaddr += off;
    }

	return true;

	cleanup_n_fail: {
		for (size_t i = 0; i < order->count; i++) {
       		OutSection* osec = &outsecs[i];

			if (osec->buffer) free(osec->buffer);
			osec->buffer = NULL;
		}

		return false;
	}
}

static void fix_outsections_addresses_n_offsets(SectionOrder* order, OutSection* outsecs, ObjectFile* objfiles, size_t objfile_count, size_t* vaddr, size_t* file_off) {
	if (!order || !outsecs || !objfiles || objfile_count < 1 || !vaddr || !file_off) return;
	
	for (size_t i = 0; i < order->count; i++) {
        OutSection* osec = &outsecs[i];

        size_t off = 0;
        for (size_t a = 0; a < objfile_count; a++) {
            for (size_t b = 0; b < objfiles[a].section_count; b++) {
                InSection* s = &objfiles[a].sections[b];
                if (strcmp(s->name, osec->name) == 0) {
                    s->loaded_off = align_up(*file_off, osec->memalign) + off;
                    s->loaded_vaddr = align_up(*vaddr, osec->memalign) + off;
                    
                    off += s->sh.sh_size;
                }
            }
        }

        // finalize output offsets
		*vaddr = align_up(*vaddr, osec->memalign);
		*file_off = align_up(*file_off, osec->memalign);

        osec->out_offset = *file_off;
        osec->out_vaddr = *vaddr;
		
        *file_off += osec->padded_size;
        *vaddr += off;
    }
}

static void merge_outsections(SectionOrder* order, OutSection* outsecs, ObjectFile* objfiles, size_t objfile_count) {
	if (!order || !outsecs || !objfiles || objfile_count < 1) return;

	for (size_t i = 0; i < order->count; i++) {
        OutSection* osec = &outsecs[i];

		if (osec->sh_type == SHT_NOBITS || !osec->buffer) continue;

        size_t off = 0;
        for (size_t a = 0; a < objfile_count; a++) {
            for (size_t b = 0; b < objfiles[a].section_count; b++) {
                InSection* s = &objfiles[a].sections[b];
                if (strcmp(s->name, osec->name) == 0) {
                    if (s->data) memcpy(osec->buffer + off, s->data, s->sh.sh_size);
                    off += s->sh.sh_size;
                }
            }
        }
    }
}

static bool resolve_extern_symbols(ObjectFile* objfiles, size_t objfile_count) {
	if (!objfiles || objfile_count < 1) return false;

	for (size_t i = 0; i < objfile_count; i++) {
		ObjectFile* ofile = &objfiles[i];
		for (size_t j = 1; j < ofile->symbol_count; j++) { // First symbol is NULL
			ObjectSymbol* osym = &ofile->symbols[j];
			Elf64_Sym* sym = &osym->sym;
			const char* name = ofile->strtab + sym->st_name;

			if (osym->vis == SYM_VIS_EXTERNAL) {
				bool found = false;

				for (size_t k = 0; k < objfile_count; k++) {
					ObjectFile* ext_ofile = &objfiles[k];

					bool found_osym = false;
					for (size_t l = 0; l < ext_ofile->symbol_count; l++) {
						ObjectSymbol* ext_osym = &ext_ofile->symbols[l];
						Elf64_Sym* ext_sym = &ext_osym->sym;
						if (ext_sym->st_name > ext_ofile->data_len) continue;
						
						const char* ext_name = ext_sym->st_name + ext_ofile->strtab;
						if (strcmp(name, ext_name) == 0 && ext_osym->vis == SYM_VIS_GLOBAL) {
							sym->st_value = ext_sym->st_value;
							sym->st_size = ext_sym->st_size;
							sym->st_info = ext_sym->st_info;
							sym->st_other = ext_sym->st_other;
							
							osym->section = ext_osym->section;

							found = true;
							found_osym = true;
							break;
						}
					}

					if (found_osym) break;
				}

				if (!found) {
					fprintf(stderr, COLOR_RED "Linker Error: Symbol '%s' couldn't be resolved!" COLOR_RESET, name);
					return false;
				}
			}
		}
	}

	return true;
}

static bool pac_link_elf64(char* entry, char* outfile, char** input_files, size_t input_file_count, size_t base_vaddr) {
    if (!input_files || input_file_count == 0 || !outfile) {
        fprintf(stderr, COLOR_RED "Linker Error: No input/output files provided!\n" COLOR_RESET);
        return false;
    }

    ObjectFile* objfiles = NULL;
    size_t objfile_count = 0;
    SectionOrder order = {0};

    size_t machine;
    if (!create_ofiles(input_files, input_file_count, &objfiles, &objfile_count, &machine, &order)) return false;
    
    size_t total_sections = order.count + 4; // Sections + NULL, SHSTRTAB, SYMTAB, STRTAB

    OutSection* outsecs = calloc(order.count, sizeof(OutSection));
	if (!outsecs) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);

		free_objfile(objfiles, objfile_count);
	}

    size_t section_count = order.count;
    size_t vaddr = base_vaddr + PAGE_SIZE;
    size_t file_off = sizeof(Elf64_Ehdr) + (total_sections * sizeof(Elf64_Shdr));

    // Precompute all addresses
    if (!precompute_addresses(&order, outsecs, objfiles, objfile_count, &vaddr, &file_off)) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
	}

	// Resolve Symbols
	if (!resolve_extern_symbols(objfiles, objfile_count)) {
		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
	}

	// Precompute PHdrs Count and Recompute Memory Alignment
	size_t phdr_count = 1;
	Elf64_Phdr* program_headers = calloc(order.count+1, sizeof(Elf64_Phdr)); // +1 For headers
	if (!program_headers) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
	}

	bool page_align_next = true;
	for (size_t i = 0; i < order.count; i++) { // Broken PHdrs used only for the sole purpose of precomputation, its overwritten later with proper phdrs
		OutSection* osec = &outsecs[i];
		Elf64_Phdr ophdr_R = {0};
		Elf64_Phdr* ophdr = &ophdr_R;

		if (page_align_next) {
			osec->memalign = align_up(osec->max_align, PAGE_SIZE);
			page_align_next = false;
		}

		if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_EXECINSTR && osec->sh_type == SHT_PROGBITS) {
			// Force Current Page Alignment
			osec->memalign = align_up(osec->max_align, PAGE_SIZE);
			
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_X | PF_R;
			ophdr->p_align = PAGE_SIZE;

			page_align_next = true;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_type == SHT_NOBITS) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = 0;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = 0;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_WRITE) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else {
			continue;
		}

		bool merged = false;
		for (size_t j = 1; j < phdr_count; j++) {
			Elf64_Phdr* p = &program_headers[j];
			if (p->p_vaddr + p->p_memsz <= ophdr->p_vaddr && p->p_flags == ophdr->p_flags && p->p_type == ophdr->p_type) {
				if (p->p_filesz == 0 || ophdr->p_filesz == 0) {
					// .bss merged
					p->p_memsz += ophdr->p_memsz;
					p->p_align = max(p->p_align, ophdr->p_align);
					merged = true;
				} else if (p->p_filesz + p->p_offset == ophdr->p_offset) {
					p->p_align = max(p->p_align, ophdr->p_align);
					p->p_memsz += ophdr->p_memsz;
					p->p_filesz += ophdr->p_filesz;
					merged = true;
				}
			} 
		}
		if (!merged) program_headers[phdr_count++] = ophdr_R;
	}

	// Pass-2 to fix Section Offsets and Virtual Addresses
	file_off = sizeof(Elf64_Ehdr) + (total_sections * sizeof(Elf64_Shdr)) + (phdr_count * sizeof(Elf64_Phdr));
	vaddr = base_vaddr + PAGE_SIZE;
	fix_outsections_addresses_n_offsets(&order, outsecs, objfiles, objfile_count, &vaddr, &file_off);

	// Resolve Relocations
	for (size_t i = 0; i < objfile_count; i++) {
		ObjectFile* ofile = &objfiles[i];
		if (ofile->rela_count <= 0) continue;
		for (size_t j = 0; j < ofile->rela_count; j++) {
			InRelocation* irel = &ofile->relas[j];
			resolve_relocs(irel, ofile, j);
		}
	}

	// Merge
	merge_outsections(&order, outsecs, objfiles, objfile_count);

    size_t shstrtab_size = 1;
    for (size_t i = 0; i < section_count; i++) {
        shstrtab_size += strlen(outsecs[i].name) + 1;
    }
    shstrtab_size += 10 + 8 + 8; // .shstrtab, .symtab, .strtab
    char* shstrtab = malloc(shstrtab_size);
    if (!shstrtab) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		free(program_headers);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
    }
    size_t shstrtab_off = 1;

	for (size_t i = 0; i < section_count; i++) {
        strcpy(&shstrtab[shstrtab_off], outsecs[i].name);
        outsecs[i].sh_name_off = shstrtab_off;
        shstrtab_off += strlen(outsecs[i].name) + 1;
    }

    size_t strtab_size = 1; // first byte is null
	size_t local_syms = 0;
	size_t global_syms = 0;
    for (size_t i = 0; i < objfile_count; i++) {
        for (size_t j = 1; j < objfiles[i].symbol_count; j++) { // First symbol is NULL
			ObjectSymbol* osym = &objfiles[i].symbols[j];
			if (osym->vis == SYM_VIS_EXTERNAL) continue; // Repeated Symbol

            const char* name = objfiles[i].strtab + osym->sym.st_name;
            strtab_size += strlen(name) + 1;

			// Now also find out local and global symbols
			if (osym->vis == SYM_VIS_LOCAL) local_syms++;
			else global_syms++;
        }
    }
    
	char* strtab = malloc(strtab_size);
	if (!strtab) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		free(shstrtab);
		free(program_headers);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
	}
    size_t strtab_off = 1;

    OutSection shstr_section = {0};
	shstrtab[0] = '\0';
	shstrtab[shstrtab_size-1] = '\0';

    shstr_section.name = ".shstrtab";
    shstr_section.buffer = (uint8_t*)shstrtab;
    shstr_section.size = shstrtab_size;
    shstr_section.padded_size = shstrtab_size;
    shstr_section.max_align = 1;
    shstr_section.sh_name_off = shstrtab_off;
    shstr_section.sh_type = SHT_STRTAB;
    strcpy(&shstrtab[shstrtab_off], ".shstrtab");
    shstrtab_off += 10;
    size_t shstr_index = section_count+1; // index in section header table
    file_off = align_up(file_off, shstr_section.max_align);
    shstr_section.out_offset = file_off;
    file_off += shstr_section.padded_size;

    // Resolve symbols
    size_t total_symbols = 1 + local_syms + global_syms; // +1 for NULL
    Elf64_Sym* outsyms = calloc(total_symbols, sizeof(Elf64_Sym));
	if (!outsyms) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		free(strtab);
		free(shstrtab);
		free(program_headers);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
	}

    size_t lsym_index = 1;
	size_t gsym_index = 1 + local_syms;
	uint64_t entry_vaddr = 0;
	bool found_entry = false;
	
	if (entry == NULL) {
		entry = "_start";
		printf(COLOR_YELLOW "Linker Warning: No Entry Label Specified, Defaulting to '_start'\n" COLOR_RESET);
	}

    for (size_t i = 0; i < objfile_count; i++) {
        ObjectFile* ofile = &objfiles[i];
        for (size_t j = 1; j < ofile->symbol_count; j++) { // First symbol is NULL
			ObjectSymbol* osym = &ofile->symbols[j];
			if (osym->vis == SYM_VIS_EXTERNAL) continue; // Repeated Symbol

			size_t* sidx = osym->vis == SYM_VIS_LOCAL ? &lsym_index : &gsym_index;

            Elf64_Sym* insym = &osym->sym;
            Elf64_Sym* outsym = &outsyms[*sidx];

            // copy basic fields
            outsym->st_info = insym->st_info;
            outsym->st_other = insym->st_other;
            outsym->st_size = insym->st_size;

            // remap section index
            if (insym->st_shndx < SHN_LORESERVE) {
                // find the output section that matches input section
                InSection* sec = osym->section;
                for (size_t k = 0; k < section_count; k++) {
                    if (strcmp(sec->name, outsecs[k].name) == 0) {
                        outsym->st_shndx = k + 1;
                        break;
                    }
                }
            } else {
                outsym->st_shndx = insym->st_shndx; // e.g., SHN_UNDEF
            }

			const char* name = ofile->strtab + insym->st_name;

            // remap symbol value
            if (outsym->st_shndx != SHN_UNDEF)
                outsym->st_value = ofile->sections[insym->st_shndx].loaded_vaddr + insym->st_value;
            else
                outsym->st_value = 0;

            // copy name to output strtab
            outsym->st_name = strtab_off;
            strcpy(&strtab[strtab_off], name);
            strtab_off += strlen(name) + 1;

			if (insym->st_shndx < SHN_LORESERVE && strcmp(name, entry) == 0 && !found_entry) {
				entry_vaddr = ofile->sections[insym->st_shndx].loaded_vaddr + insym->st_value;
				found_entry = true;
			}

            (*sidx)++;
        }
    }

	if (!found_entry) {
		char* esname = NULL;
		for (size_t i = 0; i < order.count; i++) {
			OutSection* osec = &outsecs[i];
			if (osec->sh_type == SHT_PROGBITS) {
				entry_vaddr = osec->out_vaddr;
				esname = osec->name;
				break;
			}
		}

		if (esname)
			printf(COLOR_YELLOW "Linker Warning: Could not find any entry that matches '%s', using base virtual address of '%s' section\n" COLOR_RESET, entry, esname);
		else
			printf(COLOR_YELLOW "Linker Warning: Could not find any entry that matches '%s' or any PROGBITS section, using base virtual address of executable\n" COLOR_RESET, entry);
	}

    OutSection sym_section = {0};
    sym_section.name = ".symtab";sym_section.sh_info = local_syms + 1; // First global sym
	
    sym_section.buffer = (uint8_t*)outsyms;
    sym_section.size = total_symbols * sizeof(Elf64_Sym);
    sym_section.padded_size = sym_section.size;
    sym_section.max_align = 8; // ELF64 alignment for symbols
    sym_section.sh_name_off = shstrtab_off;
    sym_section.sh_type = SHT_SYMTAB;
    sym_section.capacity = total_symbols; // used as total count
    strcpy(&shstrtab[shstrtab_off], ".symtab");
    shstrtab_off += 8;
    file_off = align_up(file_off, sym_section.max_align);
    sym_section.out_offset = file_off;
    file_off += sym_section.padded_size;
    size_t symtab_idx = shstr_index + 1;

    OutSection str_section = {0};
	strtab[0] = '\0';
	strtab[strtab_size-1] = '\0';

    str_section.name = ".strtab";
    str_section.buffer = (uint8_t*)strtab;
    str_section.size = strtab_size;
    str_section.padded_size = strtab_size;
    str_section.max_align = 1;
    str_section.sh_name_off = shstrtab_off;
    str_section.sh_type = SHT_STRTAB;
    strcpy(&shstrtab[shstrtab_off], ".strtab");
    shstrtab_off += 8;
    file_off = align_up(file_off, str_section.max_align);
    str_section.out_offset = file_off;
    file_off += str_section.padded_size;
    size_t strtab_idx = symtab_idx + 1;

	// Program Headers
	phdr_count = 0;
	
	Elf64_Phdr* hdr_phdr = &program_headers[phdr_count++];
	hdr_phdr->p_type = PT_LOAD;
	hdr_phdr->p_offset = 0x0;
	hdr_phdr->p_vaddr = 0x400000;
	hdr_phdr->p_paddr = 0;
	hdr_phdr->p_flags = PF_R;
	hdr_phdr->p_align = PAGE_SIZE;

	for (size_t i = 0; i < order.count; i++) {
		OutSection* osec = &outsecs[i];
		Elf64_Phdr ophdr_R = {0};
		Elf64_Phdr* ophdr = &ophdr_R;

		if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_EXECINSTR && osec->sh_type == SHT_PROGBITS) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_X | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_type == SHT_NOBITS) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = 0;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = 0;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_WRITE) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else {
			continue;
		}

		bool merged = false;
		for (size_t j = 1; j < phdr_count; j++) {
			Elf64_Phdr* p = &program_headers[j];
			if (p->p_vaddr + p->p_memsz <= ophdr->p_vaddr && p->p_flags == ophdr->p_flags && p->p_type == ophdr->p_type) {
				if (p->p_filesz == 0 || ophdr->p_filesz == 0) {
					// .bss merged
					p->p_memsz += ophdr->p_memsz;
					p->p_align = max(p->p_align, ophdr->p_align);
					merged = true;
				} else if (p->p_filesz + p->p_offset == ophdr->p_offset) {
					p->p_align = max(p->p_align, ophdr->p_align);
					p->p_memsz += ophdr->p_memsz;
					p->p_filesz += ophdr->p_filesz;
					merged = true;
				}
			} 
		}
		
		if (!merged) program_headers[phdr_count++] = ophdr_R;
	}

	// EHdr
    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_type = ET_EXEC;
    eh.e_machine = (Elf64_Half)machine;
    eh.e_version = EV_CURRENT;
    eh.e_entry = entry_vaddr; // entry point
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_shentsize = sizeof(Elf64_Shdr);
    eh.e_shnum = total_sections;
    eh.e_shoff = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * phdr_count);
    eh.e_shstrndx = shstr_index;
	eh.e_phentsize = sizeof(Elf64_Phdr);
	eh.e_phnum = phdr_count;
	eh.e_phoff = sizeof(Elf64_Ehdr);

	hdr_phdr->p_filesz = sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * phdr_count);
	hdr_phdr->p_memsz = align_up(sizeof(Elf64_Ehdr) + (sizeof(Elf64_Phdr) * phdr_count), 0x10);
    
    FILE* f = fopen(outfile, "wb");
    if (!f) {
		perror(COLOR_RED "Linker Error: Failed to open output file!\n" COLOR_RESET);

		free(outsyms);
		free(strtab);
		free(shstrtab);
		free(program_headers);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
    }

    fwrite(&eh, sizeof(eh), 1, f);

	fwrite(program_headers, sizeof(Elf64_Phdr), phdr_count, f);
	free(program_headers);

    Elf64_Shdr* shdrs = calloc(total_sections, sizeof(Elf64_Shdr));
    if (!shdrs) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		fclose(f);

		free(outsyms);
		free(strtab);
		free(shstrtab);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
    }
	fwrite(shdrs, sizeof(Elf64_Shdr), total_sections, f);

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

    for (size_t i = 1; i < section_count+1; i++) {
        shdrs[i].sh_name = outsecs[i-1].sh_name_off;
        shdrs[i].sh_type = outsecs[i-1].sh_type;
        shdrs[i].sh_flags = outsecs[i-1].sh_flags;
        shdrs[i].sh_offset = outsecs[i-1].out_offset;
        shdrs[i].sh_addr = outsecs[i-1].out_vaddr;
        shdrs[i].sh_size = outsecs[i-1].padded_size;
        shdrs[i].sh_addralign = outsecs[i-1].max_align;
    }
	
    // .shstrtab header
    shdrs[shstr_index].sh_name = shstr_section.sh_name_off;
    shdrs[shstr_index].sh_type = shstr_section.sh_type;
    shdrs[shstr_index].sh_flags = shstr_section.sh_flags;
    shdrs[shstr_index].sh_offset = shstr_section.out_offset;
    shdrs[shstr_index].sh_addr = shstr_section.out_vaddr;
    shdrs[shstr_index].sh_size = shstr_section.padded_size;
    shdrs[shstr_index].sh_addralign = shstr_section.max_align;

    // .symtab header
    shdrs[symtab_idx].sh_name = sym_section.sh_name_off;
    shdrs[symtab_idx].sh_type = sym_section.sh_type;
    shdrs[symtab_idx].sh_flags = sym_section.sh_flags;
    shdrs[symtab_idx].sh_offset = sym_section.out_offset;
    shdrs[symtab_idx].sh_addr = sym_section.out_vaddr;
    shdrs[symtab_idx].sh_size = sym_section.padded_size;
    shdrs[symtab_idx].sh_addralign = sym_section.max_align;
    shdrs[symtab_idx].sh_link = strtab_idx;
    shdrs[symtab_idx].sh_info = sym_section.sh_info;
    shdrs[symtab_idx].sh_entsize = sizeof(Elf64_Sym);

    // .strtab header
    shdrs[strtab_idx].sh_name = str_section.sh_name_off;
    shdrs[strtab_idx].sh_type = str_section.sh_type;
    shdrs[strtab_idx].sh_flags = str_section.sh_flags;
    shdrs[strtab_idx].sh_offset = str_section.out_offset;
    shdrs[strtab_idx].sh_addr = str_section.out_vaddr;
    shdrs[strtab_idx].sh_size = str_section.padded_size;
    shdrs[strtab_idx].sh_addralign = str_section.max_align;

    fseek(f, eh.e_shoff, SEEK_SET);
    fwrite(shdrs, sizeof(Elf64_Shdr), total_sections, f);
	
	free(shdrs);
	fclose(f);

	free(outsyms);
	free(strtab);
	free(shstrtab);

	for (size_t i = 0; i < order.count; i++) {
		if (outsecs[i].name) free(outsecs[i].buffer);
		if (order.names[i]) free(order.names[i]);
	}
	free(order.names);
	free(outsecs);

	free_objfile(objfiles, objfile_count);
    return true;
}

static bool pac_link_elf32(char* entry, char* outfile, char** input_files, size_t input_file_count, size_t base_vaddr) {
    if (!input_files || input_file_count == 0 || !outfile) {
        fprintf(stderr, COLOR_RED "Linker Error: No input/output files provided!\n" COLOR_RESET);
        return false;
    }

    ObjectFile* objfiles = NULL;
    size_t objfile_count = 0;
    SectionOrder order = {0};

    size_t machine;
    if (!create_ofiles(input_files, input_file_count, &objfiles, &objfile_count, &machine, &order)) return false;
    
    size_t total_sections = order.count + 4; // Sections + NULL, SHSTRTAB, SYMTAB, STRTAB

    OutSection* outsecs = calloc(order.count, sizeof(OutSection));
	if (!outsecs) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		for (size_t i = 0; i < order.count; i++) {
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);

		free_objfile(objfiles, objfile_count);
	}

    size_t section_count = order.count;
    size_t vaddr = base_vaddr + PAGE_SIZE;
    size_t file_off = sizeof(Elf64_Ehdr) + (total_sections * sizeof(Elf64_Shdr));

    // Precompute all addresses
    if (!precompute_addresses(&order, outsecs, objfiles, objfile_count, &vaddr, &file_off)) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
	}

	// Resolve Symbols
	if (!resolve_extern_symbols(objfiles, objfile_count)) {
		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
	}

	// Precompute PHdrs Count and Recompute Memory Alignment
	size_t phdr_count = 1;
	Elf32_Phdr* program_headers = calloc(order.count+1, sizeof(Elf32_Phdr)); // +1 For headers
	if (!program_headers) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
	}

	bool page_align_next = true;
	for (size_t i = 0; i < order.count; i++) { // Broken PHdrs used only for the sole purpose of precomputation, its overwritten later with proper phdrs
		OutSection* osec = &outsecs[i];
		Elf32_Phdr ophdr_R = {0};
		Elf32_Phdr* ophdr = &ophdr_R;

		if (page_align_next) {
			osec->memalign = align_up(osec->max_align, PAGE_SIZE);
			page_align_next = false;
		}

		if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_EXECINSTR && osec->sh_type == SHT_PROGBITS) {
			// Force Current Page Alignment
			osec->memalign = align_up(osec->max_align, PAGE_SIZE);
			
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_X | PF_R;
			ophdr->p_align = PAGE_SIZE;

			page_align_next = true;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_type == SHT_NOBITS) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = 0;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = 0;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_WRITE) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else {
			continue;
		}

		bool merged = false;
		for (size_t j = 1; j < phdr_count; j++) {
			Elf32_Phdr* p = &program_headers[j];
			if (p->p_vaddr + p->p_memsz <= ophdr->p_vaddr && p->p_flags == ophdr->p_flags && p->p_type == ophdr->p_type) {
				if (p->p_filesz == 0 || ophdr->p_filesz == 0) {
					// .bss merged
					p->p_memsz += ophdr->p_memsz;
					p->p_align = max(p->p_align, ophdr->p_align);
					merged = true;
				} else if (p->p_filesz + p->p_offset == ophdr->p_offset) {
					p->p_align = max(p->p_align, ophdr->p_align);
					p->p_memsz += ophdr->p_memsz;
					p->p_filesz += ophdr->p_filesz;
					merged = true;
				}
			} 
		}
		if (!merged)
			program_headers[phdr_count++] = ophdr_R;
	}

	// Pass-2 to fix Section Offsets and Virtual Addresses
	file_off = sizeof(Elf32_Ehdr) + (total_sections * sizeof(Elf32_Shdr)) + (phdr_count * sizeof(Elf32_Phdr));
	vaddr = base_vaddr + PAGE_SIZE;
	fix_outsections_addresses_n_offsets(&order, outsecs, objfiles, objfile_count, &vaddr, &file_off);

	// Resolve Relocations
	for (size_t i = 0; i < objfile_count; i++) {
		ObjectFile* ofile = &objfiles[i];
		if (ofile->rela_count <= 0) continue;
		for (size_t j = 0; j < ofile->rela_count; j++) {
			InRelocation* irel = &ofile->relas[j];
			resolve_relocs(irel, ofile, j);
		}
	}

	// Merge
	merge_outsections(&order, outsecs, objfiles, objfile_count);

    size_t shstrtab_size = 1;
    for (size_t i = 0; i < section_count; i++) {
        shstrtab_size += strlen(outsecs[i].name) + 1;
    }
    shstrtab_size += 10 + 8 + 8; // .shstrtab, .symtab, .strtab
    
	char* shstrtab = malloc(shstrtab_size);
    if (!shstrtab) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		free(program_headers);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
		return false;
    }
    shstrtab[0] = '\0';
    size_t shstrtab_off = 1;

	for (size_t i = 0; i < section_count; i++) {
        strcpy(&shstrtab[shstrtab_off], outsecs[i].name);
        outsecs[i].sh_name_off = shstrtab_off;
        shstrtab_off += strlen(outsecs[i].name) + 1;
    }

    size_t strtab_size = 1; // first byte is null
	size_t local_syms = 0;
	size_t global_syms = 0;
    for (size_t i = 0; i < objfile_count; i++) {
        for (size_t j = 1; j < objfiles[i].symbol_count; j++) { // First symbol is NULL
			ObjectSymbol* osym = &objfiles[i].symbols[j];
			if (osym->vis == SYM_VIS_EXTERNAL) continue; // Repeated Symbol

            const char* name = objfiles[i].strtab + osym->sym.st_name;
            strtab_size += strlen(name) + 1;

			// Now also find out local and global symbols
			if (osym->vis == SYM_VIS_LOCAL) local_syms++;
			else global_syms++;
        }
    }

    char* strtab = malloc(strtab_size);
	if (!strtab) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		free(shstrtab);
		free(program_headers);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
		return false;
	}
    size_t strtab_off = 1;

    OutSection shstr_section = {0};
	shstrtab[0] = '\0';
	shstrtab[shstrtab_size-1] = '\0';

    shstr_section.name = ".shstrtab";
    shstr_section.buffer = (uint8_t*)shstrtab;
    shstr_section.size = shstrtab_size;
    shstr_section.padded_size = shstrtab_size;
    shstr_section.max_align = 1;
    shstr_section.sh_name_off = shstrtab_off;
    shstr_section.sh_type = SHT_STRTAB;
    strcpy(&shstrtab[shstrtab_off], ".shstrtab");
    shstrtab_off += 10;
    size_t shstr_index = section_count+1; // index in section header table

    file_off = align_up(file_off, shstr_section.max_align);
    shstr_section.out_offset = file_off;
    file_off += shstr_section.padded_size;

    // Resolve symbols
    size_t total_symbols = 1 + local_syms + global_syms; // +1 for NULL
    
    Elf32_Sym* outsyms = calloc(total_symbols, sizeof(Elf32_Sym));
	if (!outsyms) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		free(strtab);
		free(shstrtab);
		free(program_headers);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
		return false;
	}

    size_t lsym_index = 1;
	size_t gsym_index = 1 + local_syms;
	uint64_t entry_vaddr = 0;
	bool found_entry = false;
	if (entry == NULL) {
		entry = "_start";
		printf(COLOR_YELLOW "Linker Warning: No Entry Label Specified, Defaulting to '_start'\n" COLOR_RESET);
	}
    
	for (size_t i = 0; i < objfile_count; i++) {
        ObjectFile* ofile = &objfiles[i];
        for (size_t j = 1; j < ofile->symbol_count; j++) { // First symbol is NULL
			ObjectSymbol* osym = &ofile->symbols[j];
			if (osym->vis == SYM_VIS_EXTERNAL) continue; // Repeated Symbol

			size_t* sidx = osym->vis == SYM_VIS_LOCAL ? &lsym_index : &gsym_index;

            Elf64_Sym* insym = &osym->sym;
            Elf32_Sym* outsym = &outsyms[*sidx];

            // copy basic fields
            outsym->st_info = insym->st_info;
            outsym->st_other = insym->st_other;
            outsym->st_size = insym->st_size;

            // remap section index
            if (insym->st_shndx < SHN_LORESERVE) {
                // find the output section that matches input section
                InSection* sec = osym->section;
                for (size_t k = 0; k < section_count; k++) {
                    if (strcmp(sec->name, outsecs[k].name) == 0) {
                        outsym->st_shndx = k + 1;
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

			if (insym->st_shndx < SHN_LORESERVE && strcmp(name, entry) == 0 && !found_entry) {
				entry_vaddr = ofile->sections[insym->st_shndx].loaded_vaddr + insym->st_value;
				found_entry = true;
			}

            (*sidx)++;
        }
    }

	if (!found_entry) {
		char* esname = NULL;
		for (size_t i = 0; i < order.count; i++) {
			OutSection* osec = &outsecs[i];
			if (osec->sh_type == SHT_PROGBITS) {
				entry_vaddr = osec->out_vaddr;
				esname = osec->name;
				break;
			}
		}
		if (esname)
			printf(COLOR_YELLOW "Linker Warning: Could not find any entry that matches '%s', using base virtual address of '%s' section\n" COLOR_RESET, entry, esname);
		else
			printf(COLOR_YELLOW "Linker Warning: Could not find any entry that matches '%s' or any PROGBITS section, using base virtual address of executable\n" COLOR_RESET, entry);
	}

    OutSection sym_section = {0};
    sym_section.name = ".symtab";
	sym_section.sh_info = local_syms + 1; // First global sym
    sym_section.buffer = (uint8_t*)outsyms;
    sym_section.size = total_symbols * sizeof(Elf32_Sym);
    sym_section.padded_size = sym_section.size;
    sym_section.max_align = 8; // ELF32 alignment for symbols
    sym_section.sh_name_off = shstrtab_off;
    sym_section.sh_type = SHT_SYMTAB;
    sym_section.capacity = total_symbols; // used as total count
    strcpy(&shstrtab[shstrtab_off], ".symtab");
    shstrtab_off += 8;
    file_off = align_up(file_off, sym_section.max_align);
    sym_section.out_offset = file_off;
    file_off += sym_section.padded_size;
    size_t symtab_idx = shstr_index + 1;

    OutSection str_section = {0};
	strtab[0] = '\0';
	strtab[strtab_size-1] = '\0';

    str_section.name = ".strtab";
    str_section.buffer = (uint8_t*)strtab;
    str_section.size = strtab_size;
    str_section.padded_size = strtab_size;
    str_section.max_align = 1;
    str_section.sh_name_off = shstrtab_off;
    str_section.sh_type = SHT_STRTAB;
    strcpy(&shstrtab[shstrtab_off], ".strtab");
    shstrtab_off += 8;
    file_off = align_up(file_off, str_section.max_align);
    str_section.out_offset = file_off;
    file_off += str_section.padded_size;
    size_t strtab_idx = symtab_idx + 1;

	// Program Headers
	phdr_count = 0;
	
	Elf32_Phdr* hdr_phdr = &program_headers[phdr_count++];
	hdr_phdr->p_type = PT_LOAD;
	hdr_phdr->p_offset = 0x0;
	hdr_phdr->p_vaddr = 0x400000;
	hdr_phdr->p_paddr = 0;
	hdr_phdr->p_flags = PF_R;
	hdr_phdr->p_align = PAGE_SIZE;

	for (size_t i = 0; i < order.count; i++) {
		OutSection* osec = &outsecs[i];
		Elf32_Phdr ophdr_R = {0};
		Elf32_Phdr* ophdr = &ophdr_R;

		if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_EXECINSTR && osec->sh_type == SHT_PROGBITS) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_X | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_type == SHT_NOBITS) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = 0;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = 0;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC && osec->sh_flags & SHF_WRITE) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_W | PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else if (osec->sh_flags & SHF_ALLOC) {
			ophdr->p_type = PT_LOAD;
			ophdr->p_offset = osec->out_offset;
			ophdr->p_vaddr = osec->out_vaddr;
			ophdr->p_paddr = 0;
			ophdr->p_filesz = osec->size;
			ophdr->p_memsz = osec->padded_size;
			ophdr->p_flags = PF_R;
			ophdr->p_align = PAGE_SIZE;
		} else {
			continue;
		}

		bool merged = false;
		for (size_t j = 1; j < phdr_count; j++) {
			Elf32_Phdr* p = &program_headers[j];
			if (p->p_vaddr + p->p_memsz <= ophdr->p_vaddr && p->p_flags == ophdr->p_flags && p->p_type == ophdr->p_type) {
				if (p->p_filesz == 0 || ophdr->p_filesz == 0) {
					// .bss merged
					p->p_memsz += ophdr->p_memsz;
					p->p_align = max(p->p_align, ophdr->p_align);
					merged = true;
				} else if (p->p_filesz + p->p_offset == ophdr->p_offset) {
					p->p_align = max(p->p_align, ophdr->p_align);
					p->p_memsz += ophdr->p_memsz;
					p->p_filesz += ophdr->p_filesz;
					merged = true;
				}
			} 
		}
		
		if (!merged) program_headers[phdr_count++] = ophdr_R;
	}

	// EHdr
    Elf32_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS32;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_type = ET_EXEC;
    eh.e_machine = (Elf32_Half)machine;
    eh.e_version = EV_CURRENT;
    eh.e_entry = entry_vaddr; // entry point
    eh.e_ehsize = sizeof(Elf32_Ehdr);
    eh.e_shentsize = sizeof(Elf32_Shdr);
    eh.e_shnum = total_sections;
    eh.e_shoff = sizeof(Elf32_Ehdr) + (sizeof(Elf32_Phdr) * phdr_count);
    eh.e_shstrndx = shstr_index;
	eh.e_phentsize = sizeof(Elf32_Phdr);
	eh.e_phnum = phdr_count;
	eh.e_phoff = sizeof(Elf32_Ehdr);

	hdr_phdr->p_filesz = sizeof(Elf32_Ehdr) + (sizeof(Elf32_Phdr) * phdr_count);
	hdr_phdr->p_memsz = align_up(sizeof(Elf32_Ehdr) + (sizeof(Elf32_Phdr) * phdr_count), 0x10);
    
    FILE* f = fopen(outfile, "wb");
    if (!f) {
		perror(COLOR_RED "Linker Error: Failed to open output file!\n" COLOR_RESET);

		free(outsyms);
		free(strtab);
		free(shstrtab);
		free(program_headers);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
		return false;
    }

    fwrite(&eh, sizeof(eh), 1, f);

	fwrite(program_headers, sizeof(Elf32_Phdr), phdr_count, f);
	free(program_headers);

    Elf32_Shdr* shdrs = calloc(total_sections, sizeof(Elf32_Shdr));
    if (!shdrs) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		fclose(f);

		free(outsyms);
		free(strtab);
		free(shstrtab);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
		return false;
    }
	fwrite(shdrs, sizeof(Elf32_Shdr), total_sections, f);

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

    for (size_t i = 1; i < section_count+1; i++) {
        shdrs[i].sh_name = outsecs[i-1].sh_name_off;
        shdrs[i].sh_type = outsecs[i-1].sh_type;
        shdrs[i].sh_flags = outsecs[i-1].sh_flags;
        shdrs[i].sh_offset = outsecs[i-1].out_offset;
        shdrs[i].sh_addr = outsecs[i-1].out_vaddr;
        shdrs[i].sh_size = outsecs[i-1].padded_size;
        shdrs[i].sh_addralign = outsecs[i-1].max_align;
    }
	
    // .shstrtab header
    shdrs[shstr_index].sh_name = shstr_section.sh_name_off;
    shdrs[shstr_index].sh_type = shstr_section.sh_type;
    shdrs[shstr_index].sh_flags = shstr_section.sh_flags;
    shdrs[shstr_index].sh_offset = shstr_section.out_offset;
    shdrs[shstr_index].sh_addr = shstr_section.out_vaddr;
    shdrs[shstr_index].sh_size = shstr_section.padded_size;
    shdrs[shstr_index].sh_addralign = shstr_section.max_align;

    // .symtab header
    shdrs[symtab_idx].sh_name = sym_section.sh_name_off;
    shdrs[symtab_idx].sh_type = sym_section.sh_type;
    shdrs[symtab_idx].sh_flags = sym_section.sh_flags;
    shdrs[symtab_idx].sh_offset = sym_section.out_offset;
    shdrs[symtab_idx].sh_addr = sym_section.out_vaddr;
    shdrs[symtab_idx].sh_size = sym_section.padded_size;
    shdrs[symtab_idx].sh_addralign = sym_section.max_align;
    shdrs[symtab_idx].sh_link = strtab_idx;
    shdrs[symtab_idx].sh_info = sym_section.sh_info;
    shdrs[symtab_idx].sh_entsize = sizeof(Elf32_Sym);

    // .strtab header
    shdrs[strtab_idx].sh_name = str_section.sh_name_off;
    shdrs[strtab_idx].sh_type = str_section.sh_type;
    shdrs[strtab_idx].sh_flags = str_section.sh_flags;
    shdrs[strtab_idx].sh_offset = str_section.out_offset;
    shdrs[strtab_idx].sh_addr = str_section.out_vaddr;
    shdrs[strtab_idx].sh_size = str_section.padded_size;
    shdrs[strtab_idx].sh_addralign = str_section.max_align;

    fseek(f, eh.e_shoff, SEEK_SET);
    fwrite(shdrs, sizeof(Elf32_Shdr), total_sections, f);

	free(shdrs);
    fclose(f);
	free(outsyms);
	free(strtab);
	free(shstrtab);

	for (size_t i = 0; i < order.count; i++) {
		if (outsecs[i].name) free(outsecs[i].buffer);
		if (order.names[i]) free(order.names[i]);
	}
	free(order.names);
	free(outsecs);

	free_objfile(objfiles, objfile_count);
    return true;
}

static bool pac_link_binary(char* entry, char* outfile, char** input_files, size_t input_file_count, size_t base_vaddr) {
	if (!input_files || input_file_count == 0 || !outfile) {
        fprintf(stderr, COLOR_RED "Linker Error: No input/output files provided!\n" COLOR_RESET);
        return false;
    }
	if (base_vaddr != 0) {
		fprintf(stderr, COLOR_YELLOW "Linker Warning: Using base virtual address as '0' and not '0x%llX' [Reason: Using binary format]\n" COLOR_RESET, (unsigned long long)base_vaddr);
		base_vaddr = 0;
	}
	if (entry) {
		fprintf(stderr, COLOR_YELLOW "Linker Warning: Using first byte as entry and not '%s' [Reason: Using binary format]\n" COLOR_RESET, entry);
	}
	fprintf(stderr, COLOR_YELLOW "Linker Warning: Binary output is a very raw format. Section order directly affects the output layout, and executable machine code may appear at an unexpected offset. Using binary format without understanding the section layout can produce invalid or unsafe output\n" COLOR_RESET);

	ObjectFile* objfiles = NULL;
    size_t objfile_count = 0;
    SectionOrder order = {0};

    size_t machine;
    if (!create_ofiles(input_files, input_file_count, &objfiles, &objfile_count, &machine, &order)) return false;

    OutSection* outsecs = calloc(order.count, sizeof(OutSection));
	if (!outsecs) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);

		free_objfile(objfiles, objfile_count);
	}

    size_t section_count = order.count;
    size_t vaddr = base_vaddr;
    size_t file_off = 0;

    // Precompute all addresses
    if (!precompute_addresses(&order, outsecs, objfiles, objfile_count, &vaddr, &file_off)) {
		perror(COLOR_RED "Linker Error: Memory Allocation Failed!\n" COLOR_RESET);

        for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

        free_objfile(objfiles, objfile_count);
        return false;
	}

	// Resolve Relocations
	for (size_t i = 0; i < objfile_count; i++) {
		ObjectFile* ofile = &objfiles[i];
		if (ofile->rela_count <= 0) continue;
		for (size_t j = 0; j < ofile->rela_count; j++) {
			InRelocation* irel = &ofile->relas[j];
			resolve_relocs(irel, ofile, j);
		}
	}

	// Merge
	merge_outsections(&order, outsecs, objfiles, objfile_count);

	FILE* f = fopen(outfile, "wb");
	if (!f) {
		perror(COLOR_RED "Linker Error: Failed to open output file!\n" COLOR_RESET);

		for (size_t i = 0; i < order.count; i++) {
			if (outsecs[i].name) free(outsecs[i].buffer);
			if (order.names[i]) free(order.names[i]);
		}
        free(order.names);
		free(outsecs);

		free_objfile(objfiles, objfile_count);
		return false;
	}

	// Output
	for (size_t i = 0; i < section_count; i++) {
        fseek(f, outsecs[i].out_offset, SEEK_SET);
        if (outsecs[i].buffer && outsecs[i].size > 0) fwrite(outsecs[i].buffer, 1, outsecs[i].size, f);
        if (outsecs[i].padded_size > outsecs[i].size) {
            for (size_t j = 0; j < (outsecs[i].padded_size - outsecs[i].size); j++) {
                fwrite("\0", 1, 1, f);
            }
        }
    }

	fclose(f);
	for (size_t i = 0; i < order.count; i++) {
		if (outsecs[i].name) free(outsecs[i].buffer);
		if (order.names[i]) free(order.names[i]);
	}
	free(order.names);
	free(outsecs);

	free_objfile(objfiles, objfile_count);
	return false;
}

bool pac_link(char* entry, char* outfile, char** input_files, size_t input_file_count, LinkerFormat outformat, size_t base_vaddr) {
	if (!input_files || input_file_count == 0 || !outfile) {
        fprintf(stderr, COLOR_RED "Linker Error: No input files provided!\n" COLOR_RESET);
        return false;
    }

	bool out = false;
    switch (outformat) {
        case ELF64:
            out = pac_link_elf64(entry, outfile, input_files, input_file_count, base_vaddr);
			break;
		case ELF32:
            out = pac_link_elf32(entry, outfile, input_files, input_file_count, base_vaddr);
			break;
		case BINARY:
			return pac_link_binary(entry, outfile, input_files, input_file_count, base_vaddr); // DO NOT MAKE BINARY EXECUTABLE
        default:
            printf(COLOR_RED "Linker Error: Unknown/Unsupported Link Format: %s\n", linker_format_to_str(outformat));
            return false;
    }
	if (!out) return false;

	if (chmod(outfile, S_IRUSR | S_IXUSR | S_IWUSR) != 0) {
		perror(COLOR_YELLOW "Linker Warning: Failed to add EXECUTABLE permission to output binary, skipping EXECUTABLE permission\n" COLOR_RESET);
	}
	return true;
}
