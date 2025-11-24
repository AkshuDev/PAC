#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include <pac.h>

#include <pac-err.h>
#include <pac-extra.h>

#include <pac-lexer.h>
#include <pac-parser.h>
#include <pac-asm.h>
#include <pac-linker.h>

// Encoders
#include <pac-x86_64-encoder.h> // includes x86 also
#include <pac-pvpcu-encoder.h>

typedef struct {
    char* output_file;
    char** input_files;
    int input_count;
    bool verbose;
    bool debug_symbols;
    enum Architecture arch;
    int bits;
    bool lexout;
    bool parseout;
    bool asmout;
    bool savetemps;
    bool only_asm;
    size_t base;
    char* entry_label;
    LinkerFormat linkformat;
} Args;

void print_usage(const char* prog) {
    printf("Usage: %s -o <output_file> [--verbose] <input_files...>\n", prog);
    printf("Options:\n");
    printf("\t-o, --output <file>       Set output file (required)\n");
    printf("\t-v, --verbose             Enable verbose output\n");
    printf("\t-h, --help                Show this help message\n");
    printf("\t-d, --debug               Include debug symbols\n");
    printf("\t--version                 Display Version information and quit\n");
    printf("\t--lexout                  Stop after lexing and print tokens\n");
    printf("\t--parseout                Stop after parsing and print AST Nodes\n");
    printf("\t--asmout                  Stop after assembling and print IR Instructions\n");
    printf("\t--savetemp                Pause after core stages such as Assembling and save contents into a file in current dir named asave.<extension>\n");
    printf("\t--only-asm                Stop after encoding and do not link\n");
    printf("\t-a, --arch <architecture> Target architecture (default: x86_64)\n");
    printf("\t-b, --bits <16|32|64>     Target bits (default: 64)\n");
    printf("\t-t, --base                Base Virtual Address (default: 0x400000 (linux) and 0x140000000 (windows))\n");
    printf("\t-e, --entry               Provide Entry Label/Function (default: The first Label/Function)\n");
    printf("\t-f, --format <elf64/elf32/win64/win32> Target output format (default: elf64)\n");
}

bool parse_args(int argc, char** argv, Args* args) {
    // Defaults
    args->output_file = NULL;
    args->input_files = NULL;
    args->input_count = 0;
    args->verbose = false;
    args->arch = x86_64;
    args->bits = 64;
    args->debug_symbols = false;
    args->lexout = false;
    args->parseout = false;
    args->asmout = false;
    #ifdef __WIN32
    args->base = 0x140000000;
    #else
    args->base = 0x400000;
    #endif
    args->savetemps = false;
    args->entry_label = NULL;
    args->linkformat = ELF64;
    args->only_asm = false;

    // Define long options
    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"debug", no_argument, 0, 'd'},
        {"arch", required_argument, 0, 'a'},
        {"bits", required_argument, 0, 'b'},
        {"lexout", no_argument, 0, 1000},
        {"parseout", no_argument, 0, 1001},
        {"asmout", no_argument, 0, 1002},
        {"base", required_argument, 0, 't'},
        {"savetemp", no_argument, 0, 1003},
        {"entry", required_argument, 0, 'e'},
        {"version", no_argument, 0, 1004},
        {"format", required_argument, 0, 'f'},
        {"only-asm", no_argument, 0, 1005},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "o:vhda:b:t:e:f:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'o':
                args->output_file = optarg;
                break;
            case 'v':
                args->verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(PAC_Success);
            case 'd':
                args->debug_symbols = true;
                break;
            case 'a':
                args->arch = archs_to_archenum(optarg);
                if (args->arch == UNKNOWN_ARCH) {
                    fprintf(stderr, COLOR_RED "Error: Unknown Architecture [%s]\n" COLOR_RESET, optarg);
                    return false;
                }
                break;
            case 'b':
                args->bits = atoi(optarg);
                if (args->bits != 16 && args->bits != 32 && args->bits != 64) {
                    fprintf(stderr, COLOR_RED "Error: Bits must be 16/32/64\n" COLOR_RESET);
                    return false;
                }
                break;
            case 1000: 
                args->lexout = true; 
                break;
            case 1001:
                args->parseout = true;
                break;
            case 1002:
                args->asmout = true;
                break;
            case 't':
                args->base = (size_t)strtoul(optarg, NULL, 10);
                break;
            case 1003:
                args->savetemps = true;
                break;
            case 'e':
                args->entry_label = optarg;
                break;
            case 1004:
                printf(COLOR_GREEN __PAC_FULL_INFO__ COLOR_RESET);
                exit(PAC_Success);
            case 'f':
                args->linkformat = str_to_linker_format(optarg);
                if (args->linkformat == (LinkerFormat)-1) {
                    fprintf(stderr, COLOR_RED "Error: Unknown Output format: %s\n" COLOR_CYAN "Tip: Supported Output formats are: elf64/elf32/win64/win32\n" COLOR_RESET, optarg);
                    exit(PAC_Error_UnsupportedObjectFormat);
                }
                break;
            case 1005:
                args->only_asm = true;
                break;
            case '?': // unknown option
            default:
                print_usage(argv[0]);
                return false;
        }
    }

    // Remaining arguments are input files
    args->input_count = argc - optind;
    if (args->input_count <= 0) {
        fprintf(stderr, COLOR_RED "Error: At least one input file is required\n" COLOR_RESET);
        return false;
    }

    args->input_files = &argv[optind]; // point to remaining args

    // Validate output file
    if (!args->output_file && !args->lexout && !args->parseout && !args->asmout) {
        fprintf(stderr, COLOR_RED "Error: Output file is required, unless --lexout/--parseout/--asmout\n" COLOR_RESET);
        return false;
    }

    return true;
}

char* read_file(const char* path, size_t* len) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, path);
        exit(PAC_Error_FileOpenFailed);
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

void write_file(const char* path, void* data, size_t len) {
    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, path);
        exit(PAC_Error_FileOpenFailed);
    }
    fseek(f, 0, SEEK_SET);
    fwrite(data, 1, len, f);
    fflush(f);
    fclose(f);
}

FILE* open_file(const char* path, const char* mode) {
    FILE* f = fopen(path, mode);
    if (!f) {
        fprintf(stderr, COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, path);
        exit(PAC_Error_FileOpenFailed);
    }
    fseek(f, 0, SEEK_SET);
    return f;
}

void perform_lexout(char** file_l, int idx, int count) {
    char* file = file_l[idx];
    printf(COLOR_CYAN "Lexing file: %s\n" COLOR_RESET, file);
    size_t len = 0;
    char* src = read_file(file, &len);
    Lexer lx = init_lexer(src, len, file);
    Token tk;

    while (1) {
        tk = next_token(&lx);
        if (tk.type == SP_EOF) {
            free(tk.lexeme); // free EOF
            break;
        }
        printf(COLOR_GREEN "[%3d:%-3d]" COLOR_RESET " %-20s '%s'\n",
               tk.line, tk.column, token_type_to_str(tk.type), tk.lexeme);
        free(tk.lexeme);
    }

    free(src);
    
    if (count > idx + 1) {
        perform_lexout(file_l, idx + 1, count);
    }
}

void perform_parseout(char** file_l, int idx, int count) {
    char* file = file_l[idx];
    printf(COLOR_CYAN "Parsing file: %s\n" COLOR_RESET, file);
    size_t len = 0;
    char* src = read_file(file, &len);
    Lexer lx = init_lexer(src, len, file);
    Parser parser = init_parser(&lx);
    parse_symbols(&parser); // get all symbols first

    lx = init_lexer(src, len, file);
    parser = init_parser(&lx);
    ASTNode* root = parse_program(&parser);

    char output[512];
    for (size_t i = 0; i < root->child_count; i++) {
        ASTNode* node = root->children[i];
        ast_to_str(node, output, sizeof(output));
        printf(COLOR_GREEN "[AST]" COLOR_RESET " %s\n", output);
    }

    free_ast(root);
    free(src);

    if (count > idx + 1) {
        perform_parseout(file_l, idx + 1, count);
    }
}

void perform_asmout(char** file_l, Args* args, int idx, int count) {
    char* file = file_l[idx];
    printf(COLOR_CYAN "Assembling file: %s\n" COLOR_RESET, file);
    size_t len = 0;
    char* src = read_file(file, &len);

    Lexer lx = init_lexer(src, len, file);
    Parser parser = init_parser(&lx);

    parse_symbols(&parser); // get all symbols first
    lx = init_lexer(src, len, file);
    parser = init_parser(&lx);

    ASTNode* root = parse_program(&parser);

    Assembler asmctx;
    SectionTable sectable;
    SymbolTable symtable;

    sectable.base = args->base;

    init_assembler(&asmctx, &lx, &parser, args->bits, args->arch, root, &symtable, &sectable, args->entry_label);
    symtab_init(&symtable);
    assembler_collect_symbols(&asmctx, file);

    IRList irlist = assemble(&asmctx);

    if (args->savetemps) {
        FILE* f = open_file("asave.paci", "w");
        char buf[512];
        for (size_t i = 0; i < sectable.count; i++) {
            Section sec = sectable.sections[i];
            snprintf(buf, sizeof(buf), ":align %llu\n:start 0x%llx\n:size: 0x%llx\n\t:section %s\n\n", (unsigned long long)sec.alignment, (unsigned long long)sec.base, (unsigned long long)sec.size, sec.name);
            fwrite(buf, 1, strlen(buf), f);
            for (size_t j = 0; j < symtable.count; j++) {
                Symbol sym = symtable.symbols[j];

                if (sym.section_index != i) continue;

                if (sym.type == SYM_IDENTIFIER) snprintf(buf, sizeof(buf), ":start 0x%llx\n\t%s = %s\n", (unsigned long long)sym.addr, sym.name, sym.value);
                if (sym.type == SYM_LABEL) snprintf(buf, sizeof(buf), ":start 0x%llx\n\t%s:\n", (unsigned long long)sym.addr, sym.name);
                
                fwrite(buf, 1, strlen(buf), f);
            }
            fwrite("\n", 1, 1, f);
        }
        fflush(f);
        fclose(f);
    }
    
    print_ir_list(&irlist);
    print_symtab(&symtable, &sectable);
    print_sectab(&sectable);

    free_ast(root); // No need for AST nodes anymore

    free_ir_list(&irlist);
    symtab_free(&symtable);
    section_free(&sectable);
    free(src);

    if (count > idx + 1) {
        perform_asmout(file_l, args, idx + 1, count);
    }
}

int main(int argc, char** argv) {
    Args args;

    if (!parse_args(argc, argv, &args)) {
        return PAC_Error_ArgumentInvalidUsage;
    }

    if (args.lexout) {
        perform_lexout(args.input_files, 0, args.input_count);
        return PAC_Success;
    }

    if (args.parseout) {
        perform_parseout(args.input_files, 0, args.input_count);
        return PAC_Success;
    }

    if (args.asmout) {
        perform_asmout(args.input_files, &args, 0, args.input_count);
        return PAC_Success;
    }

    char** encoded_files = calloc(args.input_count, 128);
    
    for (int i = 0; i < args.input_count; i++){    
        size_t len = 0;
        char* src = read_file(args.input_files[i], &len);

        Lexer lexer = init_lexer(src, len, args.input_files[i]);
        Parser parser = init_parser(&lexer);
        
        parse_symbols(&parser);
        lexer = init_lexer(src, len, args.input_files[i]);
        parser = init_parser(&lexer);

        ASTNode* root = parse_program(&parser);

        SectionTable sectab;
        SymbolTable symtab;

        symtab_init(&symtab);

        Assembler assembler;
        init_assembler(&assembler, &lexer, &parser, (size_t)args.bits, args.arch, root, &symtab, &sectab, args.entry_label);

        assembler_collect_symbols(&assembler, args.input_files[i]);
        IRList irlist = assemble(&assembler);
        
        free_ast(root);

        char outfile[128];
        snprintf(outfile, sizeof(outfile), "asave.%d.paco", i);
        encoded_files[i] = (char*)malloc(128);
        strcpy(encoded_files[i], outfile);

        if (args.arch == x86_64) {
            if (!encode_x86_64(&assembler, outfile, &irlist, args.bits)) break;
        } else if (args.arch == x86) {
            if (!encode_x86_64(&assembler, outfile, &irlist, args.bits)) break;
        } else if (args.arch == PVCPU) {
            if (!encode_pvcpu(&assembler, outfile, &irlist, args.bits)) break;
        } else {
            fprintf(stderr, COLOR_RED "Error: Unsupported Architecture\n" COLOR_RESET);
            return PAC_Error_ArchitectureNotSupported;
        }

        free(src);
        symtab_free(&symtab);
        free_ir_list(&irlist);
        section_free(&sectab);
    }

    if (!args.only_asm) pac_link(args.output_file, encoded_files, args.input_count, args.linkformat, args.base);

    for (int i = 0; i < args.input_count; i++) {
        char* outfile = encoded_files[i];
        if (!args.savetemps && !args.only_asm) remove(outfile);
        free(encoded_files[i]);
    }

    free(encoded_files);

    return PAC_Success;
}
