#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include <pac-err.h>
#include <pac-extra.h>

#include <pac-lexer.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[0;31m"
#define COLOR_GREEN "\033[0;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_CYAN "\033[0;36m"

typedef struct {
    char* output_file;
    char** input_files;
    int input_count;
    bool verbose;
    bool debug_symbols;
    enum Architecture arch;
    int bits;
    bool lexout;
} Args;

void print_usage(const char* prog) {
    printf("Usage: %s -o <output_file> [--verbose] <input_files...>\n", prog);
    printf("Options:\n");
    printf("\t-o, --output <file>       Set output file (required)\n");
    printf("\t-v, --verbose             Enable verbose output\n");
    printf("\t-h, --help                Show this help message\n");
    printf("\t-d, --debug               Include debug symbols\n");
    printf("\t--lexout                  Stop after lexing and print tokens\n");
    printf("\t-a, --arch <architecture> Target architecture (default: host)\n");
    printf("\t-b, --bits <16|32|64>     Target bits (default: host)\n");
}

bool parse_args(int argc, char** argv, Args* args) {
    // Defaults
    args->output_file = NULL;
    args->input_files = NULL;
    args->input_count = 0;
    args->verbose = false;
    args->arch = UNKNOWN_ARCH;
    args->bits = 64;
    args->debug_symbols = false;
    args->lexout = false;

    // Define long options
    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"debug", no_argument, 0, 'd'},
        {"arch", required_argument, 0, 'a'},
        {"bits", required_argument, 0, 'b'},
        {"lexout", no_argument, 0, 1000},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "o:vhda:b:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'o':
                args->output_file = optarg;
                break;
            case 'v':
                args->verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
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
    if (!args->output_file && !args->lexout) {
        fprintf(stderr, COLOR_RED "Error: Output file is required, unless --lexout\n" COLOR_RESET);
        return false;
    }

    return true;
}

char* read_file(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, COLOR_RED "Error: Cannot open file '%s'\n" COLOR_RESET, path);
        exit(EXIT_FAILURE);
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    char* buffer = malloc(size + 1);
    fread(buffer, 1, size, f);
    buffer[size] = '\0';
    fclose(f);
    return buffer;
}

void perform_lexout(const char* file) {
    printf(COLOR_CYAN "Lexing file: %s\n" COLOR_RESET, file);
    char* src = read_file(file);
    Lexer lx = init_lexer(src);
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
}

int main(int argc, char** argv) {
    Args args;

    if (!parse_args(argc, argv, &args)) {
        return EXIT_FAILURE;
    }

    if (args.lexout) {
        for (int i = 0; i < args.input_count; i++) {
            perform_lexout(args.input_files[i]);
        }
        return EXIT_SUCCESS;
    }

    printf(COLOR_YELLOW "Normal compilation mode not yet implemented.\n" COLOR_RESET);
    return EXIT_SUCCESS;
}
