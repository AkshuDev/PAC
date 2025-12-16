#pragma once

#include <pac-lexer.h>
#include <pac-parser.h>

#include <pac-extra.h>

typedef enum {
    SYM_LABEL,
    SYM_IDENTIFIER,
    SYM_SECTION,
    SYM_FILE,
} SymbolType;

typedef struct {
    char* name;
    SymbolType type;
    uint64_t addr; // address
    char* value; // constant value
    size_t section_index; // section the symbol belongs to
    uint64_t size; // size
    TokenType type_of_data;
    bool is_global;
} Symbol;

typedef struct {
    Symbol* symbols;
    size_t count;
    size_t capacity;
} SymbolTable;

typedef struct {
    uint64_t offset; // Offset within the section where relocation applies
    uint32_t symbol; // Symbol index in the .symtab
    uint32_t type; // ELF relocation type (R_X86_64_PC32, etc.)
    int64_t addend; // Addend for RELA (usually 0)
} Relocation;

typedef struct {
    char* name;
    uint64_t base;
    uint64_t size;
    uint64_t alignment;

    Relocation* relocs;
    size_t reloc_count;
    size_t reloc_capacity;
} Section;

typedef struct {
    Section* sections;
    size_t count;
    size_t capacity;
    size_t base;
} SectionTable;

typedef struct {
    Lexer* lex;
    Parser* parser;
    ASTNode* current; // No previous
    size_t bits;
    enum Architecture arch;
    SymbolTable* symbols;
    SectionTable* sections;
    size_t entry;
    char* entry_label;
} Assembler;

typedef struct {
    TokenType opcode; // e.g. ASM_MOV
    char* operands[3]; // e.g. "rax", "60"
    size_t operand_count;
    enum Architecture arch; // e.g. "x86_64"
    uint8_t bytes[16]; // machine code output
    size_t byte_count;
    size_t vaddr;
} IRInstruction;

typedef struct {
    IRInstruction* instructions;
    size_t count;
    size_t capacity;
} IRList;

void symtab_init(SymbolTable* tab);
void symtab_free(SymbolTable* tab);
void section_free(SectionTable* table);
Section *section_get(SectionTable *table, const char *name);
bool symtab_get(SymbolTable *tab, const char *name, Symbol *out);
void add_reloc(Section* sec, uint64_t offset, uint32_t symbol, uint32_t type, int64_t addend);
void free_reloc(Section* sec);
void free_relocs(SectionTable* sectab);
IRList assemble(Assembler* ctx);    
void free_ir_list(IRList* list);
void init_assembler(Assembler* ctx, Lexer* lex, Parser* parser, size_t bits, enum Architecture arch, ASTNode* root, SymbolTable* symtable, SectionTable* sectable, char* entry_label);
void assembler_collect_symbols(Assembler* ctx, char* filename);
void print_ir(const IRInstruction* ir);
void print_ir_list(const IRList* list);
void print_symtab(SymbolTable* symtab, SectionTable* sectab);
void print_sectab(SectionTable* sectab);
