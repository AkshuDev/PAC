#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <elf.h>

#include <pac-lexer.h>
#include <pac-parser.h>
#include <pac-extra.h>
#include <pac-err.h>

#include <pac-asm.h>

void symtab_init(SymbolTable *tab)
{
    tab->symbols = NULL;
    tab->count = 0;
    tab->capacity = 0;
}

void symtab_add(SymbolTable *tab, const char *name, SymbolType type, uint64_t addr, char *value, size_t section_index, uint64_t size, TokenType type_of_data, bool isglobal)
{
    if (tab->count >= tab->capacity)
    {
        tab->capacity = tab->capacity ? tab->capacity * 2 : 16;
        tab->symbols = realloc(tab->symbols, tab->capacity * sizeof(Symbol));
    }
    Symbol *sym = &tab->symbols[tab->count++];
    sym->name = strdup(name);
    sym->type = type;
    sym->addr = addr;
    sym->value = strdup(value);
    sym->section_index = section_index;
    sym->size = size;
    sym->type_of_data = type_of_data;
    sym->is_global = isglobal;
}

bool symtab_get(SymbolTable *tab, const char *name, Symbol *out)
{
    for (size_t i = 0; i < tab->count; i++)
    {
        if (strcmp(tab->symbols[i].name, name) == 0)
        {
            if (out)
                *out = tab->symbols[i];
            return true;
        }
    }
    return false;
}

void symtab_free(SymbolTable *tab)
{
    for (size_t i = 0; i < tab->count; i++)
    {
        free(tab->symbols[i].name);
        free(tab->symbols[i].value);
    }
    free(tab->symbols);
    memset(tab, 0, sizeof(*tab));
}

void section_add(SectionTable *table, const char *name, uint64_t base, uint64_t alignment)
{
    if (table->count >= table->capacity)
    {
        table->capacity = table->capacity ? table->capacity * 2 : 8;
        table->sections = realloc(table->sections, table->capacity * sizeof(Section));
    }

    Section *sec = &table->sections[table->count++];
    sec->name = strdup(name);
    sec->base = base;
    sec->size = 0; // initial size is 0, increase later when adding data/instructions
    sec->alignment = alignment;
    sec->reloc_capacity = 0;
    sec->reloc_count = 0;
    sec->relocs = NULL;
}

Section *section_get(SectionTable *table, const char *name)
{
    for (size_t i = 0; i < table->count; i++)
    {
        if (strcmp(table->sections[i].name, name) == 0)
        {
            return &table->sections[i];
        }
    }
    return NULL;
}

void section_free(SectionTable *table)
{
    for (size_t i = 0; i < table->count; i++)
    {
        free(table->sections[i].name);
    }
    free(table->sections);
    table->sections = NULL;
    table->count = 0;
    table->capacity = 0;
}

void add_reloc(Section* sec, uint64_t offset, uint32_t symbol, uint32_t type, int64_t addend) {
    if (sec->reloc_count == sec->reloc_capacity) {
        sec->reloc_capacity = sec->reloc_capacity ? sec->reloc_capacity * 2 : 16;
        sec->relocs = realloc(sec->relocs, sec->reloc_capacity * sizeof(Relocation));
    }
    sec->relocs[sec->reloc_count++] = (Relocation){ offset, symbol, type, addend };
}

void free_reloc(Section* sec) {
    if (sec->relocs) {
        free(sec->relocs);
        sec->reloc_capacity = 0;
        sec->reloc_count = 0;
        sec->relocs = NULL;
    }
}

void init_assembler(Assembler *ctx, Lexer *lex, Parser *parser, size_t bits, enum Architecture arch, ASTNode *root, SymbolTable *symtable, SectionTable *sectable, char *entry_label)
{
    ctx->arch = arch;
    ctx->bits = bits;
    ctx->parser = parser;
    ctx->lex = lex;
    ctx->current = root;
    ctx->symbols = symtable;
    ctx->sections = sectable;
    ctx->entry_label = entry_label;
}

static void add_ir(IRList *list, IRInstruction instr)
{
    if (list->count >= list->capacity)
    {
        list->capacity = list->capacity ? list->capacity * 2 : 16;
        list->instructions = realloc(list->instructions, list->capacity * sizeof(IRInstruction));
    }
    list->instructions[list->count++] = instr;
}

static size_t default_section_alignment(const char *name)
{
    if (strcmp(name, ".text") == 0)
        return 16;
    if (strcmp(name, ".data") == 0)
        return 8;
    if (strcmp(name, ".rodata") == 0)
        return 8;
    if (strcmp(name, ".bss") == 0)
        return 8;
    if (strcmp(name, ".stack") == 0)
        return 16;
    return 8; // generic safe fallback
}

static size_t operand_length_x86(ASTOperand *op, ASTInstruction *inst, enum Architecture arch, size_t *index, ASTOperand* prev, Assembler* ctx, size_t* cvaddr, size_t* clength)
{
    switch (op->type)
    {
    case OPERAND_REGISTER:
        // extended registers (r8–r15) need REX prefix
        if (prev && prev->type == OPERAND_REGISTER) return 1; // already taken into account (+1 for ModR/M)
        if (arch == x86_64 && op->reg[0] == 'r' )
        {
            return 1; //  REX
        }
        return 0; // No REX
    case OPERAND_LIT_INT:
        *index += 1;
        if (prev && prev->type == OPERAND_REGISTER) {
            if (prev->reg[0] == 'r' && arch == x86_64) return 8;
            else if (prev->reg[0] == 'e') return 4;
            else if (prev->reg[0] == 'a' && (prev->reg[1] != 'h' || prev->reg[1] != 'l')) return 2;
            else return 1;
        }
        return 4; // 4 byte imm
    case OPERAND_LIT_FLOAT:
        *index += 1;
        if (prev && prev->type == OPERAND_REGISTER) {
            if (prev->reg[0] == 'r' && arch == x86_64) return 8;
            else if (prev->reg[0] == 'e') return 4;
            else if (prev->reg[0] == 'a' && (prev->reg[1] != 'h' || prev->reg[1] != 'l')) return 2;
            else return 1;
        }
        return 4;
    case OPERAND_LIT_DOUBLE:
        *index += 1;
        if (prev && prev->type == OPERAND_REGISTER) {
            if (prev->reg[0] == 'r' && arch == x86_64) return 8;
            else if (prev->reg[0] == 'e') return 4;
            else if (prev->reg[0] == 'a' && (prev->reg[1] != 'h' || prev->reg[1] != 'l')) return 2;
            else return 1;
        }
        return 4;
    case OPERAND_MEMORY:
        size_t len = 1; // ModR/M
        *index += 1;
        if (op->mem_opr_count > 0 && op->mem_addr[0]->type == OPERAND_IDENTIFIER) {
            // find it
            Symbol out;
            if (symtab_get(ctx->symbols, op->mem_addr[0]->identifier->identifier.name, &out)) {
                if (strcmp(ctx->sections->sections[out.section_index].name, ".bss") != 0) {
                    if (prev && prev->type == OPERAND_REGISTER) {
                        if (prev->reg[0] == 'r' && arch == x86_64) return 8;
                        else if (prev->reg[0] == 'e') return 4;
                        else if (prev->reg[0] == 'a' && (prev->reg[1] != 'h' || prev->reg[1] != 'l')) return 2;
                    }
                }
            }
        }
        len += 4; // max displacement
        return len;
    case OPERAND_LABEL:
        *index += 1;
        if (inst->opcode >= ASM_JMP && inst->opcode <= ASM_JLE) {
            Symbol sym;
            if (symtab_get(ctx->symbols, op->label, &sym)) {
                size_t disp = sym.addr - (*cvaddr + *clength + 4);
                if (disp < 0xFF) return 4; // Currently I only support 32-bit disp
            }
        }
        return 4; // assume relative address
    case OPERAND_IDENTIFIER:
        *index += 1;
        if (inst->opcode >= ASM_JMP && inst->opcode <= ASM_JLE) {
            Symbol sym;
            if (symtab_get(ctx->symbols, op->identifier->identifier.name, &sym)) {
                size_t disp = sym.addr - (*cvaddr + *clength + 4);
                if (disp < 0xFF) return 4; // Currently I only support 32-bit disp
            }
        }
        
        if (prev && prev->type == OPERAND_REGISTER) {
            if (prev->reg[0] == 'r' && arch == x86_64) return 8;
            else if (prev->reg[0] == 'e') return 4;
            else if (prev->reg[0] == 'a' && (prev->reg[1] != 'h' || prev->reg[1] != 'l')) return 2;
            else return 1;
        }
        return 4; // 4 byte relative displacement
    default:
        return 0;
    }
}

static uint64_t get_opcode_len_x86(TokenType opcode, bool* only_opcode)
{
    switch (opcode)
    {
    case ASM_MOV:
        return 1;

    case ASM_ADD:
        return 1;

    case ASM_SUB:
        return 1;

    case ASM_MUL:
        return 1;

    case ASM_DIV:
        return 1;

    case ASM_PUSH:
        *only_opcode = true;
        return 1;

    case ASM_POP:
        *only_opcode = true;
        return 1;

    case ASM_CALL:
        return 1;

    case ASM_RET:
        return 1;

    case ASM_JMP:
        return 1;

    case ASM_JE:
        return 2;

    case ASM_JNE:
        return 2;

    case ASM_JG:
        return 2;

    case ASM_JGE:
        return 2;

    case ASM_JL:
        return 2;

    case ASM_JLE:
        return 2;

    case ASM_CMP:
        return 1;

    case ASM_TEST:
        return 1;

    case ASM_AND:
        return 1;

    case ASM_OR:
        return 1;

    case ASM_XOR:
        return 1;

    case ASM_NOT:
        return 1;

    case ASM_SHL:
        return 1;

    case ASM_SHR:
        return 1;

    case ASM_SYSCALL:
        return 2;

    case ASM_NOP:
        return 1;

    default:
        return 0;
    }
}

static size_t instruction_length(ASTInstruction inst, enum Architecture arch, Assembler* ctx, size_t* cvaddr)
{
    size_t length = 0;
    size_t temp = 0;
    ASTOperand* prev = NULL;
    bool only_opcode = false;

    switch (arch)
    {
    case x86_64:
        // x86_64 is variable length        
        length = get_opcode_len_x86(inst.opcode, &only_opcode); // opcode
        if (inst.operand_count == 0 || only_opcode == true) break;
        for (size_t i = 0; i < inst.operand_count; i++) {
            if (i != 0) prev = inst.operands[i - 1];
            length += operand_length_x86(inst.operands[i], &inst, arch, &temp, prev, ctx, cvaddr, &length);
        }
        break;

    case x86:
        // x86 is variable length
        length = get_opcode_len_x86(inst.opcode, &only_opcode); // opcode
        if (inst.operand_count == 0 || only_opcode == true) break;
        for (size_t i = 0; i < inst.operand_count; i++) {
            if (i != 0) prev = inst.operands[i - 1];
            length += operand_length_x86(inst.operands[i], &inst, arch, &temp, prev, ctx, cvaddr, &length);
        }
        break;

    case ARM32:
        // ARM instructions are fixed 4 bytes
        length = 4;
        break;
    case ARM64:
        // ARM instructions are fixed 4 bytes
        length = 4;
        break;

    case RISCV32:
        // RISC-V: 4 bytes base, 2 bytes if compressed
        // here uncompressed
        length = 4;
        break;
    case RISCV64:
        // RISC-V: 4 bytes base, 2 bytes if compressed
        // here uncompressed
        length = 4;
        break;

    case PVCPU:
        // PVCpu is fixed at 12 bytes (little big don't you think? well it has a format like - [src:1b][dest:1b][imm:8b][mode:1b][extra:1b] (extra can be used for anything)
        length = 12;
        break;

    default:
        // fallback: sum opcode + operand sizes from AST
        length = 1;
        for (size_t i = 0; i < inst.operand_count; i++)
            length += 4; // assuming 4 bytes each
        break;
    }

    return length;
}

void assembler_collect_symbols(Assembler *ctx, char* filename)
{
    ASTNode *root = ctx->current;
    SectionTable *sectab = ctx->sections;
    SymbolTable *symtab = ctx->symbols;
    signed long long current_section = -1;
    size_t cvaddr = 0; // Current Virtual Address
    Symbol *first_label = NULL;
    ASTNode *first_label_node = NULL;

    ASTNode *section_node = NULL;

    symtab_add(symtab, filename, SYM_FILE, 0, "\0", 0, 0, (TokenType)-1, false);

    for (size_t i = 0; i < root->child_count; i++)
    {
        ASTNode *node = root->children[i];

        switch (node->type)
        {
        case AST_DIRECTIVE:
            if (node->directive.type == SECTION)
            {
                if (cvaddr != 0 && current_section >= 0)
                {
                    Section cursec = sectab->sections[current_section];
                    size_t def_alignment = default_section_alignment(cursec.name);
                    size_t alignment = (section_node->directive.aligment != 0) ? section_node->directive.aligment : def_alignment;

                    if (section_node->directive.size < 0)
                    {
                        sectab->sections[current_section].size = align_up((size_t)cursec.size, alignment);
                    }
                    else
                    {
                        sectab->sections[current_section].size = align_up((size_t)cursec.size, alignment);
                        cursec.size = sectab->sections[current_section].size; // ensure it updated
                        if ((uint64_t)section_node->directive.size < cursec.size)
                        {
                            PAC_ERRORF(ctx->lex->file, section_node->line, section_node->col, ctx->lex->src, ctx->lex->len, section_node->directive.arg, strlen(section_node->directive.arg), "Tried to define more data then allocated using ':size'!");
                            PAC_TIPF(ctx->lex->file, section_node->line, section_node->col, ctx->lex->src, ctx->lex->len, section_node->directive.arg, strlen(section_node->directive.arg), "The size of sections is aligned up to match the section alignment, try an aligned size when using ':size'");
                            symtab_free(symtab);
                            section_free(sectab);
                            free_ast(ctx->parser->root);
                            exit(PAC_Error_SectionFull);
                        }
                        else if ((uint64_t)section_node->directive.size > cursec.size)
                        {
                            sectab->sections[current_section].size = align_up((size_t)section_node->directive.size, alignment);
                            cvaddr += section_node->directive.size - cursec.size; // padding
                        }
                    }

                    cvaddr = align_up(cvaddr, alignment);
                }
                Section *s = section_get(sectab, node->directive.arg);
                if (!s)
                {
                    size_t def_align = default_section_alignment(node->directive.arg);
                    size_t alignment = (node->directive.aligment != 0) ? node->directive.aligment : def_align;

                    if (node->directive.start >= 0)
                    {
                        if (cvaddr > (size_t)node->directive.start)
                        {
                            PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->directive.arg, strlen(node->directive.arg), "value provided using ':start' overlaps current virtual address, try an higher value!");
                            symtab_free(symtab);
                            section_free(sectab);
                            free_ast(ctx->parser->root);
                            exit(PAC_Error_InvalidSectionLayout);
                        }
                        else if (cvaddr < (size_t)node->directive.start)
                        {
                            cvaddr = align_up((size_t)node->directive.start, alignment);
                        }
                        else
                        {
                            cvaddr = align_up(cvaddr, alignment);
                        }
                    }
                    else
                    {
                        cvaddr = align_up(cvaddr, alignment);
                    }

                    section_add(sectab, node->directive.arg, cvaddr, alignment);
                    section_node = node;
                }

                current_section = sectab->count - 1;
            }
            break;

        case AST_LABEL:
            if (current_section < 0)
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->label.name, strlen(node->label.name), "Tried to define labels in undefined section!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionNotFound);
            }
            symtab_add(symtab, node->label.name, SYM_LABEL, cvaddr, "\0", current_section, 0, (TokenType)-1, false);
            if (first_label == NULL)
            {
                first_label = &symtab->symbols[symtab->count - 1];
                first_label_node = node;
            }
            break;

        case AST_DECLIDENTIFIER:
            if (current_section < 0)
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->decl_identifier.name, strlen(node->decl_identifier.name), "Tried to define data in undefined section!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionNotFound);
            }

            TokenType type = node->decl_identifier.type;
            size_t size = 0;
            char value[512];
            if (type >= LIT_INT && type <= LIT_FLOAT)
            {
                size = 4;
            }
            else if (type == LIT_STRING)
            {
                if (node->child_count == 0)
                {
                    size = sizeof(void *);
                }
                else
                {
                    size = strlen(node->children[0]->literal.str_val);
                }
            }
            else if (type == LIT_CHAR)
            {
                size = 1;
            }
            else
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->decl_identifier.name, strlen(node->decl_identifier.name), "Cannot resolve type's size!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_TypeResolutionFailed);
            }

            switch (type)
            {
            case LIT_INT:
                type = T_INT;
                snprintf(value, sizeof(value), "%lld", (long long int)node->children[0]->literal.int_val);
                break;
            case LIT_BIN:
                type = T_INT;
                snprintf(value, sizeof(value), "%lld", (long long int)node->children[0]->literal.int_val);
                break;
            case LIT_HEX:
                type = T_INT;
                snprintf(value, sizeof(value), "%lld", (long long int)node->children[0]->literal.int_val);
                break;
            case LIT_CHAR:
                type = T_BYTE;
                snprintf(value, sizeof(value), "%lld", (long long int)node->children[0]->literal.int_val);
                break;
            case LIT_FLOAT:
                type = T_FLOAT;
                snprintf(value, sizeof(value), "%f", node->children[0]->literal.float_val);
                break;
            case LIT_STRING:
                type = T_ARRAY;
                snprintf(value, sizeof(value), "%s", node->children[0]->literal.str_val);
                break;
            default:
                break;
            }

            if (node->decl_identifier.opt_specified_type != (TokenType)-1 && node->decl_identifier.opt_specified_type >= T_BYTE && node->decl_identifier.opt_specified_type <= T_PTR)
            {
                if (type != node->decl_identifier.opt_specified_type && type > node->decl_identifier.opt_specified_type)
                {
                    PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->decl_identifier.name, strlen(node->decl_identifier.name), "Invalid Cast!");
                    symtab_free(symtab);
                    section_free(sectab);
                    free_ast(ctx->parser->root);
                    exit(PAC_Error_InvalidCast);
                }
                if (type < node->decl_identifier.opt_specified_type)
                {
                    switch (node->decl_identifier.opt_specified_type)
                    {
                    case T_BYTE:
                        size = 1;
                        break;
                    case T_UBYTE:
                        size = 1;
                        break;
                    case T_SHORT:
                        size = 2;
                        break;
                    case T_USHORT:
                        size = 2;
                        break;
                    case T_INT:
                        size = 4;
                        break;
                    case T_UINT:
                        size = 4;
                        break;
                    case T_FLOAT:
                        size = 4;
                        break;
                    case T_DOUBLE:
                        size = 8;
                        break;
                    case T_PTR:
                        size = sizeof(void *);
                        break;
                    case T_LONG:
                        size = 8;
                        break;
                    case T_ULONG:
                        size = 8;
                        break;
                    case T_ARRAY:
                        size = 8;
                        break;
                    default:
                        PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->decl_identifier.name, strlen(node->decl_identifier.name), "Unknown Type!");
                        symtab_free(symtab);
                        section_free(sectab);
                        free_ast(ctx->parser->root);
                        exit(PAC_Error_TypeResolutionFailed);
                    }
                }
            }

            symtab_add(symtab, node->decl_identifier.name, SYM_IDENTIFIER, cvaddr, value, current_section, (uint64_t)size, type, false);

            cvaddr += size;
            sectab->sections[current_section].size += size;

            break;

        case AST_RESERVE:
            if (current_section < 0)
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->reserve.name, strlen(node->reserve.name), "Tried to reserve data in undefined section!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionNotFound);
            }

            Section cursec = sectab->sections[current_section];
            if (strcmp(cursec.name, ".bss") != 0)
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->reserve.name, strlen(node->reserve.name), "Tried to reserve data in non bss section!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionNotFound);
            }

            size = 0;

            switch (node->reserve.type)
            {
            case T_BYTE:
                size = 1;
                break;
            case T_UBYTE:
                size = 1;
                break;
            case T_SHORT:
                size = 2;
                break;
            case T_USHORT:
                size = 2;
                break;
            case T_INT:
                size = 4;
                break;
            case T_UINT:
                size = 4;
                break;
            case T_FLOAT:
                size = 4;
                break;
            case T_DOUBLE:
                size = 8;
                break;
            case T_PTR:
                size = sizeof(void *);
                break;
            case T_LONG:
                size = 8;
                break;
            case T_ULONG:
                size = 8;
                break;
            case T_ARRAY:
                size = 8;
                break;
            default:
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->reserve.name, strlen(node->reserve.name), "Unknown Type!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_TypeResolutionFailed);
            }

            symtab_add(symtab, node->reserve.name, SYM_IDENTIFIER, cvaddr, "\0", current_section, (uint64_t)size, node->reserve.type, false);
            cvaddr += size;
            sectab->sections[current_section].size += size;

            break;

        case AST_INSTRUCTION:
            if (current_section < 0)
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, "", 0, "Tried to define instructions in undefined section!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionNotFound);
            }
            size_t inst_size = instruction_length(node->inst, ctx->arch, ctx, &cvaddr);
            cvaddr += inst_size;
            sectab->sections[current_section].size += inst_size;
            break;

        default:
            break;
        }
    }
    if (cvaddr != 0 && current_section >= 0)
    {
        Section cursec = sectab->sections[current_section];
        size_t def_alignment = default_section_alignment(cursec.name);
        size_t alignment = (section_node->directive.aligment != 0) ? section_node->directive.aligment : def_alignment;

        if (section_node->directive.size < 0)
        {
            sectab->sections[current_section].size = align_up((size_t)cursec.size, alignment);
        }
        else
        {
            sectab->sections[current_section].size = align_up((size_t)cursec.size, alignment);
            cursec.size = sectab->sections[current_section].size; // ensure it updated
            if ((uint64_t)section_node->directive.size < cursec.size)
            {
                PAC_ERRORF(ctx->lex->file, section_node->line, section_node->col, ctx->lex->src, ctx->lex->len, section_node->directive.arg, strlen(section_node->directive.arg), "Tried to define more data then allocated using ':size'!");
                PAC_TIPF(ctx->lex->file, section_node->line, section_node->col, ctx->lex->src, ctx->lex->len, section_node->directive.arg, strlen(section_node->directive.arg), "The size of sections is aligned up to match the section alignment, try an aligned size when using ':size'");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionFull);
            }
            else if ((uint64_t)section_node->directive.size > cursec.size)
            {
                sectab->sections[current_section].size = align_up((size_t)section_node->directive.size, alignment);
                cvaddr += section_node->directive.size - cursec.size; // padding
            }
        }

        cvaddr = align_up(cvaddr, alignment);
    }

    if (ctx->entry_label == NULL)
    {
        fprintf(stderr, COLOR_YELLOW "Warning: No entry point specified, defaulting to the first label/func!\n" COLOR_RESET);
        ctx->entry_label = first_label_node->label.name;
        ctx->entry = (size_t)first_label->addr;
    }
    else
    {
        Symbol *entry_label = NULL;
        if (!symtab_get(symtab, ctx->entry_label, entry_label))
        {
            fprintf(stderr, COLOR_RED "Error: No such label/function [%s]\n", ctx->entry_label);
            symtab_free(symtab);
            section_free(sectab);
            free_ast(ctx->parser->root);
            exit(PAC_Error_MissingEntryPoint);
        }
        ctx->entry = (size_t)entry_label->addr;
    }
}

IRList assemble(Assembler *ctx)
{
    IRList list = {0};
    SymbolTable *symtab = ctx->symbols;
    SectionTable *sectab = ctx->sections;
    ASTNode *root = ctx->current;

    size_t current_offset = 0;
    signed long long current_section = -1;

    for (size_t i = 0; i < root->child_count; i++)
    {
        ASTNode *node = root->children[i];
        if (node->type == AST_DIRECTIVE && node->directive.type == SECTION)
        {
            Section *sec = section_get(ctx->sections, node->directive.arg);
            current_section = (sec ? (sec - ctx->sections->sections) : 0);
            current_offset = ctx->sections->sections[current_section].base;
            continue;
        }

        if (node->type == AST_LABEL)
        {
            // assign label addr = current offset in section
            if (current_section < 0)
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, node->label.name, strlen(node->label.name), "Tried to define labels in undefined section!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionNotFound);
            }
            Symbol sym;
            if (symtab_get(symtab, node->label.name, &sym))
            {
                sym.addr = current_offset;
            }
            continue;
        }

        if (node->type == AST_INSTRUCTION)
        {
            if (current_section < 0)
            {
                PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, "", 0, "Tried to define instructions in undefined section!");
                symtab_free(symtab);
                section_free(sectab);
                free_ast(ctx->parser->root);
                exit(PAC_Error_SectionNotFound);
            }
            ASTInstruction *inst = &node->inst;
            IRInstruction ir = {0};
            ir.opcode = inst->opcode;
            ir.arch = ctx->arch;
            ir.operand_count = inst->operand_count;
            ir.vaddr = current_offset;

            for (size_t j = 0; j < inst->operand_count; j++)
            {
                ASTOperand *op = inst->operands[j];

                if (op->type == OPERAND_LABEL || op->type == OPERAND_IDENTIFIER)
                {
                    Symbol sym;
                    char *label = NULL;

                    if (op->type == OPERAND_LABEL)
                        label = op->label;
                    if (op->type == OPERAND_IDENTIFIER)
                    {
                        if (op->identifier->type != AST_IDENTIFIER)
                        {
                            PAC_ERRORF(ctx->lex->file, node->line, node->col, ctx->lex->src, ctx->lex->len, "", 0, "Identifier doesn't have type AST_Identifier!");
                            symtab_free(symtab);
                            section_free(sectab);
                            free_ast(ctx->parser->root);
                            exit(PAC_Error_InvalidIdentifier);
                        }
                        label = op->identifier->identifier.name;
                    }

                    bool got_sym = symtab_get(symtab, label, &sym);
                    if (got_sym)
                    {
                        char buf[128];
                        snprintf(buf, sizeof(buf), "0x%llX", (long long)sym.addr);
                        ir.operands[j] = strdup(buf);
                    }
                    else
                    {
                        ir.operands[j] = strdup("UNRESOLVED");
                    }
                }
                else if (op->type == OPERAND_REGISTER)
                {
                    ir.operands[j] = strdup(op->reg);
                }
                else if (op->type == OPERAND_LIT_INT || op->type == OPERAND_LIT_CHAR)
                {
                    char buf[128];
                    snprintf(buf, sizeof(buf), "%lld", (long long)op->int_val);
                    ir.operands[j] = strdup(buf);
                }
                else if (op->type == OPERAND_LIT_FLOAT || op->type == OPERAND_LIT_DOUBLE)
                {
                    char buf[128];
                    snprintf(buf, sizeof(buf), "%f", op->float_val);
                    ir.operands[j] = strdup(buf);
                }
                else if (op->type == OPERAND_MEMORY)
                {
                    char buf[128];
                    if (op->mem_opr_count < 1)
                    {
                        fprintf(stderr, COLOR_RED "Error: Operand of type memory is empty. e.g. mov %%rax, []\n" COLOR_RESET);
                        symtab_free(symtab);
                        section_free(sectab);
                        free_ast(ctx->parser->root);
                        exit(PAC_Error_SyntaxMissingOperand);
                    }
                    if (op->mem_opr_count == 1)
                    {
                        // Either identifier or register
                        ASTOperand *opmem_op = op->mem_addr[0];
                        if (opmem_op->type == OPERAND_REGISTER)
                        {
                            snprintf(buf, sizeof(buf), "[%s]", opmem_op->reg);
                        }
                        else if (opmem_op->type == OPERAND_IDENTIFIER)
                        {
                            if (opmem_op->identifier->type != AST_IDENTIFIER)
                            {
                                fprintf(stderr, COLOR_RED "Error: Identifier doesn't have type AST_Identifier!\n" COLOR_RESET);
                                fprintf(stderr, COLOR_CYAN "Tip: This is an internal error, but it could be caused by the user, try using '--parseout' to take a look at all the generated AST Nodes!\n" COLOR_RESET);
                                symtab_free(symtab);
                                section_free(sectab);
                                free_ast(ctx->parser->root);
                                exit(PAC_Error_InvalidIdentifier);
                            }
                            Symbol sym;
                            bool got_sym = symtab_get(symtab, opmem_op->identifier->identifier.name, &sym);
                            if (got_sym)
                            {
                                snprintf(buf, sizeof(buf), "[0x%llX]", (long long)sym.addr);
                            }
                            else
                            {
                                snprintf(buf, sizeof(buf), "UNRESOLVED");
                            }
                        } else
                        {
                            fprintf(stderr, COLOR_RED "Error: Operand of type memory has an undefined/unsupported expression! .e.g mov %%rax, [\"This string is unsupported!\"]\n" COLOR_RESET);
                            symtab_free(symtab);
                            section_free(sectab);
                            free_ast(ctx->parser->root);
                            exit(PAC_Error_SyntaxInvalidOperandType);
                        }
                    } else if (op->mem_opr_count == 2)
                    {
                        // 101% displacement
                        ASTOperand *opmem_op = op->mem_addr[0];
                        ASTOperand *opmem_disp = op->mem_addr[1];

                        if (opmem_disp->type != OPERAND_DISPLACEMENT) {
                            fprintf(stderr, COLOR_RED "Error: Expected Operand of type Displacement, got something else instead! e.g.\n\tInvalid - mov %%rax, [%%rbx 123]\n\tValid - mov %%rax, [%%rbx + 123]\n" COLOR_RESET);
                            symtab_free(symtab);
                            section_free(sectab);
                            free_ast(ctx->parser->root);
                            exit(PAC_Error_SyntaxUnexpectedToken);
                        }

                        if (opmem_op->type == OPERAND_REGISTER)
                        {
                            if (opmem_op->int_val >= 0) snprintf(buf, sizeof(buf), "[%s + %llu]", opmem_op->reg, (unsigned long long)opmem_disp->int_val);
                            else snprintf(buf, sizeof(buf), "[%s - %llu]", opmem_op->reg, (unsigned long long)-opmem_disp->int_val);
                        }
                        else if (opmem_op->type == OPERAND_IDENTIFIER)
                        {
                            if (op->identifier->type != AST_IDENTIFIER)
                            {
                                fprintf(stderr, COLOR_RED "Error: Identifier doesn't have type AST_Identifier!\n" COLOR_RESET);
                                fprintf(stderr, COLOR_CYAN "Tip: This is an internal error, but it could be caused by the user, try using '--parseout' to take a look at all the generated AST Nodes!\n" COLOR_RESET);
                                symtab_free(symtab);
                                section_free(sectab);
                                free_ast(ctx->parser->root);
                                exit(PAC_Error_InvalidIdentifier);
                            }
                            Symbol sym;
                            bool got_sym = symtab_get(symtab, opmem_op->identifier->identifier.name, &sym);
                            if (got_sym)
                            {
                                if (opmem_op->int_val >= 0) snprintf(buf, sizeof(buf), "[0x%llX + %llu]", (long long)sym.addr, (unsigned long long)opmem_disp->int_val);
                                else snprintf(buf, sizeof(buf), "[0x%llX - %llu]", (long long)sym.addr, (unsigned long long)-opmem_disp->int_val);
                            }
                            else
                            {
                                snprintf(buf, sizeof(buf), "UNRESOLVED");
                            }
                        } else
                        {
                            fprintf(stderr, COLOR_RED "Error: Operand of type memory has an undefined/unsupported expression! .e.g mov %%rax, [\"This string is unsupported!\"]\n" COLOR_RESET);
                            symtab_free(symtab);
                            section_free(sectab);
                            free_ast(ctx->parser->root);
                            exit(PAC_Error_SyntaxInvalidOperandType);
                        }
                    }
                    ir.operands[j] = strdup(buf);
                }
            }

            add_ir(&list, ir);
            current_offset += instruction_length(node->inst, ctx->arch, ctx, &current_offset);
            sectab->sections[current_section].size += instruction_length(node->inst, ctx->arch, ctx, &current_offset);
        }
    }

    return list;
}

void free_ir_list(IRList *list)
{
    for (size_t i = 0; i < list->count; i++)
    {
        for (size_t j = 0; j < list->instructions[i].operand_count; j++)
        {
            free(list->instructions[i].operands[j]);
        }
    }
    free(list->instructions);
    memset(list, 0, sizeof(*list));
}

void print_ir(const IRInstruction *ir)
{
    printf(COLOR_GREEN "[IR] [0x%llX]" COLOR_RESET " %s ", (unsigned long long)ir->vaddr, token_type_to_ogstr(ir->opcode));

    if (ir->operand_count > 0)
    {
        for (size_t i = 0; i < ir->operand_count; i++)
        {
            printf("%s", ir->operands[i] ? ir->operands[i] : "(null)");
            if (i + 1 < ir->operand_count)
                printf(", ");
        }
    }

    if (ir->arch)
    {
        char arch[256];
        archenum_to_archs(ir->arch, arch);
        printf(" :arch=%s", arch);
    }

    printf("\n");
}

void print_ir_list(const IRList *list)
{
    printf(COLOR_YELLOW "=== IR Dump (%zu instructions) ===\n" COLOR_RESET, list->count);
    for (size_t i = 0; i < list->count; i++)
    {
        print_ir(&list->instructions[i]);
    }
    printf(COLOR_YELLOW "=== End IR ===\n" COLOR_RESET);
}

char *symtype_to_str(SymbolType type)
{
    switch (type)
    {
    case SYM_LABEL:
        return "LABEL";
    case SYM_IDENTIFIER:
        return "IDENTIFIER";
    case SYM_SECTION:
        return "SECTION";
    default:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

void print_symtab(SymbolTable *symtab, SectionTable *sectab)
{
    printf(COLOR_YELLOW "=== Symbol Dump (%zu symbols) ===\n" COLOR_RESET, symtab->count);
    for (size_t i = 0; i < symtab->count; i++)
    {
        Symbol sym = symtab->symbols[i];
        if ((signed long long)sym.section_index < 0)
        {
            printf(COLOR_GREEN "[%s] %s at 0x%llX => %s in section: Undefined\n" COLOR_RESET, symtype_to_str(sym.type), sym.name, (unsigned long long)sym.addr, sym.value);
            continue;
        }
        printf(COLOR_GREEN "[%s] " COLOR_RESET "%s " COLOR_GREEN "at 0x%llX " COLOR_YELLOW "=> " COLOR_RESET "%s " COLOR_GREEN "in section: %s\n" COLOR_RESET, symtype_to_str(sym.type), sym.name, (unsigned long long)sym.addr, strcmp(sym.value, "") != 0 ? sym.value : "null", sectab->sections[sym.section_index].name);
    }
    printf(COLOR_YELLOW "=== End Symbol ===\n" COLOR_RESET);
}

void print_sectab(SectionTable *sectab)
{
    printf(COLOR_YELLOW "=== Section Dump (%zu sections) ===\n" COLOR_RESET, sectab->count);
    for (size_t i = 0; i < sectab->count; i++)
    {
        Section sec = sectab->sections[i];
        printf(COLOR_GREEN "[0x%llX] " COLOR_RESET "%s " COLOR_YELLOW "=> " COLOR_GREEN "%llu bytes\n" COLOR_RESET, (unsigned long long)sec.base, sec.name, (unsigned long long)sec.size);
    }
    printf(COLOR_YELLOW "=== End Section ===\n" COLOR_RESET);
}