#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <pac-lexer.h>
#include <pac-parser.h>
#include <pac-err.h>

static char* macros_str[256];
static char* macros_val[256];
static size_t macros = 0;

static size_t nxt_secalignment = 0;
static int64_t nxt_secstart = -1;
static int64_t nxt_secsize = -1;

static size_t funccount = 0;
static bool in_func = false;
static char func_start[256];

static ASTNode* parse_identifier(Parser* p);

static void free_macros() {
    for (size_t i = 0; i < macros; i++) {
        char* str = macros_str[i];
        char* val = macros_val[i];
        if (str != NULL) free(str);
        if (val != NULL) free(val);
    }
    macros = 0;
}

static void alloc_macros(size_t index, size_t sizename, size_t sizeval) {
    macros_str[index] = malloc(sizename);
    macros_val[index] = malloc(sizeval);
}

static char* find_macro(char* name, int* ret) {
    for (size_t i = 0; i < macros; i++) {
        char* macro = macros_str[i];
        if (strcmp(macro, name) == 0) {
            if (*macros_val[i] == (char)0x0) {
                *ret = -2;
                return NULL;
            }
            *ret = 0;
            return macros_val[i];
        }
    }
    *ret = -1;
    return NULL;
}

static void new_macro(char* name, char* value) {
    if (value == NULL) {
        alloc_macros(macros, strlen(name) + 1, 8); // 8 bytes to ensure void* fits (NULL)
        strcpy(macros_str[macros], name);
        *macros_val[macros] = (char)0x0; // Set the first byte of the char* to null not the char* itself
        macros++;
        return;
    }
    alloc_macros(macros, strlen(name) + 1, strlen(value) + 1);
    strcpy(macros_str[macros], name);
    strcpy(macros_val[macros], value);
    macros++;
}

static void rm_macro(char* name) {
    if (strlen(name) < 1) {
        return; // cannot free, already freed
    }
    for (size_t i = 0; i < macros; i++) {
        char* macro = macros_str[i];
        if (strcmp(macro, name) == 0) {
            strcpy(macros_str[i], "");
            strcpy(macros_val[i], "");
            return;
        }
    }
}

static void parser_advance(Parser* p) {
    if (p->current.type != SP_EOF) {
        free_token(&p->previous);
        p->previous = p->current;
        p->current = next_token(p->lexer);
    }
}

static bool parser_match(Parser* p, TokenType type) {
    if (p->current.type == type) {
        parser_advance(p);
        return true;
    }
    return false;
}

static bool parser_check(Parser* p, TokenType type) {
    return p->current.type == type;
}

ASTNode* create_node(ASTNodeType type, Parser* p) {
    ASTNode* node = calloc(1, sizeof(ASTNode));
    node->type = type;
    node->line = p->current.line;
    node->col = p->current.column;
    node->children = NULL;
    node->child_count = 0;
    return node;
}

void add_child(ASTNode* parent, ASTNode* child) {
    parent->children = realloc(parent->children, sizeof(ASTNode*) * (parent->child_count + 1));
    parent->children[parent->child_count++] = child;
}

void free_ast(ASTNode* node) {
    if (!node) return;
    for (size_t i = 0; i < node->child_count; i++) {
        free_ast(node->children[i]);
    }
    free(node->children);
    switch(node->type) {
        case AST_INSTRUCTION:
            for(size_t i = 0; i < node->inst.operand_count; i++) {
                ASTOperand* op = node->inst.operands[i];
                
                if (op->type == OPERAND_LABEL) {
                    free(op->label);
                } else if (op->type == OPERAND_REGISTER) {
                    free(op->reg);
                } else if (op->type == OPERAND_IDENTIFIER) {
                    free_ast(op->identifier);
                } else if (op->type == OPERAND_MEMORY) {
                    for(size_t i = 0; i < op->mem_opr_count; i++) {
                        ASTOperand* opr = op->mem_addr[i];
                        
                        if (opr->type == OPERAND_LABEL) {
                            free(opr->label);
                        } else if (opr->type == OPERAND_REGISTER) {
                            free(opr->reg);
                        } else if (opr->type == OPERAND_IDENTIFIER) {
                            free_ast(opr->identifier);
                        }
                        free(opr);
                    }
                    free(op->mem_addr);
                }
                free(op);
            }
            free(node->inst.operands);
            break;
        case AST_DIRECTIVE:
            free(node->directive.arg);
            break;
        case AST_COMMENT:
            free(node->comment.value);
            break;
        case AST_LABEL:
            free(node->label.name);
            break;
        case AST_LITERAL:
            if (node->literal.type == LIT_STRING) {
                free(node->literal.str_val);
            }
            break;
        case AST_IDENTIFIER:
            free(node->identifier.name);
            break;
        case AST_DECLIDENTIFIER:
            free(node->decl_identifier.name);
            break;
        case AST_RESERVE:
            free(node->reserve.name);
            break;
        case AST_PROGRAM:
            free_macros();
            break;
        default:
            break;
    }
    free(node);
}

static ASTOperand* parse_operand(Parser* p) {
    if (parser_check(p, RBRACKET)) {parser_advance(p); return NULL; } // Probably a memory expression closing

    ASTOperand* op = calloc(1, sizeof(ASTOperand));

    if (parser_check(p, REGISTER)) {
        op->type = OPERAND_REGISTER;
        op->reg = (char*)calloc(strlen(p->current.lexeme) + 1, 1);
        op->reg[strlen(p->current.lexeme)] = '\0';
        pac_strdup(p->current.lexeme, op->reg);
        parser_advance(p);
    } else if (parser_check(p, LIT_INT)) {
        op->type = OPERAND_LIT_INT;
        op->int_val = strtoll(p->current.lexeme, NULL, 10);
        parser_advance(p);
    } else if (parser_check(p, LIT_BIN)) {
        op->type = OPERAND_LIT_INT;
        op->int_val = strtoll(p->current.lexeme, NULL, 2);
        parser_advance(p);
    } else if (parser_check(p, LIT_HEX)) {
        op->type = OPERAND_LIT_INT;
        op->int_val = strtoll(p->current.lexeme, NULL, 16);
        parser_advance(p);
    } else if (parser_check(p, LIT_FLOAT)) {
        op->type = OPERAND_LIT_FLOAT;
        op->float_val = strtod(p->current.lexeme, NULL);
        parser_advance(p);
    } else if (parser_check(p, LIT_CHAR)) {
        op->type = OPERAND_LIT_CHAR;
        op->int_val = (int64_t)p->current.lexeme[0];
        parser_advance(p);
    } else if (parser_check(p, OP_ADD)) {
        op->type = OPERAND_DISPLACEMENT;
        parser_advance(p);

        if (parser_check(p, LIT_INT)) {
            op->int_val = strtoll(p->current.lexeme, NULL, 10);
            parser_advance(p);
        } else if (parser_check(p, LIT_BIN)) {
            op->int_val = strtoll(p->current.lexeme, NULL, 2);
            parser_advance(p);
        } else if (parser_check(p, LIT_HEX)) {
            op->int_val = strtoll(p->current.lexeme, NULL, 16);
            parser_advance(p);
        } else if (parser_check(p, LIT_CHAR)) {
            op->int_val = (int64_t)p->current.lexeme[0];
            parser_advance(p);
        } else {
            PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an integer literal!");
            free_ast(p->root);
            exit(PAC_Error_UnexpectedToken);
        }
    } else if (parser_check(p, OP_SUB)) {
        op->type = OPERAND_DISPLACEMENT;
        parser_advance(p);

        if (parser_check(p, LIT_INT)) {
            op->int_val = 0 - strtoll(p->current.lexeme, NULL, 10);
            parser_advance(p);
        } else if (parser_check(p, LIT_BIN)) {
            op->int_val = 0 - strtoll(p->current.lexeme, NULL, 2);
            parser_advance(p);
        } else if (parser_check(p, LIT_HEX)) {
            op->int_val = 0 - strtoll(p->current.lexeme, NULL, 16);
            parser_advance(p);
        } else if (parser_check(p, LIT_CHAR)) {
            op->int_val = 0 - (int64_t)p->current.lexeme[0];
            parser_advance(p);
        } else {
            PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an integer literal!");
            free_ast(p->root);
            exit(PAC_Error_UnexpectedToken);
        }
    } else if (parser_check(p, FUNC_USE)) {
        ASTNode* identnode = parse_identifier(p);
        op->type = OPERAND_IDENTIFIER;
        op->identifier = identnode;
        parser_advance(p);
    } else if (parser_check(p, LABEL_DEF)) {
        op->type = OPERAND_LABEL;
        op->label = (char*)calloc(strlen(p->current.lexeme) + 1, 1);
        op->label[strlen(p->current.lexeme)] = '\0';
        pac_strdup(p->current.lexeme, op->label);
        parser_advance(p);
    } else if (parser_check(p, IDENTIFIER_TOK)) {
        ASTNode* identnode = parse_identifier(p);
        op->type = OPERAND_IDENTIFIER;
        op->identifier = identnode;
        parser_advance(p);
    } else if (parser_check(p, LBRACKET)) {
        // Probably some memory expression
        op->type = OPERAND_MEMORY;
        
        size_t memoprcount = 0; // Something is corrupting the other fields on malloc/realloc/calloc
        parser_advance(p);
        while (!parser_check(p, SP_EOF) && p->current.type != SEMICOLON && p->current.type != SP_EOL) {
            ASTOperand* opr = parse_operand(p);
            if (!opr) break;
            op->mem_addr = recalloc(op->mem_addr, memoprcount, memoprcount + 1, sizeof(ASTOperand*));
            op->mem_addr[memoprcount++] = opr;
        }
        op->mem_opr_count = memoprcount;
    } else {
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unexpected Token in Operand!");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }
    return op;
}

static ASTNode* parse_inst(Parser* p) {
    ASTNode* node = create_node(AST_INSTRUCTION, p);
    node->inst.opcode = p->current.type;
    parser_advance(p);

    while (!parser_check(p, SP_EOF) && p->current.type != SEMICOLON && p->current.type != SP_EOL) {
        ASTOperand* op = parse_operand(p);
        if (!op) break;
        node->inst.operands = realloc(node->inst.operands, sizeof(ASTOperand*) * (node->inst.operand_count + 1));
        node->inst.operands[node->inst.operand_count++] = op;

        if (parser_match(p, COMMA)) continue;
        else break;
    }
    return node;
}

static ASTNode* parse_label(Parser* p, bool make_macro) {
    ASTNode* node = create_node(AST_LABEL, p);
    node->label.name = (char*)malloc(strlen(p->current.lexeme) + 1);
    node->label.name[strlen(p->current.lexeme)] = '\0';
    if (in_func) {
        if (func_start[0] == 0) {
            funccount = 0;
            pac_strdup(p->current.lexeme, node->label.name);
            snprintf(func_start, sizeof(func_start), "%s", p->current.lexeme); // set the function start

            char label[256];
            snprintf(label, sizeof(label), "$%s", p->current.lexeme);
            if (make_macro) {
                new_macro(label, node->label.name);
                new_macro(node->label.name, NULL); // keep track!
            }
        } else {
            free(node->label.name);
            char label[512];

            // Already inside a function
            snprintf(label, sizeof(label), "%s_%llu", func_start, (unsigned long long)funccount);
            node->label.name = (char*)malloc(strlen(label) + 1);
            node->label.name[strlen(label)] = '\0';
            pac_strdup(label, node->label.name);

            snprintf(label, sizeof(label), "$%s.%s", func_start, p->current.lexeme);
            if (make_macro) {
                new_macro(label, node->label.name);
                new_macro(node->label.name, NULL); // keep track!
                char templabel[512];
                snprintf(templabel, sizeof(templabel), "%s_raw", node->label.name); // for using the mangled label to access to usage label
                new_macro(templabel, label);
            }
            funccount++;
        }
    } else {
        pac_strdup(p->current.lexeme, node->label.name);
        if (make_macro) new_macro(node->label.name, NULL); // ensure using the label works!
    }
    parser_advance(p);
    return node;
}

static ASTNode* parse_directive(Parser* p) {
    ASTNode* node = create_node(AST_DIRECTIVE, p);
    node->directive.type = p->current.type;
    node->directive.aligment = nxt_secalignment;
    node->directive.start = nxt_secstart;
    node->directive.size = nxt_secsize;
    nxt_secalignment = 0;
    nxt_secsize = -1; // N/A
    nxt_secstart = -1; // N/A
    parser_advance(p);
    if (p->current.type == IDENTIFIER_TOK || p->current.type == LIT_STRING) {
        node->directive.arg = (char*)malloc(strlen(p->current.lexeme) + 1);
        node->directive.arg[strlen(p->current.lexeme)] = '\0';
        pac_strdup(p->current.lexeme, node->directive.arg);
        parser_advance(p);
    }
    return node;
}

static ASTNode* parse_literal(Parser* p) {
    ASTNode* node = create_node(AST_LITERAL, p);
    ASTLiteral* op = &node->literal;
    if (parser_check(p, LIT_INT)) {
        node->literal.type = LIT_INT;
        op->int_val = strtoll(p->current.lexeme, NULL, 10);
        parser_advance(p);
    } else if (parser_check(p, LIT_BIN)) {
        node->literal.type = LIT_BIN;
        op->int_val = strtoll(p->current.lexeme, NULL, 2);
        parser_advance(p);
    } else if (parser_check(p, LIT_HEX)) {
        node->literal.type = LIT_HEX;
        op->int_val = strtoll(p->current.lexeme, NULL, 16);
        parser_advance(p);
    } else if (parser_check(p, LIT_FLOAT)) {
        node->literal.type = LIT_FLOAT;
        op->float_val = strtod(p->current.lexeme, NULL);
        parser_advance(p);
    } else if (parser_check(p, LIT_CHAR)) {
        node->literal.type = LIT_CHAR;
        op->int_val = (int64_t)p->current.lexeme[0];
        parser_advance(p);
    } else if (parser_check(p, LIT_STRING)) {
        node->literal.type = LIT_STRING;
        op->str_val = (char*)malloc(strlen(p->current.lexeme) + 1);
        op->str_val[strlen(p->current.lexeme)] = '\0';
        pac_strdup(p->current.lexeme, op->str_val);
        parser_advance(p);
    }
    return node;
}

static ASTNode* parse_identifier(Parser* p) {
    char* name = (char*)malloc(strlen(p->current.lexeme) + 1);
    name[strlen(p->current.lexeme)] = '\0';
    pac_strdup(p->current.lexeme, name);

    if (p->current.type == FUNC_USE) {
        free(name);

        int ret = 0;
        char* label = find_macro(p->current.lexeme, &ret);
        if (ret != 0) {
            free_ast(p->root);
            PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Function not found!");
            exit(PAC_Error_FunctionNotFound);
        }

        name = (char*)malloc(strlen(label) + 1);
        name[strlen(label)] = '\0';
        pac_strdup(label, name);
    }
    parser_advance(p);
    TokenType opt_specified_type = (TokenType)-1;
    if (parser_check(p, OP_NOT)) {
        parser_advance(p);
        if (p->current.type >= T_BYTE && p->current.type <= T_PTR) {
            parser_advance(p);
            opt_specified_type = p->current.type;
        }
    }

    if (p->current.type == OP_ASSIGN) {
        ASTNode* child = NULL;
        parser_advance(p);

        ASTNode* node = create_node(AST_DECLIDENTIFIER, p);
        node->decl_identifier.name = (char*)malloc(strlen(name) + 1);
        node->decl_identifier.name[strlen(name)] = '\0';
        pac_strdup(name, node->decl_identifier.name);
        node->decl_identifier.type = p->current.type;
        node->decl_identifier.opt_specified_type = opt_specified_type;

        if (p->current.type == IDENTIFIER_TOK) {
            child = parse_identifier(p);
            if (child->type == AST_LITERAL) { // Probably due to macro
                node->decl_identifier.type = child->literal.type;
            }
        } else if (p->current.type >= LIT_INT && p->current.type <= LIT_CHAR) {
            child = parse_literal(p);
        } else {
            free_ast(p->root);
            PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, name, strlen(name), "Unknown Value!");
            free(name);
            exit(PAC_Error_TypeResolutionFailed);
        }

        add_child(node, child);
        new_macro(name, NULL);
        free(name);
        return node;
    }

    int ret;
    char* value = find_macro(name, &ret);
    if (ret == 0) {
        ASTNode* node = create_node(AST_LITERAL, p);
        node->literal.type = LIT_STRING; // Only string for now
        node->literal.str_val = (char*)malloc(strlen(value) + 1);
        node->literal.str_val[strlen(value)] = '\0';
        pac_strdup(value, node->literal.str_val);
        free(name);
        return node;
    } else if (ret == -2) { // value found but NULL
        ASTNode* node = create_node(AST_IDENTIFIER, p);
        node->identifier.name = (char*)malloc(strlen(name) + 1);
        node->identifier.name[strlen(name)] = '\0';
        pac_strdup(name, node->identifier.name);
        free(name);
        return node;
    } else { // Error
        free_ast(p->root);
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, name, strlen(name), "Unknown Identifier!");
        free(name);
        exit(PAC_Error_InvalidIdentifier);
    }

    return NULL;
}

void parse_preprocessors(Parser* p) {
    if (p->current.type == PP_DEF) {
        parser_advance(p);
        if (p->current.type != IDENTIFIER_TOK) {
            free_ast(p->root);
            PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only define Identifiers!");
            exit(PAC_Error_InvalidIdentifier);
        }

        char* name = (char*)malloc(strlen(p->current.lexeme) + 1);
        name[strlen(p->current.lexeme)] = '\0';
        pac_strdup(p->current.lexeme, name);

        parser_advance(p);
        if (p->current.type < LIT_INT || p->current.type > LIT_CHAR) {
            free_ast(p->root);
            PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only define Identifiers with literal values!");
            exit(PAC_Error_InvalidIdentifier);
        }
        char value[256];
        if (parser_check(p, LIT_CHAR)) {
            snprintf(value, sizeof(value), "%c", *p->current.lexeme);
        } else if (parser_check(p, LIT_INT)) {
            long long out = strtoll(p->current.lexeme, NULL, 10);
            snprintf(value, sizeof(value), "%lld", out);
        } else if (parser_check(p, LIT_BIN)) {
            long long out = strtoll(p->current.lexeme, NULL, 2);
            snprintf(value, sizeof(value), "%lld", out);
        } else if (parser_check(p, LIT_HEX)) {
            long long out = strtoll(p->current.lexeme, NULL, 16);
            snprintf(value, sizeof(value), "%lld", out);
        } else if (parser_check(p, LIT_STRING)) {
            snprintf(value, sizeof(value), "%s", p->current.lexeme);
        } else if (parser_check(p, LIT_FLOAT)) {
            float out = strtof(p->current.lexeme, NULL);
            snprintf(value, sizeof(value), "%f", out);
        }

        new_macro(name, value);
        free(name);
        parser_advance(p);
    }
}

ASTNode* parse_reserve(Parser* p) {
    ASTNode* node = create_node(AST_RESERVE, p);
    parser_advance(p); // consume :res
    if (p->current.type != IDENTIFIER_TOK) {
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an Identifier!");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }
    node->reserve.name = (char*)malloc(strlen(p->current.lexeme) + 1);
    node->reserve.name[strlen(p->current.lexeme)] = '\0';
    pac_strdup(p->current.lexeme, node->reserve.name);

    parser_advance(p);

    if (p->current.type != OP_NOT) {
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected '!'");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }

    parser_advance(p);

    if (p->current.type < T_BYTE || p->current.type > T_PTR) {
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected a Type!");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }

    node->reserve.type = p->current.type;
    new_macro(node->reserve.name, NULL);
    parser_advance(p);
    return node;
}

void parse_symbols(Parser* p) {
    parser_advance(p);
    while (p->current.type != SP_EOF) {
        if (p->current.type == LABEL_DEF) {
            ASTNode* temp = parse_label(p, true);
            free_ast(temp);
            continue;
        } else if (p->current.type == FUNC_DEF) {
            parser_advance(p);
            
            ASTNode* temp;
            
            if (in_func) {
                temp = parse_label(p, true);
            } else {
                memset(func_start, 0, sizeof(func_start));
                in_func = true;
                temp = parse_label(p, true); // resolve func
            }
            free_ast(temp);
            continue;
        } else if (p->current.type == FUNC_END) {
            memset(func_start, 0, sizeof(func_start));
            parser_advance(p);
            in_func = false;
            continue;
        }
        parser_advance(p);
    }
    free_token(&p->current);
    free_token(&p->previous);
}

ASTNode* parse_program(Parser* p) {
    ASTNode* root = create_node(AST_PROGRAM, p);
    p->root = root;
    parser_advance(p);
    while (p->current.type != SP_EOF) {
        if (p->current.type == SP_EOL) {
            parser_advance(p);
            continue;
        }
        ASTNode* stmt = NULL;
        if (p->current.type >= ASM_MOV && p->current.type <= ASM_NOP) {
            stmt = parse_inst(p);
        } else if (p->current.type >= PP_DEF && p->current.type <= PP_UNDEF) {
            parse_preprocessors(p);
        } else if (p->current.type == LABEL_DEF) {
            stmt = parse_label(p, false);
        } else if (p->current.type == SECTION || p->current.type == GLOBAL) {
            stmt = parse_directive(p);
        } else if (p->current.type == COMMENT_LINE || p->current.type == COMMENT_BLOCK) {
            stmt = create_node(AST_COMMENT, p);
            stmt->comment.value = (char*)malloc(strlen(p->current.lexeme) + 1);
            stmt->comment.value[strlen(p->current.lexeme)] = '\0';
            pac_strdup(p->current.lexeme, stmt->comment.value);
            parser_advance(p);
        } else if (p->current.type == LIT_BIN || p->current.type == LIT_INT || p->current.type == LIT_HEX || p->current.type == LIT_FLOAT || p->current.type == LIT_CHAR || p->current.type == LIT_STRING) {
            stmt = parse_literal(p);
        } else if (p->current.type == IDENTIFIER_TOK) {
            stmt = parse_identifier(p);
        } else if (p->current.type == ALIGN) {
            parser_advance(p); // consume :align
            stmt = parse_literal(p); // parse literal
            if (stmt->type != AST_LITERAL) {
                PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':align'");
                free_ast(root);
                exit(PAC_Error_InvalidAlignment);
            } else if (stmt->literal.type != LIT_BIN && stmt->literal.type != LIT_INT && stmt->literal.type != LIT_HEX) {
                PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':align'");
                free_ast(root);
                exit(PAC_Error_InvalidAlignment);
            }
            nxt_secalignment = stmt->literal.int_val;
            free_ast(stmt);
            stmt = NULL;
        } else if (p->current.type == START_SEC) {
            parser_advance(p); // consume :start
            stmt = parse_literal(p); // parse literal
            if (stmt->type != AST_LITERAL) {
                PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':start'");
                free_ast(root);
                exit(PAC_Error_InvalidAlignment);
            } else if (stmt->literal.type != LIT_BIN && stmt->literal.type != LIT_INT && stmt->literal.type != LIT_HEX) {
                PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':start'");
                free_ast(root);
                exit(PAC_Error_InvalidAlignment);
            }
            nxt_secstart = stmt->literal.int_val;
            free_ast(stmt);
            stmt = NULL;
        } else if (p->current.type == SIZE_SEC) {
            parser_advance(p); // consume :size
            stmt = parse_literal(p); // parse literal
            if (stmt->type != AST_LITERAL) {
                PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer literal when using ':size'");
                free_ast(root);
                exit(PAC_Error_InvalidAlignment);
            } else if (stmt->literal.type != LIT_BIN && stmt->literal.type != LIT_INT && stmt->literal.type != LIT_HEX) {
                PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer literal when using ':size'");
                free_ast(root);
                exit(PAC_Error_InvalidAlignment);
            }
            nxt_secsize = stmt->literal.int_val;
            free_ast(stmt);
            stmt = NULL;
        } else if (p->current.type == RESERVE) {
            stmt = parse_reserve(p);
        } else if (p->current.type == FUNC_DEF) {
            parser_advance(p); // consume .func
            in_func = true;
            stmt = parse_label(p, false);
        } else if (p->current.type == FUNC_END) {
            parser_advance(p); // consume .endfunc
            in_func = false;
            char label[512];
            // Remove all labels
            for (size_t i = 0; i < funccount; i++) {
                snprintf(label, sizeof(label), "%s_%llu", func_start, (unsigned long long)i);
                rm_macro(label);
                snprintf(label, sizeof(label), "%s_%llu_raw", func_start, (unsigned long long)i);
                int ret = 0;
                char* usage_label = find_macro(label, &ret);
                if (ret == 0) {
                    rm_macro(usage_label);
                }
                rm_macro(label);
            }
        } else {
            PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unexpected token at top-level!");
            free_ast(root);
            exit(PAC_Error_UnexpectedToken);
        }

        if (stmt) add_child(root, stmt);
    }
    free_token(&p->current);
    free_token(&p->previous);
    return root;
}

Parser init_parser(Lexer* lex) {
    Parser p;
    memset(&p, 0, sizeof(Parser));
    p.lexer = lex;
    p.had_error = false;
    p.root = NULL;

    return p;
}

void ast_to_str(ASTNode* node, char* out, size_t maxsize) {
    ASTNodeType type = node->type;
    char operand[maxsize];
    switch (type) {
        case AST_INSTRUCTION:
            ASTOperand** operands = node->inst.operands;
            size_t operand_count = node->inst.operand_count;
            if (node->inst.opcode >= ASM_MOV && node->inst.opcode <= ASM_NOP) {
                if (node->inst.operand_count > 0) snprintf(out, maxsize, "[Instruction] %s", token_type_to_ogstr(node->inst.opcode));
                else snprintf(out, maxsize, "[Instruction] %s  ", token_type_to_ogstr(node->inst.opcode));
            }

            snprintf(operand, maxsize, "%s ", out);
            if (node->inst.opcode < ASM_MOV || node->inst.opcode > ASM_NOP) {
                snprintf(operand, maxsize, "%s", out);
            }
            
            for (size_t i = 0; i < operand_count; i++) {
                ASTOperand* opr = operands[i];
                switch (opr->type) {
                    case OPERAND_LABEL:
                        snprintf(out, maxsize, "%s%s, ", operand, opr->label);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_LIT_INT:
                        snprintf(out, maxsize, "%s%ld, ", operand, opr->int_val);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_LIT_CHAR:
                        snprintf(out, maxsize, "%s%ld, ", operand, opr->int_val);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_LIT_FLOAT:
                        snprintf(out, maxsize, "%s%f, ", operand, opr->float_val);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_LIT_DOUBLE:
                        snprintf(out, maxsize, "%s%f, ", operand, opr->float_val);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_REGISTER:
                        snprintf(out, maxsize, "%s%s, ", operand, opr->reg);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_IDENTIFIER:
                        char temp[256];
                        ast_to_str(opr->identifier, temp, sizeof(temp));
                        snprintf(out, maxsize, "%s%s  ", operand, temp); // ensure the removal process doesn't remove any info
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_DISPLACEMENT:
                        size_t operand_size = strlen(operand);
                        operand[operand_size - 1] = '+';
                        operand[operand_size - 2] = ' ';
                        snprintf(out, maxsize, "%s %ld, ", operand, opr->int_val);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    case OPERAND_MEMORY:
                        ASTNode temp_node = {
                            .child_count = 0,
                            .children = NULL,
                            .col = 0,
                            .line = 0,
                            .type = AST_INSTRUCTION,
                            .inst = {
                                .opcode = 0,
                                .operand_count = opr->mem_opr_count,
                                .operands = opr->mem_addr
                            }
                        };
                        ast_to_str(&temp_node, temp, sizeof(temp));
                        snprintf(out, maxsize, "%s[%s]  ", operand, temp);
                        snprintf(operand, maxsize, "%s", out);
                        break;
                    default:
                        strcpy(out, "Unknown Operand!");
                        return;
                }
            }
            operand[strlen(operand) - 1] = '\0'; // remove last ' '
            operand[strlen(operand) - 1] = '\0'; // remove last ','
            snprintf(out, maxsize, "%s", operand); // ensure the same
            return;
        case AST_DIRECTIVE:
            ASTDirective dir = node->directive;
            if (dir.aligment != 0) {
                snprintf(out, maxsize, "[Directive] [Alignment: %llu] %s", (long long unsigned)dir.aligment, dir.arg);
            } else {
                snprintf(out, maxsize, "[Directive] %s", dir.arg);
            }
            return;
        case AST_LABEL:
            snprintf(out, maxsize, "[Label] %s", node->label.name);
            return;
        case AST_COMMENT:
            snprintf(out, maxsize, "[Comment] %s", node->comment.value);
            return;
        case AST_LITERAL:
            ASTLiteral* op = &node->literal;
            TokenType type = op->type;
            switch (type) {
                case LIT_INT:
                    snprintf(out, maxsize, "[Literal.Int] %ld", op->int_val);
                    break;
                case LIT_BIN:
                    snprintf(out, maxsize, "[Literal.Bin] %ld", op->int_val);
                    break;
                case LIT_HEX:
                    snprintf(out, maxsize, "[Literal.Hex] %ld", op->int_val);
                    break;
                case LIT_FLOAT:
                    snprintf(out, maxsize, "[Literal.Float] %f", op->float_val);
                    break;
                case LIT_CHAR:
                    snprintf(out, maxsize, "[Literal.Char] %ld", op->int_val);
                    break;
                case LIT_STRING:
                    snprintf(out, maxsize, "[Literal.String] %s", op->str_val);
                    break;
                default:
                    strcpy(out, "Unknown Literal!");
                    break;
            }
            break;
        case AST_IDENTIFIER:
            snprintf(out, maxsize, "[Identifier] %s", node->identifier.name);
            return;
        case AST_DECLIDENTIFIER:
            if (node->child_count < 1) {
                strcpy(out, "Invalid DeclIdentifier!");
                return;
            }
            ast_to_str(node->children[0], operand, sizeof(operand));
            snprintf(out, maxsize, "[DeclIdentifier] %s => %s", node->decl_identifier.name, operand);
            return;
        case AST_RESERVE:
            snprintf(out, maxsize, "[Reserve] [%s] %s", token_type_to_str(node->reserve.type), node->reserve.name);
            return;
        default:
            strcpy(out, "Unknown!");
            return;
    }
}   