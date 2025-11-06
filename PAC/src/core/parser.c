#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <pac-lexer.h>
#include <pac-parser.h>
#include <pac-err.h>

static void parser_advance(Parser* p);
static bool parser_match(Parser* p, TokenType type);
static bool parser_check(Parser* p, TokenType type);

static ASTNode* parse_inst(Parser* p);
static ASTNode* parse_label(Parser* p);
static ASTNode* parse_directive(Parser* p);
static ASTOperand* parse_operand(Parser* p);

static void parser_advance(Parser* p) {
    if (p->current.type != SP_EOF) {
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

ASTNode* create_node(ASTNodeType type) {
    ASTNode* node = calloc(1, sizeof(ASTNode));
    node->type = type;
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
    free(node);
}

static ASTOperand* parse_operand(Parser* p) {
    ASTOperand* op = calloc(1, sizeof(ASTOperand));

    if (parser_check(p, IDENTIFIER_TOK)) {
        op->type = OPERAND_REGISTER;
        pac_strdup(p->current.lexeme, op->reg);
        parser_advance(p);
    } else if (parser_check(p, LIT_INT)) {
        op->type = OPERAND_LITERAL;
        op->int_val = strtoll(p->current.lexeme, NULL, 10);
        parser_advance(p);
    } else if (parser_check(p, LIT_BIN)) {
        op->type = OPERAND_LITERAL;
        op->int_val = strtoll(p->current.lexeme, NULL, 2);
        parser_advance(p);
    } else if (parser_check(p, LIT_HEX)) {
        op->type = OPERAND_LITERAL;
        op->int_val = strtoll(p->current.lexeme, NULL, 16);
        parser_advance(p);
    } else if (parser_check(p, LIT_FLOAT)) {
        op->type = OPERAND_LITERAL;
        op->float_val = strtod(p->current.lexeme, NULL);
        parser_advance(p);
    } else if (parser_check(p, LIT_CHAR)) {
        op->type = OPERAND_LITERAL;
        op->int_val = (int64_t)p->current.lexeme[0];
        parser_advance(p);
    } else if (parser_check(p, LABEL_USE)) {
        op->type = OPERAND_LABEL;
        pac_strdup(p->current.lexeme, op->label);
        parser_advance(p);
    } else if (parser_check(p, LABEL_DEF)) {
        op->type = OPERAND_LABEL;
        pac_strdup(p->current.lexeme, op->label);
        parser_advance(p);
    } else {
        pac_diag(PAC_ERROR, p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unexpected Token in Operand!");
        free(op);
        exit(PAC_Error_UnexpectedToken);
    }
}

static ASTNode* parse_inst(Parser* p) {
    ASTNode* node = create_node(AST_INSTRUCTION);
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

static ASTNode* parse_label(Parser* p) {
    ASTNode* node = create_node(AST_LABEL);
    pac_strdup(p->current.lexeme, node->label.name);
    parser_advance(p);
    return node;
}

static ASTNode* parse_directive(Parser* p) {
    ASTNode* node = create_node(AST_DIRECTIVE);
    node->directive.type = p->current.type;
    parser_advance(p);
    if (p->current.type == IDENTIFIER_TOK || p->current.type == LIT_STRING) {
        pac_strdup(node->directive.arg, p->current.lexeme);
        parser_advance(p);
    }
    return node;
}

ASTNode* parse_program(Parser* p) {
    ASTNode* root = create_node(AST_PROGRAM);
    parser_advance(p);
    while (p->current.type != SP_EOF) {
        if (p->current.type == SP_EOL) continue;
        ASTNode* stmt = NULL;
        if (p->current.type >= ASM_MOV && p->current.type <= ASM_NOP) {
            stmt = parse_inst(p);
        } else if (p->current.type == LABEL_DEF) {
            stmt = parse_label(p);
        } else if (p->current.type == PP_DEF || p->current.type == SECTION || p->current.type == GLOBAL) {
            stmt = parse_directive(p);
        } else {
            pac_diag(PAC_ERROR, p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unexpected token at top-level!");
            free(root);
            exit(PAC_Error_UnexpectedToken);
        }

        if (stmt) add_child(root, stmt);
    }
    return root;
}

Parser init_parser(Lexer* lex) {
    Parser p;
    memset(&p, 0, sizeof(Parser));
    p.lexer = lex;
    p.had_error = false;
    parser_advance(&p);
    return p;
}