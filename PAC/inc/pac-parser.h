#pragma once

#define PAC_PARSER

#include <stdint.h>
#include <pac-lexer.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    AST_PROGRAM,
    AST_INSTRUCTION,
    AST_LABEL,
    AST_DIRECTIVE,
    AST_OPERAND,
    AST_LITERAL,
    AST_IDENTIFIER,
} ASTNodeType;

typedef enum {
    OPERAND_REGISTER,
    OPERAND_LITERAL,
    OPERAND_LABEL,
    OPERAND_MEMORY,
} OperandType;

struct ASTNode;
typedef struct ASTOperand {
    OperandType type;
    union {
        char* reg; // Register name
        int64_t int_val; // Literal integer value
        double float_val; // Literal float value
        char* label; // Label name
        struct ASTNode* mem_addr; // Memory expression
    };
} ASTOperand;

typedef struct ASTInstruction {
    TokenType opcode; // The ASM_* token type from lexer
    ASTOperand** operands; // Array of operand pointers
    size_t operand_count;
} ASTInstruction;

typedef struct ASTLabel {
    char* name;
} ASTLabel;

typedef struct ASTDirective {
    TokenType type;
    char* arg;
} ASTDirective;

typedef struct ASTLiteral {
    TokenType type;
    union {
        int64_t int_val;
        double float_val;
        char* str_val;
    };
} ASTLiteral;

typedef struct ASTIdentifier {
    char* name;
} ASTIdentifier;

typedef struct ASTNode {
    ASTNodeType type;
    union {
        ASTInstruction inst;
        ASTLabel label;
        ASTDirective directive;
        ASTOperand operand;
        ASTLiteral literal;
        ASTIdentifier identifer;
    };
    struct ASTNode** children;
    size_t child_count;
} ASTNode;

typedef struct {
    Lexer* lexer;
    Token current;
    Token previous;
    bool had_error;
} Parser;

ASTNode* create_node(ASTNodeType type);
void add_child(ASTNode* parent, ASTNode* child);
void free_ast(ASTNode* node);

ASTNode* parse_program(Parser* p);
Parser init_parser(Lexer* lex);