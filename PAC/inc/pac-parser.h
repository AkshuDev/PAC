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
    AST_COMMENT,
    AST_DECLIDENTIFIER,
    AST_RESERVE,
} ASTNodeType;

typedef enum {
    OPERAND_REGISTER,
    OPERAND_LIT_INT,
    OPERAND_LIT_FLOAT,
    OPERAND_LIT_DOUBLE,
    OPERAND_LIT_CHAR,
    OPERAND_LABEL,
    OPERAND_MEMORY,
    OPERAND_IDENTIFIER,
    OPERAND_DISPLACEMENT,
} OperandType;

struct ASTNode;
typedef struct ASTOperand {
    OperandType type;
    union {
        char* reg; // Register name
        int64_t int_val; // Literal integer value
        double float_val; // Literal float value
        char* label; // Label name
        struct ASTOperand** mem_addr; // Memory expression
        struct ASTNode* identifier; // Identifier
    };
    size_t mem_opr_count;
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
    size_t aligment;
    int64_t start;
    int64_t size;
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

typedef struct ASTDeclIdentifier {
    char* name;
    TokenType type;
    TokenType opt_specified_type;
} ASTDeclIdentifier;

typedef struct ASTComment {
    char* value;
} ASTComment;

typedef struct ASTReserve {
    char* name;
    TokenType type;
} ASTReserve;

typedef struct ASTNode {
    ASTNodeType type;
    union {
        ASTInstruction inst;
        ASTLabel label;
        ASTDirective directive;
        ASTOperand operand;
        ASTLiteral literal;
        ASTIdentifier identifier;
        ASTComment comment;
        ASTDeclIdentifier decl_identifier;
        ASTReserve reserve;
    };
    int line; 
    int col;
    struct ASTNode** children;
    size_t child_count;
} ASTNode;

typedef struct {
    Lexer* lexer;
    Token current;
    Token previous;
    bool had_error;
    ASTNode* root;
} Parser;

ASTNode* create_node(ASTNodeType type, Parser* p);
void add_child(ASTNode* parent, ASTNode* child);
void free_ast(ASTNode* node);

void parse_symbols(Parser* p);
ASTNode* parse_program(Parser* p);
Parser init_parser(Lexer* lex);
void ast_to_str(ASTNode* node, char* out, size_t maxsize);