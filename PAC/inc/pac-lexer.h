#pragma once

typedef enum {
    // Data types
    T_BYTE,
    T_SHORT,
    T_INT,
    T_LONG,
    T_UBYTE,
    T_USHORT,
    T_UINT,
    T_ULONG,
    T_FLOAT,
    T_DOUBLE,
    T_PTR,
    // Preprocessor
    PP_DEF, // @def
    PP_INC, // @inc
    PP_IF, // @if
    PP_ELSE, // @else
    PP_ELIF, // @elif
    PP_END, // @end
    PP_UNDEF, // @undef
    // Labels, Functions, and Sections
    LABEL_DEF, // label:
    LABEL_USE, // $label
    FUNC_DEF, // .func
    FUNC_END, // .endfunc
    STRUCT_DEF, // .struct
    STRUCT_END, // .endstruct
    SECTION, // :section
    GLOBAL, // :global
    // Comments
    COMMENT_LINE, // //
    COMMENT_BLOCK, // /**/
    // Maths
    OP_ADD, // +
    OP_SUB, // -
    OP_MUL, // *
    OP_DIV, // /
    OP_MOD, // %
    OP_INC, // ++
    OP_DEC, // --
    OP_AND, // &
    OP_OR, // |
    OP_XOR, // ^
    OP_NOT, // ~
    OP_SHL, // <<
    OP_SHR, // >>
    OP_ASSIGN, // =
    OP_EQ, // ==
    OP_NE, // !=
    OP_LT, // <
    OP_GT, // >
    OP_LE, // <=
    OP_GE, // >=

    // Assembly / Backend Keywords
    ASM_MOV,
    ASM_ADD,
    ASM_SUB,
    ASM_MUL,
    ASM_DIV,
    ASM_PUSH,
    ASM_POP,
    ASM_CALL,
    ASM_RET,
    ASM_JMP,
    ASM_JE,
    ASM_JNE,
    ASM_JG,
    ASM_JGE,
    ASM_JL,
    ASM_JLE,
    ASM_CMP,
    ASM_TEST,
    ASM_AND,
    ASM_OR,
    ASM_XOR,
    ASM_NOT,
    ASM_SHL,
    ASM_SHR,
    ASM_NOP,
    // Literals
    LIT_INT,
    LIT_HEX,
    LIT_BIN,
    LIT_FLOAT,
    LIT_STRING,
    LIT_CHAR,
    // Punctuation
    COMMA, // ,
    COLON, // :
    SEMICOLON, // ;
    LPAREN, // (
    RPAREN, // )
    LBRACKET, // [
    RBRACKET, // ]
    LBRACE, // {
    RBRACE, // }
    // Special
    SP_EOF,
} TokenType;

typedef struct {
    TokenType type;
    char* lexeme;
    int line;
    int column;
} Token;

typedef struct {
    const char* src;
    size_t pos;
    int line;
    int column;
} Lexer;

Lexer init_lexer(const char* src);
void free_token(Token* t);
Token next_token(Lexer* lx);
const char* token_type_to_str(TokenType type);