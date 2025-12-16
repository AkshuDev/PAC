#pragma once

#define PAC_LEXER

typedef enum {
    // identifiers
    IDENTIFIER_TOK,
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
    T_ARRAY,
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
    FUNC_USE, // $func
    FUNC_DEF, // .func
    FUNC_END, // .endfunc
    STRUCT_DEF, // .struct
    STRUCT_END, // .endstruct
    SECTION, // :section
    GLOBAL, // :global
    ALIGN, // :align
    RESERVE, // :res (for bss section only)
    START_SEC, // :start
    SIZE_SEC, // :size
    TYPEDEF, // .type
    // Registers
    REGISTER,
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
    ASM_MOVB,
    ASM_MOVW,
    ASM_MOVD,
    ASM_MOVQ,
    ASM_XCHG,
    ASM_RREG,
    ASM_ADD,
    ASM_SUB,
    ASM_MUL,
    ASM_DIV,
    ASM_PUSH,
    ASM_POP,
    ASM_PUSH16,
    ASM_POP16,
    ASM_PUSH32,
    ASM_POP32,
    ASM_PUSH64,
    ASM_POP64,
    ASM_CALL,
    ASM_RET,
    ASM_JMP,
    ASM_JE,
    ASM_JNE,
    ASM_JZ,
    ASM_JNZ,
    ASM_JG,
    ASM_JGE,
    ASM_JL,
    ASM_JLE,
    ASM_CMP,
    ASM_UCMP,
    ASM_TEST,
    ASM_AND,
    ASM_NAND,
    ASM_OR,
    ASM_NOR,
    ASM_XOR,
    ASM_NOT,
    ASM_SHL,
    ASM_SHR,
    ASM_SYSCALL,
    ASM_LEA,
    ASM_LOAD,
    ASM_STORE,
    ASM_ASHR, // Arithmetic Shift Right
    ASM_ASHL,
    ASM_ROTL, // Rotate Left
    ASM_ROTR,
    ASM_INC,
    ASM_DEC,
    ASM_MSET,
    ASM_MCPY,
    ASM_MCMP,
    ASM_EXCEPTION,
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
    SP_EOL,
    UNKNOWN,
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
    size_t len;
    const char* file;
} Lexer;

Lexer init_lexer(const char* src, size_t len, const char* file);
void free_token(Token* t);
Token next_token(Lexer* lx);
const char* token_type_to_str(TokenType type);
const char* token_type_to_ogstr(TokenType type);
