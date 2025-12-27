#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include <pac-lexer.h>
#include <pac-err.h>

Lexer init_lexer(const char* src, size_t len, const char* file) {
    Lexer lex;
    lex.src = src;
    lex.column = 1;
    lex.line = 1;
    lex.pos = 0;
    lex.len = len;
    lex.file = file;
    return lex;
}

// Utility
char peek(Lexer* lex) {
    if (lex->pos >= lex->len) // len = number of chars before '\0'
        return '\0';
    return lex->src[lex->pos];
}

char advance(Lexer* lex) {
    char c = peek(lex);
    if (c == '\0') return '\0';
    
    lex->pos++;
    if (c == '\n') {
        lex->line++;
        lex->column = 1;
    } else {
        lex->column++;
    }
    return c;
}

bool match(Lexer* lex, char expected) {
    if (lex->src[lex->pos] == expected) {
        advance(lex);
        return true;
    }
    return false;
}

// Tokens
Token make_token(Lexer* lex, TokenType type, const char* start, size_t len) {
    Token tk;
    tk.type = type;
    tk.lexeme = (char*)malloc(len + 1);
    strncpy(tk.lexeme, start, len);
    tk.lexeme[len] = '\0';
    tk.line = lex->line;
    tk.column = lex->column - (int)len + 1;
    return tk;
}

TokenType check_keyword(const char* str) {
    // Data types
    if (strcmp(str, "byte") == 0) return T_BYTE;
    if (strcmp(str, "short") == 0) return T_SHORT;
    if (strcmp(str, "int") == 0) return T_INT;
    if (strcmp(str, "long") == 0) return T_LONG;
    if (strcmp(str, "ubyte") == 0) return T_UBYTE;
    if (strcmp(str, "ushort") == 0) return T_USHORT;
    if (strcmp(str, "uint") == 0) return T_UINT;
    if (strcmp(str, "ulong") == 0) return T_ULONG;
    if (strcmp(str, "float") == 0) return T_FLOAT;
    if (strcmp(str, "double") == 0) return T_DOUBLE;
    if (strcmp(str, "ptr") == 0) return T_PTR;

    // Preprocessor
    if (strcmp(str, "@def") == 0) return PP_DEF;
    if (strcmp(str, "@undef") == 0) return PP_UNDEF;
    if (strcmp(str, "@if") == 0) return PP_IF;
    if (strcmp(str, "@elif") == 0) return PP_ELIF;
    if (strcmp(str, "@else") == 0) return PP_ELSE;
    if (strcmp(str, "@end") == 0) return PP_END;
    if (strcmp(str, "@inc") == 0) return PP_INC;

    // Labels, Functions, and more
    if (strcmp(str, ":section") == 0) return SECTION;
    if (strcmp(str, ":global") == 0) return GLOBAL;
    if (strcmp(str, ":align") == 0) return ALIGN;
    if (strcmp(str, ":res") == 0) return RESERVE;
    if (strcmp(str, ":start") == 0) return START_SEC;
    if (strcmp(str, ":size") == 0) return SIZE_SEC;
    if (strcmp(str, ".struct") == 0) return STRUCT_DEF;
    if (strcmp(str, ".endstruct") == 0) return STRUCT_END;
    if (strcmp(str, ".func") == 0) return FUNC_DEF;
    if (strcmp(str, ".endfunc") == 0) return FUNC_END;
    if (strcmp(str, ".type") == 0) return TYPEDEF;

    // Assembly instructions
    if (strcmp(str, "mov") == 0) return ASM_MOV;
    if (strcmp(str, "add") == 0) return ASM_ADD;
    if (strcmp(str, "sub") == 0) return ASM_SUB;
    if (strcmp(str, "mul") == 0) return ASM_MUL;
    if (strcmp(str, "div") == 0) return ASM_DIV;
    if (strcmp(str, "push") == 0) return ASM_PUSH;
    if (strcmp(str, "pop") == 0) return ASM_POP;
    if (strcmp(str, "call") == 0) return ASM_CALL;
    if (strcmp(str, "ret") == 0) return ASM_RET;
    if (strcmp(str, "jmp") == 0) return ASM_JMP;
    if (strcmp(str, "je") == 0) return ASM_JE;
    if (strcmp(str, "jne") == 0) return ASM_JNE;
    if (strcmp(str, "jg") == 0) return ASM_JG;
    if (strcmp(str, "jge") == 0) return ASM_JGE;
    if (strcmp(str, "jl") == 0) return ASM_JL;
    if (strcmp(str, "jle") == 0) return ASM_JLE;
    if (strcmp(str, "jz") == 0) return ASM_JZ;
    if (strcmp(str, "jnz") == 0) return ASM_JNZ;
    if (strcmp(str, "cmp") == 0) return ASM_CMP;
    if (strcmp(str, "test") == 0) return ASM_TEST;
    if (strcmp(str, "and") == 0) return ASM_AND;
    if (strcmp(str, "or") == 0) return ASM_OR;
    if (strcmp(str, "xor") == 0) return ASM_XOR;
    if (strcmp(str, "not") == 0) return ASM_NOT;
    if (strcmp(str, "shl") == 0) return ASM_SHL;
    if (strcmp(str, "shr") == 0) return ASM_SHR;
    if (strcmp(str, "syscall") == 0) return ASM_SYSCALL;
    if (strcmp(str, "lea") == 0) return ASM_LEA;
    if (strcmp(str, "load") == 0) return ASM_LOAD;
    if (strcmp(str, "store") == 0) return ASM_STORE;
    if (strcmp(str, "ashr") == 0) return ASM_ASHR;
    if (strcmp(str, "ashl") == 0) return ASM_ASHL;
    if (strcmp(str, "rotl") == 0) return ASM_ROTL;
    if (strcmp(str, "rotr") == 0) return ASM_ROTR;
    if (strcmp(str, "ucmp") == 0) return ASM_UCMP;
    if (strcmp(str, "movb") == 0) return ASM_MOVB;
    if (strcmp(str, "movw") == 0) return ASM_MOVW;
    if (strcmp(str, "movd") == 0) return ASM_MOVD;
    if (strcmp(str, "movq") == 0) return ASM_MOVQ;
    if (strcmp(str, "xchg") == 0) return ASM_XCHG;
    if (strcmp(str, "rreg") == 0) return ASM_RREG;
    if (strcmp(str, "push16") == 0) return ASM_PUSH16;
    if (strcmp(str, "push32") == 0) return ASM_PUSH32;
    if (strcmp(str, "push64") == 0) return ASM_PUSH64;
    if (strcmp(str, "pop16") == 0) return ASM_POP16;
    if (strcmp(str, "nand") == 0) return ASM_NAND;
    if (strcmp(str, "nor") == 0) return ASM_NOR;
    if (strcmp(str, "inc") == 0) return ASM_INC;
    if (strcmp(str, "dec") == 0) return ASM_DEC;
    if (strcmp(str, "mset") == 0) return ASM_MSET;
    if (strcmp(str, "mcmp") == 0) return ASM_MCMP;
    if (strcmp(str, "mcpy") == 0) return ASM_MCPY;
    if (strcmp(str, "exception") == 0) return ASM_EXCEPTION;
    if (strcmp(str, "b") == 0) return ASM_B;
    if (strcmp(str, "bl") == 0) return ASM_BL;
    if (strcmp(str, "br") == 0) return ASM_BR;
    if (strcmp(str, "blr") == 0) return ASM_BLR;
    if (strcmp(str, "ret_arm") == 0) return ASM_RET_ARM;
    if (strcmp(str, "cbz") == 0) return ASM_CBZ;
    if (strcmp(str, "cbnz") == 0) return ASM_CBNZ;
    if (strcmp(str, "tbz") == 0) return ASM_TBZ;
    if (strcmp(str, "tbnz") == 0) return ASM_TBNZ;
    if (strcmp(str, "b.eq") == 0) return ASM_B_EQ;
    if (strcmp(str, "b.ne") == 0) return ASM_B_NE;
    if (strcmp(str, "b.cs") == 0) return ASM_B_CS;
    if (strcmp(str, "b.cc") == 0) return ASM_B_CC;
    if (strcmp(str, "b.mi") == 0) return ASM_B_MI;
    if (strcmp(str, "b.pl") == 0) return ASM_B_PL;
    if (strcmp(str, "b.vs") == 0) return ASM_B_VS;
    if (strcmp(str, "b.vc") == 0) return ASM_B_VC;
    if (strcmp(str, "b.hi") == 0) return ASM_B_HI;
    if (strcmp(str, "b.ls") == 0) return ASM_B_LS;
    if (strcmp(str, "b.ge") == 0) return ASM_B_GE;
    if (strcmp(str, "b.lt") == 0) return ASM_B_LT;
    if (strcmp(str, "b.gt") == 0) return ASM_B_GT;
    if (strcmp(str, "b.le") == 0) return ASM_B_LE;
    if (strcmp(str, "adr") == 0) return ASM_ADR;
    if (strcmp(str, "adrp") == 0) return ASM_ADRP;
    if (strcmp(str, "ldr") == 0) return ASM_LDR;
    if (strcmp(str, "ldrb") == 0) return ASM_LDRB;
    if (strcmp(str, "ldrh") == 0) return ASM_LDRH;
    if (strcmp(str, "ldrsw") == 0) return ASM_LDRSW;
    if (strcmp(str, "ldp") == 0) return ASM_LDP;
    if (strcmp(str, "str") == 0) return ASM_STR;
    if (strcmp(str, "strb") == 0) return ASM_STRB;
    if (strcmp(str, "strh") == 0) return ASM_STRH;
    if (strcmp(str, "stp") == 0) return ASM_STP;
    if (strcmp(str, "ldxr") == 0) return ASM_LDXR;
    if (strcmp(str, "ldxrb") == 0) return ASM_LDXRB;
    if (strcmp(str, "ldxrh") == 0) return ASM_LDXRH;
    if (strcmp(str, "stxr") == 0) return ASM_STXR;
    if (strcmp(str, "stxrb") == 0) return ASM_STXRB;
    if (strcmp(str, "stxrh") == 0) return ASM_STXRH;
    if (strcmp(str, "csel") == 0) return ASM_CSEL;
    if (strcmp(str, "csinc") == 0) return ASM_CSINC;
    if (strcmp(str, "csinv") == 0) return ASM_CSINV;
    if (strcmp(str, "csneg") == 0) return ASM_CSNEG;
    if (strcmp(str, "cmn") == 0) return ASM_CMN;
    if (strcmp(str, "bfm") == 0) return ASM_BFM;
    if (strcmp(str, "sbfm") == 0) return ASM_SBFM;
    if (strcmp(str, "ubfm") == 0) return ASM_UBFM;
    if (strcmp(str, "extr") == 0) return ASM_EXTR;
    if (strcmp(str, "clz") == 0) return ASM_CLZ;
    if (strcmp(str, "cls") == 0) return ASM_CLS;
    if (strcmp(str, "rbit") == 0) return ASM_RBIT;
    if (strcmp(str, "rev") == 0) return ASM_REV;
    if (strcmp(str, "rev16") == 0) return ASM_REV16;
    if (strcmp(str, "rev32") == 0) return ASM_REV32;
    if (strcmp(str, "madd") == 0) return ASM_MADD;
    if (strcmp(str, "msub") == 0) return ASM_MSUB;
    if (strcmp(str, "smaddl") == 0) return ASM_SMADDL;
    if (strcmp(str, "smsubl") == 0) return ASM_SMSUBL;
    if (strcmp(str, "umaddl") == 0) return ASM_UMADDL;
    if (strcmp(str, "umsubl") == 0) return ASM_UMSUBL;
    if (strcmp(str, "sdiv") == 0) return ASM_SDIV;
    if (strcmp(str, "udiv") == 0) return ASM_UDIV;
    if (strcmp(str, "svc") == 0) return ASM_SVC;
    if (strcmp(str, "hvc") == 0) return ASM_HVC;
    if (strcmp(str, "smc") == 0) return ASM_SMC;
    if (strcmp(str, "brk") == 0) return ASM_BRK;
    if (strcmp(str, "hlt") == 0) return ASM_HLT;
    if (strcmp(str, "isb") == 0) return ASM_ISB;
    if (strcmp(str, "dsb") == 0) return ASM_DSB;
    if (strcmp(str, "dmb") == 0) return ASM_DMB;
    if (strcmp(str, "mrs") == 0) return ASM_MRS;
    if (strcmp(str, "msr") == 0) return ASM_MSR;
    if (strcmp(str, "pacia") == 0) return ASM_PACIA;
    if (strcmp(str, "pacib") == 0) return ASM_PACIB;
    if (strcmp(str, "pacda") == 0) return ASM_PACDA;
    if (strcmp(str, "pacdb") == 0) return ASM_PACDB;
    if (strcmp(str, "autia") == 0) return ASM_AUTIA;
    if (strcmp(str, "autib") == 0) return ASM_AUTIB;
    if (strcmp(str, "autda") == 0) return ASM_AUTDA;
    if (strcmp(str, "autdb") == 0) return ASM_AUTDB;
    if (strcmp(str, "fmov") == 0) return ASM_FMOV;
    if (strcmp(str, "fcmp") == 0) return ASM_FCMP;
    if (strcmp(str, "fcmpe") == 0) return ASM_FCMPE;
    if (strcmp(str, "fadd") == 0) return ASM_FADD;
    if (strcmp(str, "fsub") == 0) return ASM_FSUB;
    if (strcmp(str, "fmul") == 0) return ASM_FMUL;
    if (strcmp(str, "fdiv") == 0) return ASM_FDIV;
    if (strcmp(str, "fneg") == 0) return ASM_FNEG;
    if (strcmp(str, "fabs") == 0) return ASM_FABS;
    if (strcmp(str, "fsqrt") == 0) return ASM_FSQRT;

    if (strcmp(str, "nop") == 0) return ASM_NOP;

    return -1; // Not a keyword
}

Token lex_identifier(Lexer* lx) {
    size_t start = lx->pos - 1;
    while (isalnum(peek(lx)) || peek(lx) == '_' || peek(lx) == '$' || peek(lx) == '.') advance(lx);
    size_t length = lx->pos - start;
    char* text = (char*)malloc(length + 1);
    strncpy(text, &lx->src[start], length);
    text[length] = '\0';

    // Check for label usage / definition
    if (text[length - 1] == ':') {
        Token tk = make_token(lx, LABEL_DEF, &lx->src[start], length);
        free(text);
        return tk;
    }
    if (text[0] == '$') {
        Token tk = make_token(lx, FUNC_USE, &lx->src[start], length);
        free(text);
        return tk;
    }

    // Check if keyword
    TokenType type = check_keyword(text);
    if ((int)type != -1) {
        Token tk = make_token(lx, type, &lx->src[start], length);
        free(text);
        return tk;
    }

    Token tk = make_token(lx, IDENTIFIER_TOK, &lx->src[start], length); // fallback
    free(text);
    return tk;
}

void skip_whitespace(Lexer* lx) {
    while (isspace(peek(lx)) && peek(lx) != '\n') advance(lx);
}

Token next_token(Lexer* lx) {
    skip_whitespace(lx);
    char c = peek(lx);

    if (c == '\n') {advance(lx); return make_token(lx, SP_EOL, "\n", 0);}

    if (c == '\0') return make_token(lx, SP_EOF, "", 0); // EOF

    // Strings
    if (c == '"') {
        advance(lx); // consume opening "
        size_t start = lx->pos;
        bool multiline = false;
        while (peek(lx) != '"' && peek(lx) != '\0'){ 
            advance(lx);
            if (peek(lx) == '\\') {
                multiline = true;
            }
            if (peek(lx) == '\n' && !multiline) {
                break;
            } else if (peek(lx) == '\n' && multiline) multiline = false;
        }
        size_t len = lx->pos - start;
        char* str = (char*)malloc(len + 1);
        if (!str) {
            perror("Memory Allocation on Heap failed");
            exit(PAC_Error_MemoryAllocationFailed);
        }
        memcpy(str, &lx->src[start], len);
        str[len] = '\0';

        rmchr(str, '\\');

        if (peek(lx) != '"') {
            printf("%d\n", lx->line);
            PAC_ERRORF(lx->file, lx->line, lx->column, lx->src, lx->len, (char*)str, len, "Unterminated string literal\n");
            free(str);
            exit(PAC_Error_UnterminatedString);
        }
        advance(lx); // consume closing "
        Token tk = make_token(lx, LIT_STRING, str, len);
        free(str);
        return tk;
    }

    if (c == '\'') {
        advance(lx); // consume opening '
        char value[8] = {0}; // Temp buffer for safety

        if (peek(lx) == '\\') { // Handle escape sequence
            advance(lx); // skip '\'
            char esc = advance(lx);
            switch (esc) {
                case 'n': strcpy(value, "\n"); break;
                case 't': strcpy(value, "\t"); break;
                case 'r': strcpy(value, "\r"); break;
                case '\\': strcpy(value, "\\"); break;
                case '\'': strcpy(value, "'"); break;
                case '0': strcpy(value, "\0"); break;
                case 'x': {  // hex literal like '\x41'
                    char hexbuf[3] = {0};
                    hexbuf[0] = advance(lx);
                    hexbuf[1] = advance(lx);
                    unsigned char ch = (unsigned char)strtol(hexbuf, NULL, 16);
                    value[0] = ch;
                    break;
                }
                default:
                    value[0] = esc; // fallback
                    break;
            }
        } else {
            // Regular char (non-escaped)
            value[0] = advance(lx);
        }

        // Expect closing quote
        if (peek(lx) != '\'') {
            char c = peek(lx);
            PAC_ERRORF(lx->file, lx->line, lx->column, lx->src, lx->len, &c, 1, "Unterminated character literal\n");
            exit(PAC_Error_UnterminatedString);
        }

        advance(lx); // consume closing quote
        return make_token(lx, LIT_CHAR, value, strlen(value));
    }

    c = advance(lx); // normal

    // Preprocessor
    if (c == '@') {
        size_t start = lx->pos - 1;
        while (isalnum(peek(lx))) advance(lx);
        size_t length = lx->pos - start;
        char* text = strndup(&lx->src[start], length);
        TokenType typ = check_keyword(text);
        Token tk = make_token(lx, typ, &lx->src[start], length);
        free(text);
        return tk;
    }

    if (c == '%') {
        advance(lx); // consume '%'
        size_t start = lx->pos - 1;
        while (isalnum(peek(lx))) advance(lx);
        size_t length = lx->pos - start;
        char* text = strndup(&lx->src[start], length);
        Token tk = make_token(lx, REGISTER, &lx->src[start], length);
        free(text);
        return tk;
    }

    if (c == ':') {
        size_t start = lx->pos - 1;
        int ogline = lx->line;
        int ogcol = lx->column;
        while (isalnum(peek(lx))) advance(lx);
        size_t length = lx->pos - start;
        char* text = strndup(&lx->src[start], length);
        TokenType typ = check_keyword(text);
        Token tk;
        if ((int)typ != -1) {
            tk = make_token(lx, typ, &lx->src[start], length);
        } else {
            lx->line = ogline;
            lx->column = ogcol;
            lx->pos = start + 1;
            tk = make_token(lx, COLON, ";", 1);
        }
        free(text);
        return tk;
    }

    // Comments
    if (c == '/' && peek(lx) == '/') { // Line comment
        size_t start = lx->pos - 1;
        while (peek(lx) != '\n' && peek(lx) != '\0') advance(lx);
        return make_token(lx, COMMENT_LINE, &lx->src[start], lx->pos - start);
    }
    if (c == '/' && peek(lx) == '*') { // Block comment
        size_t start = lx->pos - 1;
        advance(lx); // skip *
        while (!(peek(lx) == '*' && lx->src[lx->pos + 1] == '/') && peek(lx) != '\0') advance(lx);
        advance(lx); advance(lx); // skip */
        return make_token(lx, COMMENT_BLOCK, &lx->src[start], lx->pos - start);
    }


    // Numbers
    if (isdigit(c)) {
        size_t start = lx->pos - 1;
        if (c == '0' && (peek(lx) == 'x' || peek(lx) == 'X')) { 
            // Hexadecimal literal
            advance(lx); // consume 'x'
            while (isxdigit(peek(lx))) advance(lx);
            return make_token(lx, LIT_HEX, &lx->src[start], lx->pos - start);
        } else if (c == '0' && (peek(lx) == 'b' || peek(lx) == 'B')) {
            // Binary literal
            advance(lx); // consume 'b'
            while (peek(lx) == '0' || peek(lx) == '1') advance(lx);
            return make_token(lx, LIT_BIN, &lx->src[start], lx->pos - start);
        } else {
            // Decimal literal
            while (isdigit(peek(lx))) advance(lx);
            return make_token(lx, LIT_INT, &lx->src[start], lx->pos - start);
        }
    }

    // Operators and punctuation
    switch (c) {
        // Maths
        case '+':
            if (match(lx, '+')) return make_token(lx, OP_INC, "++", 2);
            return make_token(lx, OP_ADD, "+", 1);

        case '-':
            if (match(lx, '-')) return make_token(lx, OP_DEC, "--", 2);
            return make_token(lx, OP_SUB, "-", 1);

        case '*':
            return make_token(lx, OP_MUL, "*", 1);

        case '/':
            return make_token(lx, OP_DIV, "/", 1);

        case '%':
            return make_token(lx, OP_MOD, "%", 1);

        // Bitwise / logical
        case '&':
            if (match(lx, '&')) return make_token(lx, OP_AND, "&&", 2); // logical AND
            return make_token(lx, OP_AND, "&", 1);

        case '|':
            if (match(lx, '|')) return make_token(lx, OP_OR, "||", 2); // logical OR
            return make_token(lx, OP_OR, "|", 1);

        case '^':
            return make_token(lx, OP_XOR, "^", 1);

        case '~':
            return make_token(lx, OP_NOT, "~", 1);

        // Comparison / assignment / shifts
        case '=':
            if (match(lx, '=')) return make_token(lx, OP_EQ, "==", 2);
            return make_token(lx, OP_ASSIGN, "=", 1);

        case '!':
            if (match(lx, '=')) return make_token(lx, OP_NE, "!=", 2);
            return make_token(lx, OP_NOT, "!", 1); // logical not

        case '<':
            if (match(lx, '<')) return make_token(lx, OP_SHL, "<<", 2);
            if (match(lx, '=')) return make_token(lx, OP_LE, "<=", 2);
            return make_token(lx, OP_LT, "<", 1);

        case '>':
            if (match(lx, '>')) return make_token(lx, OP_SHR, ">>", 2);
            if (match(lx, '=')) return make_token(lx, OP_GE, ">=", 2);
            return make_token(lx, OP_GT, ">", 1);

        // Punctuation / delimiters
        case '(':
            return make_token(lx, LPAREN, "(", 1);
        case ')':
            return make_token(lx, RPAREN, ")", 1);
        case '[':
            return make_token(lx, LBRACKET, "[", 1);
        case ']':
            return make_token(lx, RBRACKET, "]", 1);
        case '{':
            return make_token(lx, LBRACE, "{", 1);
        case '}':
            return make_token(lx, RBRACE, "}", 1);
        case ',':
            return make_token(lx, COMMA, ",", 1);
        case ';':
            return make_token(lx, SEMICOLON, ";", 1);
    }

    // Identifiers / Keywords / Labels
    if (isalpha(c) || c == '_' || c == '$' || c == '.') {
        Token id = lex_identifier(lx);
        if (peek(lx) == ':') {
            advance(lx);
            id.type = LABEL_DEF;
        }
        return id;
    }   

    return make_token(lx, UNKNOWN, &c, 1); // Unknown/Fallback
}

void free_token(Token* t) {
    if (t && t->lexeme)
        free(t->lexeme);
}

const char* token_type_to_str(TokenType type) {
    switch(type) {
        // Identifiers
        case IDENTIFIER_TOK: return "IDENTIFIER";
        // Data types
        case T_BYTE: return "T_BYTE";
        case T_SHORT: return "T_SHORT";
        case T_INT: return "T_INT";
        case T_LONG: return "T_LONG";
        case T_UBYTE: return "T_UBYTE";
        case T_USHORT: return "T_USHORT";
        case T_UINT: return "T_UINT";
        case T_ULONG: return "T_ULONG";
        case T_FLOAT: return "T_FLOAT";
        case T_DOUBLE: return "T_DOUBLE";
        case T_PTR: return "T_PTR";

        // Preprocessor
        case PP_DEF: return "PP_DEF";
        case PP_INC: return "PP_INC";
        case PP_IF: return "PP_IF";
        case PP_ELSE: return "PP_ELSE";
        case PP_ELIF: return "PP_ELIF";
        case PP_END: return "PP_END";
        case PP_UNDEF: return "PP_UNDEF";

        // Labels, Functions, and Sections
        case LABEL_DEF: return "LABEL_DEF";
        case FUNC_USE: return "FUNC_USE";
        case FUNC_DEF: return "FUNC_DEF";
        case FUNC_END: return "FUNC_END";
        case STRUCT_DEF: return "STRUCT_DEF";
        case STRUCT_END: return "STRUCT_END";
        case SECTION: return "SECTION";
        case GLOBAL: return "GLOBAL";
        case ALIGN: return "ALIGN";
        case RESERVE: return "RESERVE";
        case TYPEDEF: return "TYPEDEF";

        // Comments
        case COMMENT_LINE: return "COMMENT_LINE";
        case COMMENT_BLOCK: return "COMMENT_BLOCK";

        // Registers
        case REGISTER: return "REGISTER";

        // Maths / Operators
        case OP_ADD: return "OP_ADD";
        case OP_SUB: return "OP_SUB";
        case OP_MUL: return "OP_MUL";
        case OP_DIV: return "OP_DIV";
        case OP_MOD: return "OP_MOD";
        case OP_INC: return "OP_INC";
        case OP_DEC: return "OP_DEC";
        case OP_AND: return "OP_AND";
        case OP_OR: return "OP_OR";
        case OP_XOR: return "OP_XOR";
        case OP_NOT: return "OP_NOT";
        case OP_SHL: return "OP_SHL";
        case OP_SHR: return "OP_SHR";
        case OP_ASSIGN: return "OP_ASSIGN";
        case OP_EQ: return "OP_EQ";
        case OP_NE: return "OP_NE";
        case OP_LT: return "OP_LT";
        case OP_GT: return "OP_GT";
        case OP_LE: return "OP_LE";
        case OP_GE: return "OP_GE";

        // Assembly / Backend
        case ASM_MOV: return "ASM_MOV";
        case ASM_ADD: return "ASM_ADD";
        case ASM_SUB: return "ASM_SUB";
        case ASM_MUL: return "ASM_MUL";
        case ASM_DIV: return "ASM_DIV";
        case ASM_PUSH: return "ASM_PUSH";
        case ASM_POP: return "ASM_POP";
        case ASM_CALL: return "ASM_CALL";
        case ASM_RET: return "ASM_RET";
        case ASM_JMP: return "ASM_JMP";
        case ASM_JE: return "ASM_JE";
        case ASM_JNE: return "ASM_JNE";
        case ASM_JG: return "ASM_JG";
        case ASM_JGE: return "ASM_JGE";
        case ASM_JL: return "ASM_JL";
        case ASM_JLE: return "ASM_JLE";
        case ASM_CMP: return "ASM_CMP";
        case ASM_TEST: return "ASM_TEST";
        case ASM_AND: return "ASM_AND";
        case ASM_OR: return "ASM_OR";
        case ASM_XOR: return "ASM_XOR";
        case ASM_NOT: return "ASM_NOT";
        case ASM_SHL: return "ASM_SHL";
        case ASM_SHR: return "ASM_SHR";
        case ASM_SYSCALL: return "ASM_SYSCALL";
        case ASM_LEA: return "ASM_LEA";
        case ASM_LOAD: return "ASM_LOAD";
        case ASM_STORE: return "ASM_STORE";
        case ASM_ASHR: return "ASM_ASHR";
        case ASM_ASHL: return "ASM_ASHL";
        case ASM_ROTL: return "ASM_ROTL";
        case ASM_ROTR: return "ASM_ROTR";
        case ASM_UCMP: return "ASM_UCMP";
        case ASM_NOP: return "ASM_NOP";
        case ASM_NAND: return "ASM_NAND";
        case ASM_NOR: return "ASM_NOR";
        case ASM_XCHG: return "ASM_XCHG";
        case ASM_PUSH16: return "ASM_PUSH16";
        case ASM_POP16: return "ASM_POP16";
        case ASM_PUSH32: return "ASM_PUSH32";
        case ASM_POP32: return "ASM_POP32";
        case ASM_PUSH64: return "ASM_PUSH64";
        case ASM_POP64: return "ASM_POP64";
        case ASM_MOVB: return "ASM_MOVB";
        case ASM_MOVW: return "ASM_MOVW";
        case ASM_MOVD: return "ASM_MOVD";
        case ASM_MOVQ: return "ASM_MOVQ";
        case ASM_RREG: return "ASM_RREG";
        case ASM_MSET: return "ASM_MSET";
        case ASM_MCMP: return "ASM_MCMP";
        case ASM_MCPY: return "ASM_MCPY";
        case ASM_JZ: return "ASM_JZ";
        case ASM_JNZ: return "ASM_JNZ";
        case ASM_INC: return "ASM_INC";
        case ASM_DEC: return "ASM_DEC";
        case ASM_EXCEPTION: return "ASM_EXCEPTION";
        case ASM_B: return "ASM_B";
        case ASM_BL: return "ASM_BL";
        case ASM_BR: return "ASM_BR";
        case ASM_BLR: return "ASM_BLR";
        case ASM_RET_ARM: return "ASM_RET_ARM";
        case ASM_CBZ: return "ASM_CBZ";
        case ASM_CBNZ: return "ASM_CBNZ";
        case ASM_TBZ: return "ASM_TBZ";
        case ASM_TBNZ: return "ASM_TBNZ";
        case ASM_B_EQ: return "ASM_B_EQ";
        case ASM_B_NE: return "ASM_B_NE";
        case ASM_B_CS: return "ASM_B_CS";
        case ASM_B_CC: return "ASM_B_CC";
        case ASM_B_MI: return "ASM_B_MI";
        case ASM_B_PL: return "ASM_B_PL";
        case ASM_B_VS: return "ASM_B_VS";
        case ASM_B_VC: return "ASM_B_VC";
        case ASM_B_HI: return "ASM_B_HI";
        case ASM_B_LS: return "ASM_B_LS";
        case ASM_B_GE: return "ASM_B_GE";
        case ASM_B_LT: return "ASM_B_LT";
        case ASM_B_GT: return "ASM_B_GT";
        case ASM_B_LE: return "ASM_B_LE";
        case ASM_ADR: return "ASM_ADR";
        case ASM_ADRP: return "ASM_ADRP";
        case ASM_LDR: return "ASM_LDR";
        case ASM_LDRB: return "ASM_LDRB";
        case ASM_LDRH: return "ASM_LDRH";
        case ASM_LDRSW: return "ASM_LDRSW";
        case ASM_LDP: return "ASM_LDP";
        case ASM_STR: return "ASM_STR";
        case ASM_STRB: return "ASM_STRB";
        case ASM_STRH: return "ASM_STRH";
        case ASM_STP: return "ASM_STP";
        case ASM_LDXR: return "ASM_LDXR";
        case ASM_LDXRB: return "ASM_LDXRB";
        case ASM_LDXRH: return "ASM_LDXRH";
        case ASM_STXR: return "ASM_STXR";
        case ASM_STXRB: return "ASM_STXRB";
        case ASM_STXRH: return "ASM_STXRH";
        case ASM_CSEL: return "ASM_CSEL";
        case ASM_CSINC: return "ASM_CSINC";
        case ASM_CSINV: return "ASM_CSINV";
        case ASM_CSNEG: return "ASM_CSNEG";
        case ASM_CMN: return "ASM_CMN";
        case ASM_BFM: return "ASM_BFM";
        case ASM_SBFM: return "ASM_SBFM";
        case ASM_UBFM: return "ASM_UBFM";
        case ASM_EXTR: return "ASM_EXTR";
        case ASM_CLZ: return "ASM_CLZ";
        case ASM_CLS: return "ASM_CLS";
        case ASM_RBIT: return "ASM_RBIT";
        case ASM_REV: return "ASM_REV";
        case ASM_REV16: return "ASM_REV16";
        case ASM_REV32: return "ASM_REV32";
        case ASM_MADD: return "ASM_MADD";
        case ASM_MSUB: return "ASM_MSUB";
        case ASM_SMADDL: return "ASM_SMADDL";
        case ASM_SMSUBL: return "ASM_SMSUBL";
        case ASM_UMADDL: return "ASM_UMADDL";
        case ASM_UMSUBL: return "ASM_UMSUBL";
        case ASM_SDIV: return "ASM_SDIV";
        case ASM_UDIV: return "ASM_UDIV";
        case ASM_SVC: return "ASM_SVC";
        case ASM_HVC: return "ASM_HVC";
        case ASM_SMC: return "ASM_SMC";
        case ASM_BRK: return "ASM_BRK";
        case ASM_HLT: return "ASM_HLT";
        case ASM_ISB: return "ASM_ISB";
        case ASM_DSB: return "ASM_DSB";
        case ASM_DMB: return "ASM_DMB";
        case ASM_MRS: return "ASM_MRS";
        case ASM_MSR: return "ASM_MSR";
        case ASM_PACIA: return "ASM_PACIA";
        case ASM_PACIB: return "ASM_PACIB";
        case ASM_PACDA: return "ASM_PACDA";
        case ASM_PACDB: return "ASM_PACDB";
        case ASM_AUTIA: return "ASM_AUTIA";
        case ASM_AUTIB: return "ASM_AUTIB";
        case ASM_AUTDA: return "ASM_AUTDA";
        case ASM_AUTDB: return "ASM_AUTDB";
        case ASM_FMOV: return "ASM_FMOV";
        case ASM_FCMP: return "ASM_FCMP";
        case ASM_FCMPE: return "ASM_FCMPE";
        case ASM_FADD: return "ASM_FADD";
        case ASM_FSUB: return "ASM_FSUB";
        case ASM_FMUL: return "ASM_FMUL";
        case ASM_FDIV: return "ASM_FDIV";
        case ASM_FNEG: return "ASM_FNEG";
        case ASM_FABS: return "ASM_FABS";
        case ASM_FSQRT: return "ASM_FSQRT";

        // Literals
        case LIT_INT: return "LIT_INT";
        case LIT_HEX: return "LIT_HEX";
        case LIT_BIN: return "LIT_BIN";
        case LIT_FLOAT: return "LIT_FLOAT";
        case LIT_STRING: return "LIT_STRING";
        case LIT_CHAR: return "LIT_CHAR";

        // Punctuation
        case COMMA: return "COMMA";
        case COLON: return "COLON";
        case SEMICOLON: return "SEMICOLON";
        case LPAREN: return "LPAREN";
        case RPAREN: return "RPAREN";
        case LBRACKET: return "LBRACKET";
        case RBRACKET: return "RBRACKET";
        case LBRACE: return "LBRACE";
        case RBRACE: return "RBRACE";

        // Special
        case SP_EOF: return "SP_EOF";
        case SP_EOL: return "SP_EOL";

        default: return "UNKNOWN_TOKEN";
    }
}

const char* token_type_to_ogstr(TokenType type) {
    switch (type) {
        case T_BYTE: return "byte";
        case T_SHORT: return "short";
        case T_INT: return "int";
        case T_LONG: return "long";
        case T_UBYTE: return "ubyte";
        case T_USHORT: return "ushort";
        case T_UINT: return "uint";
        case T_ULONG: return "ulong";
        case T_FLOAT: return "float";
        case T_DOUBLE: return "double";
        case T_PTR: return "ptr";
        // Preprocessor
        case PP_DEF: return "@def";
        case PP_INC: return "@inc";
        case PP_IF: return "@if";
        case PP_ELSE: return "@else";
        case PP_ELIF: return "@elif";
        case PP_END: return "@end";
        case PP_UNDEF: return "@undef";

        // Labels, Functions, and Sections
        case FUNC_DEF: return ".func";
        case FUNC_END: return ".endfunc";
        case STRUCT_DEF: return ".struct";
        case STRUCT_END: return ".endstruct";
        case SECTION: return ":section";
        case GLOBAL: return ":global";
        case ALIGN: return ":align";
        case RESERVE: return ":res";
        case TYPEDEF: return ".type";

        // Comments
        case COMMENT_LINE: return "//";
        case COMMENT_BLOCK: return "/*";

        // Maths / Operators
        case OP_ADD: return "+";
        case OP_SUB: return "-";
        case OP_MUL: return "*";
        case OP_DIV: return "/";
        case OP_MOD: return "%";
        case OP_INC: return "++";
        case OP_DEC: return "--";
        case OP_AND: return "&";
        case OP_OR: return "|";
        case OP_XOR: return "^";
        case OP_NOT: return "!";
        case OP_SHL: return "<<";
        case OP_SHR: return ">>";
        case OP_ASSIGN: return "=";
        case OP_EQ: return "==";
        case OP_NE: return "!=";
        case OP_LT: return "<";
        case OP_GT: return ">";
        case OP_LE: return "<=";
        case OP_GE: return ">=";

        // Assembly / Backend
        case ASM_MOV: return "mov";
        case ASM_ADD: return "add";
        case ASM_SUB: return "sub";
        case ASM_MUL: return "mul";
        case ASM_DIV: return "div";
        case ASM_PUSH: return "push";
        case ASM_POP: return "pop";
        case ASM_CALL: return "call";
        case ASM_RET: return "ret";
        case ASM_JMP: return "jmp";
        case ASM_JE: return "je";
        case ASM_JNE: return "jne";
        case ASM_JG: return "jg";
        case ASM_JGE: return "jge";
        case ASM_JL: return "jl";
        case ASM_JLE: return "jle";
        case ASM_CMP: return "cmp";
        case ASM_TEST: return "test";
        case ASM_AND: return "and";
        case ASM_OR: return "or";
        case ASM_XOR: return "xor";
        case ASM_NOT: return "not";
        case ASM_SHL: return "shl";
        case ASM_SHR: return "shr";
        case ASM_SYSCALL: return "syscall";
        case ASM_LEA: return "lea";
        case ASM_LOAD: return "load";
        case ASM_STORE: return "store";
        case ASM_ASHR: return "ashr";
        case ASM_ASHL: return "ashl";
        case ASM_ROTL: return "rotl";
        case ASM_ROTR: return "rotr";
        case ASM_UCMP: return "ucmp";
        case ASM_NAND: return "nand";
        case ASM_NOR: return "nor";
        case ASM_INC: return "inc";
        case ASM_DEC: return "dec";
        case ASM_PUSH16: return "push16";
        case ASM_POP16: return "pop16";
        case ASM_PUSH32: return "push32";
        case ASM_POP32: return "pop32";
        case ASM_PUSH64: return "push64";
        case ASM_POP64: return "pop64";
        case ASM_MOVB: return "movb";
        case ASM_MOVW: return "movw";
        case ASM_MOVD: return "movd";
        case ASM_MOVQ: return "movq";
        case ASM_JZ: return "jz";
        case ASM_JNZ: return "jnz";
        case ASM_RREG: return "rreg";
        case ASM_XCHG: return "xchg";
        case ASM_MSET: return "mset";
        case ASM_MCMP: return "mcmp";
        case ASM_MCPY: return "mcpy";
        case ASM_EXCEPTION: return "exception";
        case ASM_B: return "b";
        case ASM_BL: return "bl";
        case ASM_BR: return "br";
        case ASM_BLR: return "blr";
        case ASM_RET_ARM: return "ret";
        case ASM_CBZ: return "cbz";
        case ASM_CBNZ: return "cbnz";
        case ASM_TBZ: return "tbz";
        case ASM_TBNZ: return "tbnz";
        case ASM_B_EQ: return "b.eq";
        case ASM_B_NE: return "b.ne";
        case ASM_B_CS: return "b.cs";
        case ASM_B_CC: return "b.cc";
        case ASM_B_MI: return "b.mi";
        case ASM_B_PL: return "b.pl";
        case ASM_B_VS: return "b.vs";
        case ASM_B_VC: return "b.vc";
        case ASM_B_HI: return "b.hi";
        case ASM_B_LS: return "b.ls";
        case ASM_B_GE: return "b.ge";
        case ASM_B_LT: return "b.lt";
        case ASM_B_GT: return "b.gt";
        case ASM_B_LE: return "b.le";
        case ASM_ADR: return "adr";
        case ASM_ADRP: return "adrp";
        case ASM_LDR: return "ldr";
        case ASM_LDRB: return "ldrb";
        case ASM_LDRH: return "ldrh";
        case ASM_LDRSW: return "ldrsw";
        case ASM_LDP: return "ldp";
        case ASM_STR: return "str";
        case ASM_STRB: return "strb";
        case ASM_STRH: return "strh";
        case ASM_STP: return "stp";
        case ASM_LDXR: return "ldxr";
        case ASM_LDXRB: return "ldxrb";
        case ASM_LDXRH: return "ldxrh";
        case ASM_STXR: return "stxr";
        case ASM_STXRB: return "stxrb";
        case ASM_STXRH: return "stxrh";
        case ASM_CSEL: return "csel";
        case ASM_CSINC: return "csinc";
        case ASM_CSINV: return "csinv";
        case ASM_CSNEG: return "csneg";
        case ASM_CMN: return "cmn";
        case ASM_BFM: return "bfm";
        case ASM_SBFM: return "sbfm";
        case ASM_UBFM: return "ubfm";
        case ASM_EXTR: return "extr";
        case ASM_CLZ: return "clz";
        case ASM_CLS: return "cls";
        case ASM_RBIT: return "rbit";
        case ASM_REV: return "rev";
        case ASM_REV16: return "rev16";
        case ASM_REV32: return "rev32";
        case ASM_MADD: return "madd";
        case ASM_MSUB: return "msub";
        case ASM_SMADDL: return "smaddl";
        case ASM_SMSUBL: return "smsubl";
        case ASM_UMADDL: return "umaddl";
        case ASM_UMSUBL: return "umsubl";
        case ASM_SDIV: return "sdiv";
        case ASM_UDIV: return "udiv";
        case ASM_SVC: return "svc";
        case ASM_HVC: return "hvc";
        case ASM_SMC: return "smc";
        case ASM_BRK: return "brk";
        case ASM_HLT: return "hlt";
        case ASM_ISB: return "isb";
        case ASM_DSB: return "dsb";
        case ASM_DMB: return "dmb";
        case ASM_MRS: return "mrs";
        case ASM_MSR: return "msr";
        case ASM_PACIA: return "pacia";
        case ASM_PACIB: return "pacib";
        case ASM_PACDA: return "pacda";
        case ASM_PACDB: return "pacdb";
        case ASM_AUTIA: return "autia";
        case ASM_AUTIB: return "autib";
        case ASM_AUTDA: return "autda";
        case ASM_AUTDB: return "autdb";
        case ASM_FMOV: return "fmov";
        case ASM_FCMP: return "fcmp";
        case ASM_FCMPE: return "fcmpe";
        case ASM_FADD: return "fadd";
        case ASM_FSUB: return "fsub";
        case ASM_FMUL: return "fmul";
        case ASM_FDIV: return "fdiv";
        case ASM_FNEG: return "fneg";
        case ASM_FABS: return "fabs";
        case ASM_FSQRT: return "fsqrt";
        
        case ASM_NOP: return "nop";

        // Punctuation
        case COMMA: return ",";
        case COLON: return ":";
        case SEMICOLON: return ";";
        case LPAREN: return "(";
        case RPAREN: return ")";
        case LBRACKET: return "[";
        case RBRACKET: return "]";
        case LBRACE: return "{";
        case RBRACE: return "}";

        // Special
        case SP_EOF: return "SP_EOF";
        case SP_EOL: return "SP_EOL";
        default: return "unknown";
    }
}
