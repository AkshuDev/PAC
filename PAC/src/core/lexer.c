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
        case ASM_NOP: return "ASM_NOP";

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