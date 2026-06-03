#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <pac-lexer.h>
#include <pac-parser.h>
#include <pac-err.h>
#include <pac-extra.h>

#define parser_check(p, chktype) (p->current.type == chktype)

enum p_macro_types {
	MACRO_TYPE_UNKNOWN = 0,
	MACRO_TYPE_USER_MACRO,
	MACRO_TYPE_IDENTIFIER,
	MACRO_TYPE_NTYPE // "MACRO" is a NEW-Type defined by USER
};

struct p_macro {
	char* name;
	char* value;
	
	bool valid;
	bool auto_gen;

	int line;
	int col;
	const char* file;

	enum p_macro_types type;
};

#define MACROS_ALLOC_STEP 16

static struct p_macro* macros = NULL;
static size_t macro_count = 0;
static size_t macro_cap = 0;

static size_t nxt_secalignment = 0;
static int64_t nxt_secstart = -1;
static int64_t nxt_secsize = -1;

static size_t funccount = 0;
static bool in_func = false;
static char func_start[256];

static ASTNode* parse_identifier(Parser* p, bool only_macros, bool add_macros, char* prefix);

static void free_macros() {
    for (size_t i = 0; i < macro_count; i++) {
		struct p_macro* m = &macros[i];
        if (m->name != NULL) free(m->name);
        if (m->value != NULL) free(m->value);
    }
    macro_count = 0;
	if (macros) free(macros);
	macro_cap = 0;
}

static const char* alloc_macros(size_t index, size_t sizename, size_t sizeval) {
	if (index >= macro_cap && macro_cap > 0) {
		struct p_macro* nm = realloc(macros, sizeof(struct p_macro) * (macro_cap + MACROS_ALLOC_STEP));
		if (!nm) {
			return "Failed to allocate for a new MACRO/SYMBOL/IDENTIFIER/ETC";
		}
		macros = nm;
		macro_cap += MACROS_ALLOC_STEP;
	} else if (index >= macro_cap && macro_cap <= 0) {
		macros = malloc(sizeof(struct p_macro) * MACROS_ALLOC_STEP);
		if (!macros) {
			return "Failed to allocate for a new MACRO/SYMBOL/IDENTIFIER/ETC";
		}
		macro_cap = MACROS_ALLOC_STEP;
	}
	struct p_macro* m = &macros[index];

    char* name = sizename > 0 ? (char*)malloc(sizename) : NULL;
	if (!name && sizename > 0) {
		return "Failed to allocate for a new MACRO/SYMBOL/IDENTIFIER/ETC name";
	}
    char* val = sizeval > 0 ? (char*)malloc(sizeval) : NULL;
	if (!val && sizeval > 0) {
		if (name) free(name);
		return "Failed to allocate for a new MACRO/SYMBOL/IDENTIFIER/ETC value";
	}

	m->name = name;
	m->value = val;

	return NULL;
}

// auto_gen == false/true its used, if auto_gen != 0/1/false/true, it doesnt check with auto_gen. for type, Unknowm type signals any type
static struct p_macro* find_macro(char* name, int* ret, enum p_macro_types type, uint8_t auto_gen) {
    for (size_t i = 0; i < macro_count; i++) {
		struct p_macro* m = &macros[i];
		if (!m->valid) continue;
        if (strcmp(m->name, name) == 0) {
			if ((auto_gen == false || auto_gen == true) && m->auto_gen != (bool)auto_gen) continue;
			if (type != MACRO_TYPE_UNKNOWN && m->type != type) continue;
			if (!m->value) {
				*ret = -2;
				return m;
			}
            *ret = 0;
            return m;
        }
    }
    *ret = -1;
    return NULL;
}

static const char* new_macro(char* name, char* value, bool auto_gen, enum p_macro_types type, int line, int col, const char* file, struct p_macro** out_m) {
	if (out_m) *out_m = NULL;
	
	if (!name) return "No specified name for MACRO/IDENTIFIER/SYMBOL/ETC";
    
	size_t idx = macro_count;
	for (size_t i = 0; i < macro_count; i++) {
        struct p_macro* m = &macros[i];
		if (!m->name || !m->valid) {
			if (m->name) free(m->name);
			if (m->value) free(m->value);
			idx = i;
			break;
		}
    }
	
	const char* out = alloc_macros(idx, strlen(name) + 1, value ? strlen(value) + 1 : 0);
    
	if (out != NULL) return out;
	struct p_macro* m = &macros[idx];

	m->auto_gen = auto_gen;

	strcpy(m->name, name);
	if (value) strcpy(m->value, value);

	m->type = type;
	m->valid = true;

	m->file = file;
	m->col = col;
	m->line = line;

	if (idx > macro_count) macro_count = idx+1;
	else if (macro_count <= 0) macro_count = 1;
	else if (idx >= macro_count-1) macro_count++;

	if (out_m) *out_m = m;

	return NULL;
}

static const char* new_macroEX(char* name, uint8_t* value, size_t val_size, bool auto_gen, enum p_macro_types type, int line, int col, const char* file, struct p_macro** out_m) {
	if (out_m) *out_m = NULL;
	
	if (!name) return "No specified name for MACRO/IDENTIFIER/SYMBOL/ETC";
    
	size_t idx = macro_count;
	for (size_t i = 0; i < macro_count; i++) {
        struct p_macro* m = &macros[i];
		if (!m->name || !m->valid) {
			if (m->name) free(m->name);
			if (m->value) free(m->value);
			idx = i;
			break;
		}
    }
	
	const char* out = alloc_macros(idx, strlen(name) + 1, val_size);
    
	if (out != NULL) return out;
	struct p_macro* m = &macros[idx];

	m->auto_gen = auto_gen;

	strcpy(m->name, name);
	if (val_size > 0) memcpy(m->value, value, val_size);

	m->type = type;
	m->valid = true;

	m->file = file;
	m->col = col;
	m->line = line;

	if (idx > macro_count) macro_count = idx+1;
	else if (macro_count <= 0) macro_count = 1;
	else if (idx >= macro_count-1) macro_count++;

	if (out_m) *out_m = m;

	return NULL;
}

static void rm_macro(char* name) {
    if (!name || strlen(name) < 1) {
        return; // cannot free, already freed
    }
    for (size_t i = 0; i < macro_count; i++) {
        struct p_macro* m = &macros[i];
		if (!m->name) continue;

        if (strcmp(m->name, name) == 0) {
            free(m->name);
			m->name = NULL;
			if (m->value) {free(m->value); m->value = NULL;}
			m->valid = false;

			if (i == macro_count - 1) macro_count--;

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
    if (node->children) free(node->children);
    switch(node->type) {
        case AST_INSTRUCTION:
            for(size_t i = 0; i < node->inst.operand_count; i++) {
                ASTOperand* op = node->inst.operands[i];
                
                if (op->type == OPERAND_LABEL) {
                    if (op->label) free(op->label);
                } else if (op->type == OPERAND_REGISTER) {
                    if (op->reg) free(op->reg);
                } else if (op->type == OPERAND_IDENTIFIER) {
                    if (op->identifier) free_ast(op->identifier);
                } else if (op->type == OPERAND_MEMORY) {
                    for(size_t i = 0; i < op->mem_opr_count; i++) {
                        ASTOperand* opr = op->mem_addr[i];
                        
                        if (opr->type == OPERAND_LABEL) {
                            if (opr->label) free(opr->label);
                        } else if (opr->type == OPERAND_REGISTER) {
                            if (opr->reg) free(opr->reg);
                        } else if (opr->type == OPERAND_IDENTIFIER) {
                            if (opr->identifier) free_ast(opr->identifier);
                        }
                        if (opr) free(opr);
                    }
                    if (op->mem_addr) free(op->mem_addr);
                }
                if (op) free(op);
            }
            if (node->inst.operands) free(node->inst.operands);
            break;
        case AST_DIRECTIVE:
            if (node->directive.arg) free(node->directive.arg);
            break;
        case AST_COMMENT:
            if (node->comment.value) free(node->comment.value);
            break;
        case AST_LABEL:
            if (node->label.name) free(node->label.name);
            break;
        case AST_LITERAL:
            if (node->literal.type == LIT_STRING && node->literal.str_val) {
                free(node->literal.str_val);
            }
            break;
        case AST_IDENTIFIER:
            if (node->identifier.name) free(node->identifier.name);
            break;
        case AST_DECLIDENTIFIER:
            if (node->decl_identifier.name) free(node->decl_identifier.name);
            if (node->decl_identifier.array_value_count > 0 && node->decl_identifier.is_array) {
                for (size_t i = 0; i < node->decl_identifier.array_value_count; i++) {
                    if (node->decl_identifier.array_values[i]) free_ast(node->decl_identifier.array_values[i]);
                }
                if (node->decl_identifier.array_values) free(node->decl_identifier.array_values);
            }
            break;
        case AST_RESERVE:
            if (node->reserve.name) free(node->reserve.name);
            break;
		case AST_FILE_CHANGE:
			if (node->file_change.file_path) free(node->file_change.file_path);
			if (node->file_change.src) free(node->file_change.src);
			break;
        case AST_PROGRAM:
            free_macros();
            break;
        default:
            break;
    }
    if (node) free(node);
}

static ASTOperand* parse_operand(Parser* p, bool jst_verify) {
    if (parser_check(p, RBRACKET)) {
        parser_advance(p);
        if (parser_check(p, COMMA)) parser_advance(p);
        return NULL;
    } // Probably a memory expression closing

	ASTOperand* op = NULL;
	if (!jst_verify) {
		op = calloc(1, sizeof(ASTOperand));

		switch (p->current.type) {
			case REGISTER: {
				op->type = OPERAND_REGISTER;
				op->reg = (char*)calloc(strlen(p->current.lexeme) + 1, 1);
				op->reg[strlen(p->current.lexeme)] = '\0';
				pac_strdup(p->current.lexeme, op->reg);
				parser_advance(p);
				break;
			} 
			case LIT_INT: {
				op->type = OPERAND_LIT_INT;
				op->int_val = strtoll(p->current.lexeme, NULL, 10);
				parser_advance(p);
				break;
			} 
			case LIT_BIN: {
				op->type = OPERAND_LIT_INT;
				op->int_val = strtoll(p->current.lexeme, NULL, 2);
				parser_advance(p);
				break;
			}
			case LIT_HEX: {
				op->type = OPERAND_LIT_INT;
				op->int_val = strtoll(p->current.lexeme, NULL, 16);
				parser_advance(p);
				break;
			}
			case LIT_FLOAT: {
				op->type = OPERAND_LIT_FLOAT;
				op->float_val = strtod(p->current.lexeme, NULL);
				parser_advance(p);
				break;
			}
			case LIT_CHAR: {
				op->type = OPERAND_LIT_CHAR;
				op->int_val = (int64_t)p->current.lexeme[0];
				parser_advance(p);
				break;
			}
			case OP_ADD: {
				op->type = OPERAND_DISPLACEMENT;
				parser_advance(p);

				switch (p->current.type) {
					case LIT_INT: {
						op->int_val = strtoll(p->current.lexeme, NULL, 10);
						parser_advance(p);
						break;
					}
					case LIT_BIN: {
						op->int_val = strtoll(p->current.lexeme, NULL, 2);
						parser_advance(p);
						break;
					}
					case LIT_HEX: {
						op->int_val = strtoll(p->current.lexeme, NULL, 16);
						parser_advance(p);
						break;
					}
					case LIT_CHAR: {
						op->int_val = (int64_t)p->current.lexeme[0];
						parser_advance(p);
						break;
					}
					default: {
						free(op);
						PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an integer literal!");
						free_ast(p->root);
						exit(PAC_Error_UnexpectedToken);
						break;
					}
				}
				break;
			}
			case OP_SUB: {
				op->type = OPERAND_DISPLACEMENT;
				parser_advance(p);

				switch (p->current.type) {
					case LIT_INT: {
						op->int_val = 0 - strtoll(p->current.lexeme, NULL, 10);
						parser_advance(p);
						break;
					}
					case LIT_BIN: {
						op->int_val = 0 - strtoll(p->current.lexeme, NULL, 2);
						parser_advance(p);
						break;
					}
					case LIT_HEX: {
						op->int_val = 0 - strtoll(p->current.lexeme, NULL, 16);
						parser_advance(p);
						break;
					}
					case LIT_CHAR: {
						op->int_val = 0 - (int64_t)p->current.lexeme[0];
						parser_advance(p);
						break;
					}
					default: {
						free(op);
						PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an integer literal!");
						free_ast(p->root);
						exit(PAC_Error_UnexpectedToken);
						break;
					}
				}
				break;
			}
			case FUNC_USE: {
				ASTNode* identnode = parse_identifier(p, false, false, NULL);
				op->type = OPERAND_IDENTIFIER;
				op->identifier = identnode;
				if (parser_check(p, RBRACKET)) {
					parser_advance(p);
					if (parser_check(p, COMMA)) parser_advance(p);
				}
				break;
			}
			case LABEL_DEF: {
				op->type = OPERAND_LABEL;
				op->label = (char*)calloc(strlen(p->current.lexeme) + 1, 1);
				op->label[strlen(p->current.lexeme)] = '\0';
				pac_strdup(p->current.lexeme, op->label);
				if (parser_check(p, RBRACKET)) {
					parser_advance(p);
					if (parser_check(p, COMMA)) parser_advance(p);
				}
				break;
			}
			case IDENTIFIER_TOK: {
				ASTNode* identnode = parse_identifier(p, false, false, NULL);
				op->type = OPERAND_IDENTIFIER;
				op->identifier = identnode;
				if (parser_check(p, RBRACKET)) {
					parser_advance(p);
				}
				break;
			}
			case LBRACKET: {
				// Probably some memory expression
				op->type = OPERAND_MEMORY;
				
				size_t memoprcount = 0;
				parser_advance(p);
				while (!parser_check(p, SP_EOF) && p->current.type != SEMICOLON && p->current.type != SP_EOL && p->current.type != COMMA) {
					ASTOperand* opr = parse_operand(p, jst_verify);
					if (!opr) break;
					op->mem_addr = recalloc(op->mem_addr, memoprcount, memoprcount + 1, sizeof(ASTOperand*));
					op->mem_addr[memoprcount++] = opr;
				}
				op->mem_opr_count = memoprcount;
				break;
			}
			default:  {
				char msgbuf[128];
				snprintf(msgbuf, sizeof(msgbuf), "Unexpected token in operand: [%s]", token_type_to_ogstr(p->current.type));
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), msgbuf);
				free_ast(p->root);
				free(op);
				exit(PAC_Error_UnexpectedToken);
			}
		}
	} else {
		switch (p->current.type) {
			case REGISTER:
			case LIT_INT:
			case LIT_BIN:
			case LIT_HEX:
			case LIT_FLOAT:
			case LIT_CHAR: {
				parser_advance(p);
				break;
			}
			case OP_ADD:
			case OP_SUB: {
				parser_advance(p);

				switch (p->current.type) {
					case LIT_INT:
					case LIT_BIN:
					case LIT_HEX:
					case LIT_CHAR: {
						parser_advance(p);
						break;
					}
					default: {
						PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an integer literal!");
						free_ast(p->root);
						exit(PAC_Error_UnexpectedToken);
						break;
					}
				}
				break;
			}
			case FUNC_USE: {
				ASTNode* identnode = parse_identifier(p, true, false, NULL);
				if (identnode) free_ast(identnode);
				if (parser_check(p, RBRACKET)) {
					parser_advance(p);
					if (parser_check(p, COMMA)) parser_advance(p);
				}
				break;
			}
			case LABEL_DEF: {
				if (parser_check(p, RBRACKET)) {
					parser_advance(p);
					if (parser_check(p, COMMA)) parser_advance(p);
				}
				break;
			}
			case IDENTIFIER_TOK: {
				ASTNode* identnode = parse_identifier(p, true, false, NULL);
				if (identnode) free_ast(identnode);
				if (parser_check(p, RBRACKET)) {
					parser_advance(p);
				}
				break;
			}
			case LBRACKET: {
				parser_advance(p);
				while (!parser_check(p, SP_EOF) && p->current.type != SEMICOLON && p->current.type != SP_EOL && p->current.type != COMMA) {
					ASTOperand* opr = parse_operand(p, jst_verify);
					if (!opr) break;
				}
				break;
			}
			default:  {
				char msgbuf[128];
				snprintf(msgbuf, sizeof(msgbuf), "Unexpected token in operand: [%s]", token_type_to_ogstr(p->current.type));
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), msgbuf);
				free_ast(p->root);
				exit(PAC_Error_UnexpectedToken);
			}
		}
	}
	return op;
}

static ASTNode* parse_inst(Parser* p, bool jst_verify) {
    ASTNode* node = !jst_verify ? create_node(AST_INSTRUCTION, p) : NULL;
    if (!jst_verify) node->inst.opcode = p->current.type;
    parser_advance(p);

    while (!parser_check(p, SP_EOF) && p->current.type != SEMICOLON && p->current.type != SP_EOL) { 
        ASTOperand* op = parse_operand(p, jst_verify);

		if (!jst_verify) {
        	if (!op) break;

			node->inst.operands = realloc(node->inst.operands, sizeof(ASTOperand*) * (node->inst.operand_count + 1));
			node->inst.operands[node->inst.operand_count++] = op;
		} else if (op) free(op);

        if (parser_match(p, COMMA)) continue;
        if (parser_match(p, COMMENT_BLOCK)) break;
        if (parser_match(p, COMMENT_LINE)) break;
    }
    return node;
}

static ASTNode* parse_label(Parser* p, bool make_macro) {
    ASTNode* node = create_node(AST_LABEL, p);
    node->label.name = (char*)malloc(strlen(p->current.lexeme) + 1);
	if (!node->label.name) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
        free_ast(p->root);
        exit(PAC_Error_MemoryAllocationFailed);
	}
    node->label.name[strlen(p->current.lexeme)] = '\0';
    if (in_func) {
        if (func_start[0] == 0) {
            funccount = 0;
            pac_strdup(p->current.lexeme, node->label.name);
            snprintf(func_start, sizeof(func_start), "%s", p->current.lexeme); // set the function start

            char label[256];
            snprintf(label, sizeof(label), "$%s", p->current.lexeme);
            if (make_macro) {
				int ret = 0;
				struct p_macro* m = find_macro(p->current.lexeme, &ret, MACRO_TYPE_UNKNOWN, -1);

				if (ret != -1) {
					if (!m->auto_gen)
						PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Auto-Generated Label/Function conflicts with previous definition\n");
					else
						PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Auto-Generated Label/Function conflicts with previous Auto-Generated definition\n");
					if (m->type == MACRO_TYPE_NTYPE)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Types?");
					else if (m->type == MACRO_TYPE_USER_MACRO)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Macros?");
					else if (m->type == MACRO_TYPE_IDENTIFIER)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your identifiers?");
					else if (m->line > 0)
						PAC_NOTEF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here");
				}

                const char* err = new_macro(label, node->label.name, false, MACRO_TYPE_IDENTIFIER, p->current.line, p->current.column, p->lexer->file, NULL);
				if (err) {
					free_ast(p->root);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
					exit(PAC_Error_Unknown);
				}
                err = new_macro(node->label.name, NULL, true, MACRO_TYPE_IDENTIFIER, -1, -1, p->lexer->file, NULL); // keep track!
				if (err) {
					free_ast(p->root);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
					exit(PAC_Error_Unknown);
				}
            }
        } else {
            free(node->label.name);
            char label[512];

            // Already inside a function
            snprintf(label, sizeof(label), "%s_%llu", func_start, (unsigned long long)funccount);
            node->label.name = (char*)malloc(strlen(label) + 1);
			if (!node->label.name) {
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
				free_ast(p->root);
				exit(PAC_Error_MemoryAllocationFailed);
			}
            node->label.name[strlen(label)] = '\0';
            pac_strdup(label, node->label.name);

            snprintf(label, sizeof(label), "$%s.%s", func_start, p->current.lexeme);
            if (make_macro) {
				int ret = 0;
				struct p_macro* m = find_macro(node->label.name, &ret, MACRO_TYPE_UNKNOWN, -1);

				if (ret != -1) {
					if (!m->auto_gen)
						PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, node->label.name, strlen(p->current.lexeme), "Auto-Generated Label/Function conflicts with previous definition\n");
					else
						PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, node->label.name, strlen(p->current.lexeme), "Auto-Generated Label/Function conflicts with previous Auto-Generated definition\n");
					if (m->type == MACRO_TYPE_NTYPE)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Types?");
					else if (m->type == MACRO_TYPE_USER_MACRO)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Macros?");
					else if (m->type == MACRO_TYPE_IDENTIFIER)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your identifiers?");
					else if (m->line > 0)
						PAC_NOTEF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here");
				}

				ret = 0;
				m = find_macro(label, &ret, MACRO_TYPE_UNKNOWN, -1);

				if (ret != -1) {
					if (!m->auto_gen)
						PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, label, strlen(p->current.lexeme), "Auto-Generated Label/Function conflicts with previous definition\n");
					else
						PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, label, strlen(p->current.lexeme), "Auto-Generated Label/Function conflicts with previous Auto-Generated definition\n");
					if (m->type == MACRO_TYPE_NTYPE)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Types?");
					else if (m->type == MACRO_TYPE_USER_MACRO)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Macros?");
					else if (m->type == MACRO_TYPE_IDENTIFIER)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your identifiers?");
					else if (m->line > 0)
						PAC_NOTEF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here");
				}

                const char* err = new_macro(label, node->label.name, true, MACRO_TYPE_IDENTIFIER, p->current.line, p->current.column, p->lexer->file, NULL);
				if (err) {
					free_ast(p->root);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
					exit(PAC_Error_Unknown);
				}
                err = new_macro(node->label.name, NULL, true, MACRO_TYPE_IDENTIFIER, -1, -1, p->lexer->file, NULL); // keep track!
				if (err) {
					free_ast(p->root);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
					exit(PAC_Error_Unknown);
				}
                char templabel[512];
                snprintf(templabel, sizeof(templabel), "%s_raw", node->label.name); // for using the mangled label to access to usage label
                err = new_macro(templabel, label, true, MACRO_TYPE_IDENTIFIER, -1, -1, p->lexer->file, NULL);
				if (err) {
					free_ast(p->root);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
					exit(PAC_Error_Unknown);
				}
            }
            funccount++;
        }
    } else {
        pac_strdup(p->current.lexeme, node->label.name);
        if (make_macro) {
			int ret = 0;
			struct p_macro* m = find_macro(p->current.lexeme, &ret, MACRO_TYPE_UNKNOWN, -1);

			if (ret != -1) {
				if (!m->auto_gen)
					PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Label/Function conflicts with previous definition\n");
				else
					PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Label/Function conflicts with previous Auto-Generated definition\n");
				if (m->type == MACRO_TYPE_NTYPE)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Types?");
					else if (m->type == MACRO_TYPE_USER_MACRO)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Macros?");
					else if (m->type == MACRO_TYPE_IDENTIFIER)
						PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your identifiers?");
					else if (m->line > 0)
						PAC_NOTEF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here");
			}

			const char* err = new_macro(node->label.name, NULL, false, MACRO_TYPE_IDENTIFIER, p->current.line, p->current.column, p->lexer->file, NULL); // ensure using the label works!
			if (err) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
				exit(PAC_Error_Unknown);
			}
		}
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
		if (!node->directive.arg) {
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
			free_ast(p->root);
			exit(PAC_Error_MemoryAllocationFailed);
		}
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
		if (!op->str_val) {
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
			free_ast(p->root);
			exit(PAC_Error_MemoryAllocationFailed);
		}
        op->str_val[strlen(p->current.lexeme)] = '\0';
        pac_strdup(p->current.lexeme, op->str_val);
        parser_advance(p);
    }
    return node;
}

static ASTNode* parse_identifier(Parser* p, bool only_macros, bool add_macros, char* prefix) {
	int ret = 0;
	struct p_macro* m = NULL;

	size_t fsize = prefix ? strlen(p->current.lexeme) + strlen(prefix) : strlen(p->current.lexeme);

    char* name = (char*)malloc(fsize + 1);
	if (!name) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
		free_ast(p->root);
		exit(PAC_Error_MemoryAllocationFailed);
	}
	
	if (prefix) snprintf(name, fsize + 1, "%s%s", prefix, p->current.lexeme);
	else snprintf(name, fsize + 1, "%s", p->current.lexeme);

	size_t tsize = fsize;
	char* true_name = name;
	if (prefix) {
		tsize = strlen(p->current.lexeme);
		true_name = (char*)malloc(tsize + 1);
		if (!true_name) {
			free(name);
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
			free_ast(p->root);
			exit(PAC_Error_MemoryAllocationFailed);
		}
		true_name[tsize] = '\0';
		pac_strdup(p->current.lexeme, true_name);
	}

	int sline = p->current.line;
	int scol = p->current.column;

    if (p->current.type == FUNC_USE) {
		if (only_macros) {
			free(true_name);
			if (prefix) free(name);
			parser_advance(p);
			return NULL;
		}

        ret = 0;
        m = find_macro(p->current.lexeme, &ret, MACRO_TYPE_IDENTIFIER, -1);
		char* label = m ? m->value : NULL;
        if (ret != 0) {
            free_ast(p->root);
            PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Function not found!");
            exit(PAC_Error_FunctionNotFound);
        }

		free(name);

        name = (char*)malloc(strlen(label) + 1);
		if (!name) {
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
			free_ast(p->root);
			exit(PAC_Error_MemoryAllocationFailed);
		}
        name[strlen(label)] = '\0';
        pac_strdup(label, name);

		if (!prefix) true_name = name;
    }
    parser_advance(p);
    TokenType opt_specified_type = (TokenType)-1;
    bool is_array = false;
    int array_len = 0;
    if (parser_check(p, OP_NOT)) {
        parser_advance(p);
        if (p->current.type >= T_BYTE && p->current.type <= T_PTR) {
			opt_specified_type = p->current.type;
            parser_advance(p);
        } else if (p->current.type == IDENTIFIER_TOK) {
			ret = 0;
			m = find_macro(p->current.lexeme, &ret, MACRO_TYPE_NTYPE, -1);
			TokenType value = m && m->value ? *((TokenType*)m->value) : (TokenType)-1;
			if (ret == 0) {
				opt_specified_type = value;
            	parser_advance(p);
			} else {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unknown Identifier!");
				free(true_name);
				if (prefix) free(name);
				exit(PAC_Error_TypeResolutionFailed);
			}
		}

		if (opt_specified_type < T_BYTE || opt_specified_type > T_PTR) {
			free_ast(p->root);
			PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Unknown Type!");
			free(true_name);
			if (prefix) free(name);
			exit(PAC_Error_TypeResolutionFailed);
		}

        if (p->current.type == LBRACKET) {
            // Array
            is_array = true;
            array_len = -1; // Auto
            parser_advance(p);
            if (p->current.type == LIT_INT || p->current.type == LIT_HEX || p->current.type == LIT_BIN) {
                ASTNode* arrsize_node = parse_literal(p);
                array_len = arrsize_node->literal.int_val;
                free_ast(arrsize_node);
            } else if (p->current.type == RBRACKET) {
                // Pass
            } else {
                free_ast(p->root);
                PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Only Int/Bin/Hex Literals Allowed inside the array size specifier '[]'");
                free(true_name);
				if (prefix) free(name);
                exit(PAC_Error_TypeResolutionFailed);
            }

            if (p->current.type == RBRACKET) {
                // Parse Array Values
                parser_advance(p);
            } else {
                free_ast(p->root);
                PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Forgot to close array size specifier '[]' ?");
                free(true_name);
				if (prefix) free(name);
                exit(PAC_Error_TypeResolutionFailed);
            }
        }
    }

    if (p->current.type == OP_ASSIGN) {
		ret = 0;
		m = find_macro(p->current.lexeme, &ret, MACRO_TYPE_UNKNOWN, -1);

		if (ret != -1) {
			if (!m->auto_gen)
				PAC_WARNINGF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Identifier conflicts with previous definition\n");
			else
				PAC_WARNINGF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Identifier conflicts with previous Auto-Generated definition\n");
				
			if (m->type == MACRO_TYPE_NTYPE)
				PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Types?");
			else if (m->type == MACRO_TYPE_USER_MACRO)
				PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your Macros?");
			else if (m->type == MACRO_TYPE_IDENTIFIER)
				PAC_TIPF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here, try renaming your identifiers?");
			else if (m->line > 0)
				PAC_NOTEF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Macro created here");
		}

		ASTNode* node = NULL;
		if (!only_macros) {
			ASTNode* child = NULL;
			parser_advance(p);

			if (parser_check(p, SP_EOL)) {
				node = create_node(AST_DECLIDENTIFIER, p);
				node->decl_identifier.name = (char*)malloc(fsize + 1);
				if (!node->decl_identifier.name) {
					free(true_name);
					if (prefix) free(name);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
					free_ast(p->root);
					exit(PAC_Error_MemoryAllocationFailed);
				}
				node->decl_identifier.name[fsize] = '\0';
				pac_strdup(name, node->decl_identifier.name);
				node->decl_identifier.type = p->current.type;
				node->decl_identifier.opt_specified_type = opt_specified_type;
				node->decl_identifier.is_array = is_array;
				node->decl_identifier.array_size = array_len;
				node->decl_identifier.array_values = NULL;
				node->decl_identifier.array_value_count = 0;

				const char* err = add_macros ? new_macro(name, NULL, false, MACRO_TYPE_IDENTIFIER, sline, scol, p->lexer->file, NULL) : NULL;
				if (err) {
					free_ast(p->root);
					PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, err);
					free(true_name);
					if (prefix) free(name);
					exit(PAC_Error_Unknown);
				}
				free(true_name);
				if (prefix) free(name);
				return node;
			}

			node = create_node(AST_DECLIDENTIFIER, p);
			node->decl_identifier.name = (char*)malloc(fsize + 1);
			if (!node->decl_identifier.name) {
				free(true_name);
				if (prefix) free(name);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
				free_ast(p->root);
				exit(PAC_Error_MemoryAllocationFailed);
			}
			node->decl_identifier.name[fsize] = '\0';
			pac_strdup(name, node->decl_identifier.name);
			node->decl_identifier.type = p->current.type;
			node->decl_identifier.opt_specified_type = opt_specified_type;
			node->decl_identifier.is_array = is_array;
			node->decl_identifier.array_size = array_len;
			node->decl_identifier.array_values = NULL;
			node->decl_identifier.array_value_count = 0;
			bool continue_loop = true;
			int i = 0;

			while (continue_loop) {
				if (!is_array) {
					continue_loop = false;
				} else if (is_array && i == 0){
					node->decl_identifier.type = p->current.type;
				}
				if (p->current.type == IDENTIFIER_TOK) {
					child = parse_identifier(p, only_macros, add_macros, NULL);
					if (child->type == AST_LITERAL) { // Probably due to macro
						node->decl_identifier.type = child->literal.type;
					}
				} else if (p->current.type >= LIT_INT && p->current.type <= LIT_CHAR) {
					child = parse_literal(p);
				} else {
					free_ast(p->root);
					PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Unknown Value!");
					free(true_name);
					if (prefix) free(name);
					exit(PAC_Error_TypeResolutionFailed);
				}
			
				if (is_array) {
					node->decl_identifier.array_value_count++;
					node->decl_identifier.array_values = (ASTNode**)realloc(node->decl_identifier.array_values, sizeof(ASTNode**) * node->decl_identifier.array_value_count);
					node->decl_identifier.array_values[node->decl_identifier.array_value_count - 1] = child;
				} else {
					add_child(node, child);
				}

				if (p->current.type != COMMA) continue_loop = false;
				else parser_advance(p);
				i++;
			}
		} else {
			parser_advance(p);

			if (parser_check(p, SP_EOL)) {
			} else {
				bool continue_loop = true;
				while (continue_loop) {
					if (!is_array) {
						continue_loop = false;
					}
					if (p->current.type == IDENTIFIER_TOK) {
					} else if (p->current.type >= LIT_INT && p->current.type <= LIT_CHAR) {
						free_ast(parse_literal(p)); // Just there to ya know, do the job
					} else {
						free_ast(p->root);
						PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Unknown Value!");
						free(true_name);
						if (prefix) free(name);
						exit(PAC_Error_TypeResolutionFailed);
					}

					if (p->current.type != COMMA) continue_loop = false;
					else parser_advance(p);
				}
			}
		}

		const char* err = add_macros ? new_macro(name, NULL, false, MACRO_TYPE_IDENTIFIER, sline, scol, p->lexer->file, NULL) : NULL;
		if (err) {
			free_ast(p->root);
			PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, err);
			free(true_name);
			if (prefix) free(name);
			exit(PAC_Error_Unknown);
		}
		free(true_name);
		if (prefix) free(name);
        return node;
    }

	if (only_macros) {
		free(true_name);
		if (prefix) free(name);
		return NULL;
	}

    ret = 0;
	m = find_macro(true_name, &ret, MACRO_TYPE_UNKNOWN, -1);
    char* value = m ? m->value : NULL;
    if (ret == 0) {
		size_t len = strlen(value);
		char* str = value;

		ASTNode* node = NULL;

		if (m->type == MACRO_TYPE_USER_MACRO) {
			bool hex = false;
			bool octal = false;
			if (str[0] != '\0') {
				if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
					str = value + 2;
					hex = true;
				} else if (str[0] == '\\' && str[1] == '0') {
					str = value + 2;
					octal = true;
				}
			}
			node = create_node(AST_LITERAL, p);
			
			if (is_sdigit(str)) {
				node->literal.type = LIT_INT;
				node->literal.int_val = strtol(str, NULL, hex ? 16 : octal ? 8 : 10);
			} else {
				node->literal.type = LIT_STRING;
				node->literal.str_val = (char*)malloc(len + 1);
				if (!node->literal.str_val) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
					free(true_name);
					if (prefix) free(name);
					free_ast(p->root);
					exit(PAC_Error_MemoryAllocationFailed);
				}
				node->literal.str_val[len] = '\0';
				pac_strdup(value, node->literal.str_val);
			}
		} else if (m->type == MACRO_TYPE_IDENTIFIER) {
			node = create_node(AST_IDENTIFIER, p);
			ASTIdentifier* iden = &node->identifier;
			node->literal.type = LIT_STRING;

			size_t nlen = strlen(m->value);

			iden->name = (char*)malloc(nlen + 1);
			if (!iden->name) {
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
				free(true_name);
				if (prefix) free(name);
				free_ast(p->root);
				exit(PAC_Error_MemoryAllocationFailed);
			}

			iden->name[nlen] = '\0';
			pac_strdup(m->value, iden->name);
		} else {
			PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Can only use Macros or Identifiers (Functions/Labels/Structures/Data/Res/etc)");
			PAC_NOTEF(p->lexer->file, m->line, m->col, p->lexer->src, p->lexer->len, m->name, strlen(m->name), "Defined Here");
			free(true_name);
			if (prefix) free(name);
			free_ast(p->root);
			exit(PAC_Error_InvalidIdentifier);
		}
		free(true_name);
		if (prefix) free(name);
        return node;
    } else if (ret == -2) { // value found but NULL
        ASTNode* node = create_node(AST_IDENTIFIER, p);
        node->identifier.name = (char*)malloc(tsize + 1);
		if (!node->identifier.name) {
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
			free_ast(p->root);
			exit(PAC_Error_MemoryAllocationFailed);
		}
        node->identifier.name[tsize] = '\0';
        pac_strdup(true_name, node->identifier.name);
        free(true_name);
		if (prefix) free(name);
        return node;
    } else { // Error
        free_ast(p->root);
        PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, true_name, tsize, "Unknown Identifier!");
        free(true_name);
		if (prefix) free(name);
        exit(PAC_Error_InvalidIdentifier);
    }

    return NULL;
}

ASTNode* parse_reserve(Parser* p, bool only_macros, bool add_macros, char* prefix) {
    ASTNode* node = only_macros ? NULL : create_node(AST_RESERVE, p);
    parser_advance(p); // consume :res
    if (p->current.type != IDENTIFIER_TOK) {
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an Identifier!");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }
    
	size_t fsize = prefix ? strlen(p->current.lexeme) + strlen(prefix) : strlen(p->current.lexeme);

    char* name = (char*)malloc(fsize + 1);
	if (!name) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
		free_ast(p->root);
		exit(PAC_Error_MemoryAllocationFailed);
	}
    
    if (prefix) snprintf(name, fsize + 1, "%s%s", prefix, p->current.lexeme);
	else snprintf(name, fsize + 1, "%s", p->current.lexeme);

	size_t tsize = fsize;
	char* true_name = name;
	if (prefix) {
		tsize = strlen(p->current.lexeme);
		true_name = (char*)malloc(tsize + 1);
		if (!true_name) {
			free(name);
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
			free_ast(p->root);
			exit(PAC_Error_MemoryAllocationFailed);
		}
		true_name[tsize] = '\0';
		pac_strdup(p->current.lexeme, true_name);
	}

    parser_advance(p);

    if (p->current.type != OP_NOT) {
		free(true_name);
		if (prefix) free(name);
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected '!'");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }

    parser_advance(p);

    if (p->current.type < T_BYTE || p->current.type > T_PTR) {
		free(true_name);
		if (prefix) free(name);
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected a Type!");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }
	
	if (!only_macros) node->reserve.type = p->current.type;

	parser_advance(p);
	bool is_array = false;
	size_t array_len = 0;
	if (p->current.type == LBRACKET) {
		// Array
		is_array = true;
		array_len = 1;
		parser_advance(p);
		if (p->current.type == LIT_INT || p->current.type == LIT_HEX || p->current.type == LIT_BIN) {
			ASTNode* arrsize_node = parse_literal(p);
			array_len = arrsize_node->literal.int_val;
			free_ast(arrsize_node);
		} else if (p->current.type == RBRACKET) {
			PAC_WARNINGF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, node->reserve.name, strlen(node->reserve.name), "Size of Array not specified, defaulting to 1");
		} else {
			free(true_name);
			if (prefix) free(name);
			free_ast(p->root);
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, node->reserve.name, strlen(node->reserve.name), "Only Int/Bin/Hex Literals Allowed inside the array size specifier '[]'");
			exit(PAC_Error_TypeResolutionFailed);
		}

		if (p->current.type == RBRACKET) {
			// Parse Array Values
			parser_advance(p);
		} else {
			free(true_name);
			if (prefix) free(name);
			free_ast(p->root);
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, node->reserve.name, strlen(node->reserve.name), "Forgot to close array size specifier '[]' ?");
			exit(PAC_Error_TypeResolutionFailed);
		}
		parser_advance(p);
	}

	if (!only_macros) {
		node->reserve.is_array = is_array;
		node->reserve.array_size = array_len;
		node->reserve.name = name;
	}
    
	const char* err = add_macros ? new_macro(name, NULL, false, MACRO_TYPE_IDENTIFIER, p->current.line, p->current.column, p->lexer->file, NULL) : NULL;
	if (err) {
		free(true_name);
		if (prefix) free(name);
		free_ast(p->root);
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
		exit(PAC_Error_Unknown);
	}
    
	if (only_macros) {
		free(true_name);
		if (prefix) free(name);
	}
	
	return node;
}

static void parse_preprocessors(Parser* p, bool do_task, bool do_task_inc) {
	switch (p->current.type) {
		case PP_DEF: {
			parser_advance(p);
			if (p->current.type != IDENTIFIER_TOK) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Please use a identifier to specify macro");
				exit(PAC_Error_InvalidIdentifier);
			}

			char* name = (char*)malloc(strlen(p->current.lexeme) + 1);
			if (!name) {
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
				free_ast(p->root);
				exit(PAC_Error_MemoryAllocationFailed);
			}
			name[strlen(p->current.lexeme)] = '\0';
			pac_strdup(p->current.lexeme, name);

			int sline = p->current.line;
			int scol = p->current.column;

			parser_advance(p);
			if ((p->current.type < LIT_INT || p->current.type > LIT_CHAR) && p->current.type != SP_EOL) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only define Macros with literal values or no value!");
				exit(PAC_Error_InvalidIdentifier);
			}
			char value[256];
			if (parser_check(p, LIT_CHAR)) {
				snprintf(value, sizeof(value), "%c", *p->current.lexeme);
				parser_advance(p);
			} else if (parser_check(p, LIT_INT)) {
				long long out = strtoll(p->current.lexeme, NULL, 10);
				snprintf(value, sizeof(value), "%lld", out);
				parser_advance(p);
			} else if (parser_check(p, LIT_BIN)) {
				long long out = strtoll(p->current.lexeme, NULL, 2);
				snprintf(value, sizeof(value), "%lld", out);
				parser_advance(p);
			} else if (parser_check(p, LIT_HEX)) {
				long long out = strtoll(p->current.lexeme, NULL, 16);
				snprintf(value, sizeof(value), "%lld", out);
				parser_advance(p);
			} else if (parser_check(p, LIT_STRING)) {
				snprintf(value, sizeof(value), "%s", p->current.lexeme);
				parser_advance(p);
			} else if (parser_check(p, LIT_FLOAT)) {
				float out = strtof(p->current.lexeme, NULL);
				snprintf(value, sizeof(value), "%f", out);
				parser_advance(p);
			} else if (parser_check(p, SP_EOL)) {
				value[0] = '1';
				value[1] = '\0';
			}

			if (!do_task) {
				free(name);
				break;
			}

			const char* err = new_macro(name, value, false, MACRO_TYPE_USER_MACRO, sline, scol, p->lexer->file, NULL);
			free(name);
			if (err) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), err);
				exit(PAC_Error_Unknown);
			}
			break;
		}
		case PP_UNDEF: {
			parser_advance(p);
			if (p->current.type != IDENTIFIER_TOK) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Please use a identifier to specify macro");
				exit(PAC_Error_InvalidIdentifier);
			}
			if (!do_task) {
				parser_advance(p);
				break;
			}

			rm_macro(p->current.lexeme);
			parser_advance(p);
			break;
		}
		case PP_INC: {
			parser_advance(p);
			if (p->current.type != LIT_STRING) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Please use a string to specify file");
				exit(PAC_Error_InvalidIdentifier);
			}

			if (!do_task_inc) {
				parser_advance(p);
				break;
			}

			char nf[512] = {0};
			char* file = p->current.lexeme;

			FILE* fp = fopen(file, "r");
			if (!fp) {
				for (size_t i = 0; i < p->inc_dir_count; i++) {
					char* incDir = p->inc_dirs[i];
					bool bslash = false;
					for (char* p = incDir; *p; p++) {
						bool final = *(char*)(p + 1) == 0 ? true : false;
						switch (*p) {
							case '/': {
								if (final) 
									*p = '\0';
								break;
							}
							case '\\': {
								if (final) 
									*p = '\0';
								bslash = true;
								break;
							}
							default: break;
						}
					}
					if (bslash) {
						snprintf(nf, sizeof(nf), "%s\\%s", incDir, file);
					} else {
						snprintf(nf, sizeof(nf), "%s/%s", incDir, file);
					}

					fp = fopen(nf, "r");
					if (fp) break;
				}
			}
			if (!fp) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Could not open the specified file!");
				exit(PAC_Error_IncludeFileNotFound);
			}

			fseek(fp, 0, SEEK_END);
			size_t len = ftell(fp);
			fseek(fp, 0, SEEK_SET);

			if (len <= 0) {
				fclose(fp);
				return;
			}

			char* data = (char*)malloc(len + 1);
			if (!data) {
				fclose(fp);
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Could not allocate for reading data in the specified file!");
				exit(PAC_Error_MemoryAllocationFailed);
			}
			if (fread(data, 1, len, fp) <= 0) {
				fclose(fp);
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Could not read the specified file!");
				exit(PAC_Error_FileReadFailed);
			}
			fclose(fp);

			data[len] = '\0';

			ASTNode* incAst = create_node(AST_FILE_CHANGE, p);
			ASTFileChange* fchange = &incAst->file_change;
			if (nf[0] != '\0') {
				fchange->file_path = (char*)malloc(strlen(nf) + 1);
				if (fchange->file_path) strcpy(fchange->file_path, nf);
				else fchange->file_path = NULL;
			} else {
				fchange->file_path = NULL;
			}
			fchange->src = data;
			fchange->len = len;
			add_child(p->root, incAst);

			Lexer il = init_lexer(data, len, p->current.lexeme);
			Parser ip = init_parser(&il);
			ip.inc_dirs = p->inc_dirs;
			ip.inc_dir_count = p->inc_dir_count;
			parse_symbols(&ip);
			il = init_lexer(data, len, p->current.lexeme);
			ip = init_parser(&il);
			ip.inc_dirs = p->inc_dirs;
			ip.inc_dir_count = p->inc_dir_count;

			ASTNode* iroot = parse_program(&ip);
			if (!iroot) {
				free_ast(p->root);
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Could not parse the specified file!");
				exit(PAC_Error_FileReadFailed);
			}
			for (size_t i = 0; i < iroot->child_count; i++) {
				ASTNode* child = iroot->children[i];
				add_child(p->root, child);
				*(ASTNode**)(&iroot->children[i]) = NULL;
			}
			iroot->child_count = 0;
			free_ast(iroot);

			incAst = create_node(AST_FILE_CHANGE, p);
			fchange = &incAst->file_change;
			fchange->file_path = (char*)malloc(strlen(p->lexer->file) + 1);
			if (fchange->file_path) strcpy(fchange->file_path, p->lexer->file);
			else fchange->file_path = NULL;
			fchange->src = (char*)malloc(strlen(p->lexer->src) + 1);
			if (fchange->src) strcpy(fchange->src, p->lexer->src);
			else fchange->src = NULL;
			fchange->len = p->lexer->len;
			add_child(p->root, incAst);
			break;
		}
		default: break;
	}
}

static void parse_types(Parser* p, bool make_macro) {
	parser_advance(p);

	if (p->current.type != IDENTIFIER_TOK) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Invalid Identifier!");
		if (p->current.type >= ASM_MOV && p->current.type <= ASM_NOP) {
			PAC_NOTEF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "That word is reserved as an assembly instruction");
			free_ast(p->root);
			exit(PAC_Error_ReservedWordUsedAsIdentifier);
		}
		free_ast(p->root);
        exit(PAC_Error_InvalidIdentifier);
	}

	char* name = (char*)malloc(strlen(p->current.lexeme) + 1);
	if (!name) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
        free_ast(p->root);
        exit(PAC_Error_MemoryAllocationFailed);
	}
	name[strlen(p->current.lexeme)] = '\0';
	pac_strdup(p->current.lexeme, name);

	int sline = p->current.line;
	int scol = p->current.column;

	parser_advance(p);

	if (p->current.type != OP_ASSIGN) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Invalid Syntax, '=' is required!");
        free_ast(p->root);
		free(name);
        exit(PAC_Error_SyntaxUnexpectedToken);
	}

	parser_advance(p);

	if (p->current.type < T_BYTE || p->current.type > T_PTR) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unknown Type!");
        free_ast(p->root);
		free(name);
        exit(PAC_Error_TypeResolutionFailed);
	}

	if (make_macro) {
		const char* err = new_macroEX(name, (uint8_t*)&p->current.type, sizeof(TokenType), false, MACRO_TYPE_NTYPE, sline, scol, p->lexer->file, NULL);
		if (err) {
			free_ast(p->root);
			PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, name, strlen(name), err);
			exit(PAC_Error_Unknown);
		}
	}

	free(name);
	parser_advance(p);
}

static void parse_struct(Parser* p, bool only_macros, bool add_macros, ASTNode* parent) {
    parser_advance(p); // consume .struct
    if (p->current.type != IDENTIFIER_TOK) {
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an Identifier!");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }
    
	size_t nlen = strlen(p->current.lexeme);
	char* name = (char*)malloc(nlen + 2);
	if (!name) {
		PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
		free_ast(p->root);
		exit(PAC_Error_MemoryAllocationFailed);
	}
	
	snprintf(name, nlen + 2, "%s.", p->current.lexeme);

	int sline = p->current.line;
	int scol = p->current.column;

    parser_advance(p);

	bool res = false;
	if (parser_check(p, RESERVE)) {
		res = true;
		parser_advance(p);
	}
    if (!parser_check(p, SP_EOL)) {
        PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected '\\n' (newline)");
        free_ast(p->root);
        exit(PAC_Error_UnexpectedToken);
    }

    parser_advance(p);
	if (parser_check(p, STRUCT_END)) {
		PAC_WARNINGF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, NULL, strlen(name)-1, "Skipped Empty Structure");
		parser_advance(p);
        return;
	}
	
	bool found = false;

	size_t i = 0;
	while (!parser_check(p, STRUCT_END)) {
		if (p->current.type != IDENTIFIER_TOK) {
			PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Expected an Identifier for field name!");
			free_ast(p->root);
			exit(PAC_Error_UnexpectedToken);
		}

		if (add_macros && i == 0) {
			char v[256];
			snprintf(v, sizeof(v), "%s%s", name, p->current.lexeme);
			char n[256];
			strcpy(n, name);
			n[nlen] = '\0';
			const char* err = new_macroEX(n, (uint8_t*)v, nlen + 2 + strlen(p->current.lexeme), true, MACRO_TYPE_IDENTIFIER, p->current.line, p->current.column, p->lexer->file, NULL);
			if (err) {
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
				free_ast(p->root);
				free(name);
				exit(PAC_Error_MemoryAllocationFailed);
			}
		}

		ASTNode* node = res ? parse_reserve(p, only_macros, add_macros, name) : parse_identifier(p, only_macros, add_macros, name);
		if (node) add_child(parent, node);

		parser_advance(p);

		if (parser_check(p, STRUCT_END)) found = true;
		i++;
	}
    
	if (!found) {
		PAC_ERRORF(p->lexer->file, sline, scol, p->lexer->src, p->lexer->len, NULL, strlen(name)-1, "Incomplete Structure!");
		free(name);
		free_ast(p->root);
		exit(PAC_Error_StructIncomplete);
	}
	free(name);

	parser_advance(p); // consume .struct_end
}

void parse_symbols(Parser* p) {
    parser_advance(p);
    while (p->current.type != SP_EOF) {
		if (parser_check(p, SP_EOL)) {
			parser_advance(p);
			continue;
		}

		ASTNode* stmt = NULL;
		if (p->current.type >= ASM_MOV && p->current.type <= ASM_NOP) {
			stmt = parse_inst(p, true);
			if (stmt) free_ast(stmt);
			continue;
		} else if (p->current.type >= PP_DEF && p->current.type <= PP_UNDEF) {
			parse_preprocessors(p, true, false); // Already handled
			continue;
		}

		switch (p->current.type) {
			case LABEL_DEF: {
				stmt = parse_label(p, true);
				break;
			}
			case SECTION:
			case GLOBAL: {
				stmt = parse_directive(p);
				break;
			}
			case COMMENT_LINE:
			case COMMENT_BLOCK: {
				parser_advance(p);
				break;
			}
			case LIT_BIN:
			case LIT_HEX:
			case LIT_INT:
			case LIT_FLOAT:
			case LIT_CHAR:
			case LIT_STRING: {
				stmt = parse_literal(p);
				break;
			}
			case IDENTIFIER_TOK: {
				stmt = parse_identifier(p, true, true, NULL);
				break;
			}
			case SIZE_SEC:
			case START_SEC:
			case ALIGN: {
				parser_advance(p); // consume :align
				stmt = parse_literal(p); // parse literal
				if (stmt->type != AST_LITERAL) {
					free_ast(stmt);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':align'");
					exit(PAC_Error_InvalidAlignment);
				} else if (stmt->literal.type != LIT_BIN && stmt->literal.type != LIT_INT && stmt->literal.type != LIT_HEX) {
					free_ast(stmt);
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':align'");
					exit(PAC_Error_InvalidAlignment);
				}
				free_ast(stmt);
				stmt = NULL;
				break;
			}
			case RESERVE: {
				stmt = parse_reserve(p, true, true, NULL);
				break;
			}
			case FUNC_DEF: {
            	parser_advance(p);
            
				if (in_func) {
					stmt = parse_label(p, true);
				} else {
					memset(func_start, 0, sizeof(func_start));
					in_func = true;
					stmt = parse_label(p, true); // resolve func
				}
				break;
			}
			case FUNC_END: {
				memset(func_start, 0, sizeof(func_start));
				parser_advance(p);
				in_func = false;
				break;
			}
			case TYPEDEF: {
				parse_types(p, true);
				break;
			}
			case STRUCT_DEF: {
				parse_struct(p, true, true, NULL);
				break;
			}
			default: {
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unexpected token at top-level!");
				if (stmt) free_ast(stmt);
				exit(PAC_Error_UnexpectedToken);
				break;
			}
		}

		if (stmt) free_ast(stmt);
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
            add_child(root, parse_inst(p, false));
			continue;
        } else if (p->current.type == LABEL_DEF) {
			add_child(root, parse_label(p, false));
			continue;
        } else if (p->current.type >= PP_DEF && p->current.type <= PP_UNDEF) {
            parse_preprocessors(p, false, true); // Already handled
			continue;
		}
		switch (p->current.type) {
			case LABEL_DEF: {
				stmt = parse_label(p, false);
				break;
			}
			case SECTION:
			case GLOBAL: {
				stmt = parse_directive(p);
				break;
			}
			case COMMENT_LINE:
			case COMMENT_BLOCK: {
				stmt = create_node(AST_COMMENT, p);
				stmt->comment.value = (char*)malloc(strlen(p->current.lexeme) + 1);
				if (!stmt->comment.value) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Allocation Failed!");
					free_ast(stmt);
					free_ast(p->root);
					exit(PAC_Error_MemoryAllocationFailed);
				}
				stmt->comment.value[strlen(p->current.lexeme)] = '\0';
				pac_strdup(p->current.lexeme, stmt->comment.value);
				parser_advance(p);
				break;
			}
			case LIT_BIN:
			case LIT_HEX:
			case LIT_INT:
			case LIT_FLOAT:
			case LIT_CHAR:
			case LIT_STRING: {
				stmt = parse_literal(p);
				break;
			}
			case IDENTIFIER_TOK: {
				stmt = parse_identifier(p, false, false, NULL);
				break;
			}
			case ALIGN: {
				parser_advance(p); // consume :align
				stmt = parse_literal(p); // parse literal
				if (stmt->type != AST_LITERAL) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':align'");
					free_ast(stmt);
					free_ast(root);
					exit(PAC_Error_InvalidAlignment);
				} else if (stmt->literal.type != LIT_BIN && stmt->literal.type != LIT_INT && stmt->literal.type != LIT_HEX) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':align'");
					free_ast(stmt);
					free_ast(root);
					exit(PAC_Error_InvalidAlignment);
				}

				nxt_secalignment = stmt->literal.int_val;
				free_ast(stmt);
				stmt = NULL;
				break;
			}
			case START_SEC: {
				parser_advance(p); // consume :start
				stmt = parse_literal(p); // parse literal
				if (stmt->type != AST_LITERAL) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':start'");
					free_ast(stmt);
					free_ast(root);
					exit(PAC_Error_InvalidAlignment);
				} else if (stmt->literal.type != LIT_BIN && stmt->literal.type != LIT_INT && stmt->literal.type != LIT_HEX) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer/hex/bin literal when using ':start'");
					free_ast(stmt);
					free_ast(root);
					exit(PAC_Error_InvalidAlignment);
				}
				nxt_secstart = stmt->literal.int_val;
				free_ast(stmt);
				stmt = NULL;
				break;
			}
			case SIZE_SEC: {
				parser_advance(p); // consume :size
				stmt = parse_literal(p); // parse literal
				if (stmt->type != AST_LITERAL) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer literal when using ':size'");
					free_ast(stmt);
					free_ast(root);
					exit(PAC_Error_InvalidAlignment);
				} else if (stmt->literal.type != LIT_BIN && stmt->literal.type != LIT_INT && stmt->literal.type != LIT_HEX) {
					PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Can only pass integer literal when using ':size'");
					free_ast(stmt);
					free_ast(root);
					exit(PAC_Error_InvalidAlignment);
				}
				nxt_secsize = stmt->literal.int_val;
				free_ast(stmt);
				stmt = NULL;
				break;
			}
			case RESERVE: {
				stmt = parse_reserve(p, false, false, NULL);
				break;
			}
			case FUNC_DEF: {
            	parser_advance(p); // consume .func
				in_func = true;
				stmt = parse_label(p, false);
				break;
			}
			case FUNC_END: {
				parser_advance(p); // consume .endfunc
				in_func = false;
				char label[512];
				// Remove all labels
				for (size_t i = 0; i < funccount; i++) {
					snprintf(label, sizeof(label), "%s_%llu", func_start, (unsigned long long)i);
					rm_macro(label);
					snprintf(label, sizeof(label), "%s_%llu_raw", func_start, (unsigned long long)i);
					int ret = 0;
					struct p_macro* m = find_macro(label, &ret, MACRO_TYPE_IDENTIFIER, -1);
					char* usage_label = m ? m->value : NULL;
					if (ret == 0) {
						rm_macro(usage_label);
					}
					rm_macro(label);
				}
				memset(func_start, 0, sizeof(func_start));
				break;
			}
			case TYPEDEF: {
				parse_types(p, false);
				break;
			}
			case STRUCT_DEF: {
				parse_struct(p, false, false, root);
				break;
			}
			default: {
				PAC_ERRORF(p->lexer->file, p->current.line, p->current.column, p->lexer->src, p->lexer->len, p->current.lexeme, strlen(p->current.lexeme), "Unexpected token at top-level!");
				if (stmt) free_ast(stmt);
				free_ast(root);
				exit(PAC_Error_UnexpectedToken);
				break;
			}
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
			if (!node->decl_identifier.is_array) {
				if (node->child_count < 1) {
					snprintf(out, maxsize, "[DeclIdentifier] %s => \\x0", node->decl_identifier.name);
					return;
				}
				ast_to_str(node->children[0], operand, sizeof(operand));
				snprintf(out, maxsize, "[DeclIdentifier] %s => %s", node->decl_identifier.name, operand);
			} else {
				if (node->decl_identifier.array_size < 1 && node->decl_identifier.array_size != -1) {
					strcpy(out, "Invalid DeclIdentifier Array!");
					return;
				}
				strcpy(out, "Sadly DeclIdentifier Array is not yet supported.");
				return;
			}
            return;
        case AST_RESERVE:
            snprintf(out, maxsize, "[Reserve] [%s] %s", token_type_to_str(node->reserve.type), node->reserve.name);
            return;
        default:
            strcpy(out, "Unknown!");
            return;
    }
}   
