const {
    DiagnosticSeverity
} = require("vscode-languageserver/node.js");

function classifyToken(type) {
    if (!type) return "identifier";
    // instructions (any ASM_*)
    if (type.startsWith("ASM_")) return "instruction";

    // directives / structure
    if (
        type === "FUNC_DEF" ||
        type === "FUNC_END" ||
        type === "STRUCT_DEF" ||
        type === "STRUCT_END"
    ) return "function";

    if (
        type === "SECTION" ||
        type === "GLOBAL" ||
        type === "ALIGN" ||
        type === "RESERVE" ||
        type === "TYPEDEF"
    ) return "directive";

    // labels
    if (type === "LABEL_DEF") return "label";

    // registers
    if (type === "REGISTER") return "register";

    // literals
    if (type.startsWith("LIT_")) {
        if (type === "LIT_STRING") return "string";
        if (type === "LIT_CHAR") return "string";
        return "number";
    }

    // types
    if (type.startsWith("T_")) return "type";

    // preprocessor
    if (type.startsWith("PP_")) return "preprocessor";

    // operators
    if (type.startsWith("OP_")) return "operator";

    // comments
    if (type.startsWith("COMMENT_")) return "comment";

    return "identifier";
}

function buildHighlights(tokens) {
    return tokens.map(t => ({
        start: t.start,
        end: t.end,
        type: classifyToken(t.type)
    }));
}

function buildSymbolsFromAST(linesAST) {
    const symbols = [];

    for (const node of linesAST) {
        if (!node) continue;

        if (node.type === "func_def") {
            symbols.push({
                kind: "function",
                name: node.name
            });
        }

        if (node.type === "label") {
            symbols.push({
                kind: "label",
                name: node.name
            });
        }

        if (node.type === "directive" && node.name === ".section") {
            symbols.push({
                kind: "section",
                name: node.arg?.[0]
            });
        }
    }

    return symbols;
}

function parseOperand(tokens, i, registers) {
    const t = tokens[i];
    if (!t) return [null, i, "No token"];

    switch (t.type) {
        case "REGISTER":
            return [{
                type: "register",
                value: t.lexeme
            }, i + 1, ""];

        case "LIT_INT":
        case "LIT_HEX":
        case "LIT_BIN":
            return [{
                type: "int",
                value: Number(
                    t.type === "LIT_HEX" ? parseInt(t.lexeme, 16)
                        : t.type === "LIT_BIN" ? parseInt(t.lexeme.replace(/^0b/, ""), 2)
                            : t.lexeme
                )
            }, i + 1, ""];

        case "LIT_CHAR":
            return [{
                type: "char",
                value: t.lexeme
            }, i + 1, ""];

        case "LABEL_DEF":
            return [{
                type: "label",
                value: t.lexeme.replace(":", "")
            }, i + 1, ""];

        case "LBRACKET": {
            const mem = [];
            i++;

            while (i < tokens.length && tokens[i].type !== "RBRACKET") {
                if (tokens[i].type === "COMMA") {
                    i++;
                    continue;
                }

                const [op, ni, err] = parseOperand(tokens, i, registers);
                if (err) return [null, i, err];

                mem.push(op);
                i = ni;
            }

            if (!tokens[i] || tokens[i].type !== "RBRACKET") {
                return [null, i, "Unclosed '['"];
            }

            return [{
                type: "memory",
                value: mem
            }, i + 1, ""];
        }

        default:
            return [{
                type: "unknown",
                value: t.lexeme
            }, i + 1, ""];
    }
}

function parseInstruction(tokens, i, instructions, registers) {
    const opcodeToken = tokens[i];

    const node = {
        type: "instruction",
        opcode: opcodeToken.lexeme,
        opcodeType: opcodeToken.type,
        operands: [],
        error: "",
        i
    };

    i++;

    while (i < tokens.length) {
        const t = tokens[i];

        if (t.type === "COMMA" || t.type === "SEMICOLON") {
            i++;
            continue;
        }

        const [op, ni, msg] = parseOperand(tokens, i, registers);
        if (!op) {
            node.error = msg;
            break;
        }

        node.operands.push(op);
        i = ni;
    }

    node.i = i;
    return node;
}

function classifyLine(tokens) {
    if (!tokens.length) return { type: "empty" };

    const first = tokens[0];

    switch (first.type) {
        case "LABEL_DEF":
            return { type: "label" };

        case "FUNC_DEF":
            return { type: "func_def" };

        case "FUNC_END":
            return { type: "func_end" };

        case "SECTION":
        case "GLOBAL":
        case "ALIGN":
        case "RESERVE":
        case "TYPEDEF":
            return { type: "directive" };

        case "PP_DEF":
        case "PP_IF":
        case "PP_ELSE":
        case "PP_ELIF":
        case "PP_END":
        case "PP_INC":
        case "PP_UNDEF":
            return { type: "preprocessor" };

        default:
            // instruction OR unknown
            if (first.type.startsWith("ASM_")) {
                return { type: "instruction" };
            }

            return { type: "unknown" };
    }
}

function parseLine(lineTokens, instructions, registers) {
    if (!lineTokens.length) return null;

    const kind = classifyLine(lineTokens);

    switch (kind.type) {
        case "label":
            return {
                type: "label",
                name: lineTokens[0].lexeme.replace(":", "")
            };

        case "func_def":
            return {
                type: "func_def",
                name: lineTokens[1]?.lexeme || null
            };

        case "func_end":
            return { type: "func_end" };

        case "directive":
            return {
                type: "directive",
                name: lineTokens[0].lexeme,
                args: lineTokens.slice(1)
            };

        case "preprocessor":
            return {
                type: "preprocessor",
                name: lineTokens[0].lexeme,
                args: lineTokens.slice(1)
            };

        case "instruction": {
            const opcodeIndex = (lineTokens[0].type === "LABEL_DEF") ? 1 : 0;
            const opcodeToken = lineTokens[opcodeIndex];

            if (!opcodeToken || !opcodeToken.type.startsWith("ASM_")) {
                return {
                    error: `Invalid instruction: ${opcodeToken?.lexeme}`
                };
            }

            if (!instructions.includes(opcodeToken.type)) {
                return {
                    error: `Unknown instruction: ${opcodeToken.lexeme}`
                };
            }

            return parseInstruction(lineTokens, opcodeIndex, instructions, registers);
        }

        default:
            return { type: "unknown" };
    }
}

function validate(linesAST, registers) {
    const diagnostics = [];

    function walk(node, line) {
        if (!node) return;

        if (node.type === "register") {
            if (!registers.includes(node.value)) {
                diagnostics.push({
                    severity: DiagnosticSeverity.Error,
                    range: {
                        start: { line, character: 0 },
                        end: { line, character: 999 }
                    },
                    message: `Unknown register: ${node.value}`
                });
            }
        }

        if (node.operands) {
            for (const o of node.operands) walk(o, line);
        }

        if (Array.isArray(node.value)) {
            for (const v of node.value) walk(v, line);
        }
    }

    for (const { ast, line } of linesAST) {
        if (!ast) continue;

        if (ast.error) {
            diagnostics.push({
                severity: DiagnosticSeverity.Error,
                range: {
                    start: { line, character: 0 },
                    end: { line, character: 999 }
                },
                message: ast.error
            });
        }

        walk(ast, line);
    }

    return diagnostics;
}

module.exports = {
    validate
};