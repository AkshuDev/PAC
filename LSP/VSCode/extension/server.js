const {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  CompletionItemKind,
  TextDocumentSyncKind
} = require("vscode-languageserver/node.js");

const {
  TextDocument
} = require("vscode-languageserver-textdocument");

const {
    validate
} = require("./parser");

const connection = createConnection(ProposedFeatures.all);
const documents = new TextDocuments(TextDocument);

connection.onInitialize(() => {
    return {
        capabilities: {
            textDocumentSync: TextDocumentSyncKind.Incremental,
            completionProvider: {
                triggerCharacters: [" ", "%", ","]
            },
            configurationProvider: true
        }
    };
});

const instructions_x86_and_x64 = [
    "mov", "movzx", "movsx", "lea", "xchg", "add", "sub", "adc", "sbb", "inc", "dec",
    "and", "or", "xor", "not", "test", "cmp", "shl", "shr", "sar", "rol", "ror",
    "jmp", "call", "ret", "jz", "jnz", "jg", "jl", "jge", "jle", "push", "pop",
    "syscall", "int3", "cpuid", "nop"
];
const registers_x86_and_x64 = [
    // 64-bit
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    // Extended 64-bit
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    // 32-bit
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    // Extended 32-bit
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    // 16-bit
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    // Extended 16-bit
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    // 8-bit (Low first then High)
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
    // Extended 8-bit
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    // New 8-bit
    "spl", "bpl", "sil", "dil",
    // Special
    "rip"
];

const instructions_pvcpu = [
    // ALU Operations
    "nop", "add", "sub", "mul", "div", "cmp", "ucmp", "and", "or", "not",
    "nand", "nor", "xor", "shl", "shr", "rotl", "rotr", "arotl", "arotr", "inc", "dec", "test",
    // Memory Operations
    "load", "store", "push", "pop", "push16", "pop16", "push32", "pop32", "push64", "pop64", "mset",
    "mcpy", "mcmp",
    // Movement Operations
    "mov", "movb", "movw", "movd", "movq", "xchg", "rreg",
    // Jumping Operations
    "jmp", "call", "ret", "exception", "jz", "jnz", "jl", "jle", "jg", "jge", "syscall",
    // Control Operations
    "rderr", "rdexerr", "cpuid", "lcpui", "rcpui", "arcpu", "xrcpui"
];
const registers_pvcpu = [
    // NULL
    "null",
    // General
    "g0", "g1", "g2", "g3", "g4", "g5", "g6",
    "g7", "g8", "g9", "g10", "g11", "g12", "g13", "g14", "g15",
    "g16", "g17", "g18", "g19", "g20", "g21", "g22", "g23", "g24",
    "g25", "g26", "g27", "g28", "g29", "g30", "lr", "sf", "sp",
    // Internal
    "pc", "i0", "i1", "i2", "tr"
];

const architectures = ["x64", "x86", "pvcpu"];
let activeArch = "x64";
let activeRegisters = registers_x86_and_x64;
let activeInstructions = instructions_x86_and_x64;

connection.onDidChangeConfiguration(change => {
    const settings = change.settings;

    if (settings?.pac?.architecture) {
        activeArch = settings.pac.architecture;
    }

    if (!["x64","x86","pvcpu"].includes(activeArch)) {
        activeArch = "x64";
    }

    if (activeArch == "x86" || activeArch == "x64") {
        activeRegisters = registers_x86_and_x64;
        activeInstructions = instructions_x86_and_x64;
    } else if (activeArch == "pvcpu") {
        activeRegisters = registers_pvcpu;
        activeInstructions = instructions_pvcpu;
    }
});

connection.onCompletion(() => {
    const items = [];

    if (activeArch === "x86" || activeArch === "x64") {
        items.push(
            ...instructions_x86_and_x64.map(i => ({
                label: i,
                kind: CompletionItemKind.Keyword,
                detail: `x86/x64 instruction`
            }))
        );

        items.push(
            ...registers_x86_and_x64.map(r => ({
                label: r,
                kind: CompletionItemKind.Variable,
                detail: `x86/x64 register`
            }))
        );
    }

    if (activeArch === "pvcpu") {
        items.push(
            ...instructions_pvcpu.map(i => ({
                label: i,
                kind: CompletionItemKind.Keyword,
                detail: "PVCpu instruction"
            }))
        );

        items.push(
            ...registers_pvcpu.map(r => ({
                label: r,
                kind: CompletionItemKind.Variable,
                detail: "PVCpu register"
            }))
        );
    }

    return items;
});

let timeout;

documents.onDidChangeContent(change => {
    clearTimeout(timeout);

    timeout = setTimeout(() => {
        const text = change.document.getText();
        const diagnostics = validate(text, activeInstructions, activeRegisters);
        connection.sendDiagnostics({
            uri: change.document.uri,
            diagnostics
        });
    }, 50);
});

documents.listen(connection);
connection.listen();