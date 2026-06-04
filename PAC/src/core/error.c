#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <pac-extra.h>
#include <pac-err.h>

const char* PAC_ErrorString(PAC_Errors error) {
    switch (error) {
        /* =======================
         * CATEGORY 1: GENERAL ERRORS
         * ======================= */
        case PAC_Success: return "No error occurred, operation successful";
        case PAC_Error_Unknown: return "Unspecified or unknown error";
        case PAC_Error_NotImplemented: return "Feature not yet implemented";
        case PAC_Error_InvalidOperation: return "Invalid or unsupported operation";
        case PAC_Error_NullPointer: return "Null pointer encountered where not allowed";
        case PAC_Error_OutOfMemory: return "Memory allocation failed";
        case PAC_Error_IndexOutOfRange: return "Index exceeds buffer or array bounds";
        case PAC_Error_Overflow: return "Arithmetic or data overflow";
        case PAC_Error_Underflow: return "Arithmetic or data underflow";
        case PAC_Error_TypeMismatch: return "Generic type or data mismatch";
        case PAC_Error_InvalidParameter: return "Parameter provided is invalid or out of range";
        case PAC_Error_UnsupportedFeature: return "Feature not supported by current mode or target";
        case PAC_Error_InitializationFailed: return "Initialization routine failed";
        case PAC_Error_ResourceBusy: return "Resource locked or busy";
        case PAC_Error_Timeout: return "Operation timed out";
        case PAC_Error_StateInvalid: return "Invalid internal or external state";
        case PAC_Error_ConfigurationInvalid: return "Invalid or corrupt configuration";
        case PAC_Error_DependencyMissing: return "Missing dependency or library";
        case PAC_Error_InternalConsistency: return "Internal consistency or invariant violation";
        case PAC_Error_PlatformNotSupported: return "Host platform not supported";

        /* =======================
         * CATEGORY 2: LEXICAL ERRORS
         * ======================= */
        case PAC_Error_InvalidCharacter: return "Illegal or unrecognized character in source";
        case PAC_Error_InvalidEscapeSequence: return "Invalid escape sequence in string or char literal";
        case PAC_Error_UnterminatedString: return "String literal not properly closed";
        case PAC_Error_UnterminatedComment: return "Comment block not properly closed";
        case PAC_Error_InvalidNumberLiteral: return "Invalid number literal format";
        case PAC_Error_InvalidIdentifier: return "Identifier contains illegal characters";
        case PAC_Error_UnexpectedEOF: return "Unexpected end of file during lexing";
        case PAC_Error_TooLongIdentifier: return "Identifier exceeds maximum allowed length";
        case PAC_Error_TooLongLiteral: return "String or numeric literal too long";
        case PAC_Error_IllegalToken: return "Token cannot be recognized or parsed";
        case PAC_Error_EncodingMismatch: return "Source file encoding mismatch or corruption";
        case PAC_Error_InvalidDirectiveToken: return "Invalid or malformed directive token";
        case PAC_Error_UnexpectedToken: return "Unexpected token encountered in stream";
        case PAC_Error_MisplacedToken: return "Token found in invalid lexical context";
        case PAC_Error_ReservedWordUsedAsIdentifier: return "Attempt to use reserved keyword as identifier";
        case PAC_Error_IllegalWhitespace: return "Illegal or unexpected whitespace character";
        case PAC_Error_InvalidPreprocessorSymbol: return "Invalid character in macro or preprocessor name";
        case PAC_Error_InvalidNumericBase: return "Unsupported numeric literal base (e.g., invalid hex)";
        case PAC_Error_InvalidCommentNesting: return "Comment nesting not allowed in current mode";
        case PAC_Error_ExcessiveTokenLength: return "Token exceeds maximum buffer or token length";

        /* =======================
         * CATEGORY 3: SYNTAX ERRORS
         * ======================= */
        case PAC_Error_SyntaxUnexpectedToken: return "Unexpected token in current parsing context";
        case PAC_Error_SyntaxMissingOperand: return "Operand expected but not found";
        case PAC_Error_SyntaxMissingComma: return "Missing comma between operands or parameters";
        case PAC_Error_SyntaxMissingColon: return "Missing colon in label or directive";
        case PAC_Error_SyntaxMissingDirectiveArg: return "Directive missing required argument";
        case PAC_Error_SyntaxInvalidLabel: return "Invalid or malformed label syntax";
        case PAC_Error_SyntaxDuplicateLabel: return "Duplicate label in same scope";
        case PAC_Error_SyntaxUnexpectedEOL: return "Unexpected end of line in statement";
        case PAC_Error_SyntaxUnexpectedEOF: return "Unexpected end of file in statement";
        case PAC_Error_SyntaxMismatchedParentheses: return "Mismatched or unbalanced parentheses";
        case PAC_Error_SyntaxMismatchedBrackets: return "Mismatched brackets or braces";
        case PAC_Error_SyntaxUnexpectedKeyword: return "Keyword in invalid context";
        case PAC_Error_SyntaxMisplacedDirective: return "Directive not allowed in this section";
        case PAC_Error_SyntaxInvalidInstructionForm: return "Invalid syntax for instruction mnemonic";
        case PAC_Error_SyntaxTooManyOperands: return "Too many operands for instruction";
        case PAC_Error_SyntaxTooFewOperands: return "Not enough operands for instruction";
        case PAC_Error_SyntaxInvalidDelimiter: return "Invalid use of separator or punctuation";
        case PAC_Error_SyntaxUnexpectedIndentation: return "Unexpected indentation or alignment";
        case PAC_Error_SyntaxDuplicateDefinition: return "Repeated or conflicting definition";
        case PAC_Error_SyntaxInvalidExpression: return "Malformed arithmetic or logical expression";
        case PAC_Error_SyntaxInvalidStructure: return "Invalid struct/union declaration syntax";
        case PAC_Error_SyntaxInvalidFunctionDecl: return "Malformed function declaration or prototype";
        case PAC_Error_SyntaxDirectiveMisuse: return "Misuse of assembler directive";
        case PAC_Error_SyntaxSegmentMisplaced: return "Segment or section directive misplaced";
        case PAC_Error_SyntaxUnexpectedString: return "String literal used where not allowed";
        case PAC_Error_SyntaxInvalidMacroInvocation: return "Invalid macro syntax or argument pattern";
        case PAC_Error_SyntaxInvalidOperandType: return "Operand type not allowed for instruction form";
        case PAC_Error_SyntaxMissingStatement: return "Expected statement not found";
        case PAC_Error_SyntaxStatementTooLong: return "Statement length exceeds limit";
        case PAC_Error_SyntaxInvalidSymbolName: return "Invalid symbol name syntax";
        case PAC_Error_SyntaxMisalignedOperands: return "Operands improperly aligned or formatted";
        case PAC_Error_SyntaxUnexpectedDirectiveEnd: return "Unexpected end directive encountered";

        /* =======================
         * CATEGORY 4: SEMANTIC ERRORS
         * ======================= */
        case PAC_Error_SymbolUndefined: return "Reference to undefined symbol";
        case PAC_Error_SymbolRedefinition: return "Multiple conflicting symbol definitions";
        case PAC_Error_SymbolTypeMismatch: return "Symbol type differs between declarations";
        case PAC_Error_SymbolScopeConflict: return "Symbol declared in invalid scope";
        case PAC_Error_SymbolForwardReference: return "Invalid or illegal forward reference";
        case PAC_Error_TypeResolutionFailed: return "Could not resolve type or data kind";
        case PAC_Error_TypeMismatchAssignment: return "Mismatched types in assignment or directive";
        case PAC_Error_ConstModification: return "Attempt to modify a constant value";
        case PAC_Error_ImmutableDataChange: return "Attempt to write to read-only data section";
        case PAC_Error_ExpressionEvaluationFailed: return "Expression cannot be evaluated statically";
        case PAC_Error_ExpressionOverflow: return "Expression value out of valid range";
        case PAC_Error_ExpressionDivisionByZero: return "Division by zero in constant expression";
        case PAC_Error_InvalidCast: return "Illegal or unsupported type cast";
        case PAC_Error_InvalidReference: return "Invalid or dangling reference";
        case PAC_Error_InvalidPointerOperation: return "Pointer arithmetic or dereference invalid";
        case PAC_Error_UndefinedStructureMember: return "Structure member not found";
        case PAC_Error_DuplicateStructureMember: return "Duplicate member name in structure";
        case PAC_Error_InvalidStructureInitialization: return "Improper struct/union initialization";
        case PAC_Error_FunctionUndefined: return "Function not declared or defined";
        case PAC_Error_FunctionRedefinition: return "Duplicate or conflicting function definition";
        case PAC_Error_FunctionParameterMismatch: return "Function called with mismatched arguments";
        case PAC_Error_FunctionReturnTypeMismatch: return "Function returns wrong type";
        case PAC_Error_CallToNonFunction: return "Attempt to call non-function symbol";
        case PAC_Error_VariableShadowing: return "Symbol shadows existing variable";
        case PAC_Error_ConstantReassignment: return "Attempt to reassign constant symbol";
        case PAC_Error_LabelNotReachable: return "Unreachable label or code block";
        case PAC_Error_CodeUnreachable: return "Statement never executed due to flow";
        case PAC_Error_InvalidBranchTarget: return "Invalid or out-of-range branch target";
        case PAC_Error_UndefinedSectionReference: return "Reference to undefined section";
        case PAC_Error_InvalidAlignment: return "Data misaligned for type or architecture";
        case PAC_Error_InvalidRelocation: return "Invalid relocation type or target";
        case PAC_Error_CircularDependency: return "Cyclic dependency between modules or symbols";
        case PAC_Error_SectionRedefinition: return "Section or segment redefined inconsistently";
        case PAC_Error_DataOverlap: return "Two data items overlap in memory space";
        case PAC_Error_ExternResolutionFailed: return "External symbol could not be resolved";
        case PAC_Error_LinkageConflict: return "Inconsistent linkage specifiers";
        case PAC_Error_SemanticInvalidDirective: return "Directive semantically invalid";
        case PAC_Error_SemanticConstantExpected: return "Expected constant expression but got variable";
        case PAC_Error_SemanticInvalidInitializer: return "Invalid initializer for symbol";
        case PAC_Error_DeferredResolutionFailed: return "Post-parse symbol resolution failed";

        /* =======================
         * CATEGORY 5: ARCHITECTURE ERRORS
         * ======================= */
        case PAC_Error_InvalidInstruction: return "Unknown or unsupported instruction mnemonic";
        case PAC_Error_InvalidOpcode: return "Opcode not valid for selected CPU mode";
        case PAC_Error_InstructionNotSupported: return "Instruction unsupported on target architecture";
        case PAC_Error_InstructionSizeMismatch: return "Instruction size incompatible with operands";
        case PAC_Error_InvalidRegister: return "Invalid or undefined register name";
        case PAC_Error_RegisterClassMismatch: return "Register class mismatch for instruction";
        case PAC_Error_RegisterOutOfRange: return "Register index exceeds architecture limit";
        case PAC_Error_InvalidAddressingMode: return "Addressing mode not supported by instruction";
        case PAC_Error_IncompatibleAddressingMode: return "Addressing mode not compatible with operands";
        case PAC_Error_MisalignedAddress: return "Memory address not aligned for access size";
        case PAC_Error_ImmediateOutOfRange: return "Immediate value exceeds valid range";
        case PAC_Error_InvalidSegment: return "Invalid or non-existent segment/section";
        case PAC_Error_InvalidMemoryAccessSize: return "Invalid access size (e.g., word/byte mismatch)";
        case PAC_Error_UnalignedMemoryAccess: return "Access requires alignment not met";
        case PAC_Error_InvalidInstructionFormat: return "Encoding or form not valid for instruction";
        case PAC_Error_InvalidInstructionCombination: return "Combination of instruction modifiers invalid";
        case PAC_Error_InvalidFlagUsage: return "Illegal flag or condition code usage";
        case PAC_Error_IncompatibleArchitectureMode: return "Opcode or operand incompatible with mode";
        case PAC_Error_MissingArchitectureContext: return "Architecture context (ISA, CPU) not defined";
        case PAC_Error_ArchitectureFeatureUnavailable: return "CPU feature or extension not enabled";
        case PAC_Error_InvalidRelocationType: return "Relocation not valid for architecture";
        case PAC_Error_InvalidSectionAlignment: return "Section alignment not compatible with ISA rules";
        case PAC_Error_InvalidEndianConversion: return "Invalid byte order or endianness usage";
        case PAC_Error_InstructionRequiresPrivilege: return "Instruction requires elevated privilege level";
        case PAC_Error_PrivilegedInstructionInUserMode: return "Privileged instruction in user mode";
        case PAC_Error_InvalidPipelineCombination: return "Illegal combination of pipeline stages";
        case PAC_Error_InvalidRegisterBank: return "Register bank reference invalid";
        case PAC_Error_InvalidVectorSize: return "Vector register size invalid for instruction";
        case PAC_Error_IncompatibleExtension: return "Conflicting ISA extensions or modes";
        case PAC_Error_InstructionEncodingFailed: return "Failed to encode instruction";
        case PAC_Error_InstructionDecodingFailed: return "Failed to decode binary to instruction";
        case PAC_Error_ArchitectureNotSupported: return "Target architecture not supported by assembler";
        case PAC_Error_FeatureConflict: return "Conflicting architecture features or modes";
        case PAC_Error_MissingArchitectureDefinition: return "Architecture or target definition not loaded";
        case PAC_Error_InvalidMachineMode: return "Invalid CPU machine or privilege mode";
        case PAC_Error_ArchitectureResourceLimit: return "Architecture resource exhausted";
        case PAC_Error_IllegalInstructionCombination: return "Instruction combination illegal per ISA";
        case PAC_Error_InvalidISAStateTransition: return "Illegal mode/state switch within ISA";

        /* =======================
         * CATEGORY 6: MEMORY & LINKING ERRORS
         * ======================= */
        case PAC_Error_MemoryAllocationFailed: return "malloc() or allocation failed";
        case PAC_Error_MemoryReallocationFailed: return "realloc() failed or returned NULL";
        case PAC_Error_MemoryDeallocationFailed: return "free() or release failed";
        case PAC_Error_MemoryLeakDetected: return "Memory leak detected during cleanup";
        case PAC_Error_MemoryCorruption: return "Heap corruption detected";
        case PAC_Error_MemoryDoubleFree: return "Double free or invalid pointer release";
        case PAC_Error_MemoryOutOfRange: return "Memory access outside allocated bounds";
        case PAC_Error_MemoryAlignmentFault: return "Address alignment error";
        case PAC_Error_MemoryPageFault: return "Access to invalid memory page";
        case PAC_Error_MemoryWriteToConst: return "Attempt to write to const or read-only memory";
        case PAC_Error_MemoryZeroAllocation: return "Attempted to allocate 0 bytes";
        case PAC_Error_BufferOverflow: return "Buffer overflow detected";
        case PAC_Error_BufferUnderflow: return "Buffer underflow (read before start)";
        case PAC_Error_InvalidHeapPointer: return "Invalid heap pointer passed to allocator";
        case PAC_Error_MemoryExhausted: return "System or allocator out of memory";
        case PAC_Error_InvalidMemoryPool: return "Invalid or uninitialized memory pool used";
        case PAC_Error_HeapFragmentation: return "Severe heap fragmentation detected";
        case PAC_Error_InvalidSectionReference: return "Section reference invalid or null";
        case PAC_Error_SectionNotFound: return "Referenced section not found";
        case PAC_Error_SectionAlreadyExists: return "Attempt to redefine section";
        case PAC_Error_SectionReadOnly: return "Write attempt to read-only section";
        case PAC_Error_SectionFull: return "Section has no space for new data";
        case PAC_Error_RelocationFailed: return "Relocation process failed";
        case PAC_Error_RelocationOverflow: return "Relocation offset out of range";
        case PAC_Error_RelocationUndefinedSymbol: return "Symbol required by relocation not defined";
        case PAC_Error_RelocationInvalidType: return "Unsupported relocation type for target";
        case PAC_Error_RelocationOutOfBounds: return "Relocation address out of section bounds";
        case PAC_Error_InvalidLinkerDirective: return "Invalid linker or segment directive";
        case PAC_Error_MissingEntryPoint: return "No valid entry point defined";
        case PAC_Error_DuplicateEntryPoint: return "Multiple entry points defined";
        case PAC_Error_LinkerSymbolConflict: return "Symbol collision during link";
        case PAC_Error_LinkerResolutionFailed: return "Linker failed to resolve all externals";
        case PAC_Error_OutputWriteFailed: return "Failed to write final output binary";
        case PAC_Error_InvalidBinaryFormat: return "Output format invalid or corrupted";
        case PAC_Error_OutputFileLocked: return "Output file locked or in use";
        case PAC_Error_OutputFileAccessDenied: return "Output file permission denied";
        case PAC_Error_OutputFileCorrupted: return "Generated binary file corrupted";
        case PAC_Error_ExecutableNotLoadable: return "Resulting binary cannot be executed";

        /* =======================
         * Default fallback
         * ======================= */
        default: return "Unknown PAC_Errors code";
    }
}

char* pac_get_line(const char* src, size_t pos) {
    const char* start = src + pos;
    while (start > src && *(start - 1) != '\n') start--;

    const char* end = src + pos;
    while (*end && *end != '\n') end++;

    size_t len = (size_t)(end - start);
    char* line = (char*)malloc(len + 1);
    strncpy(line, start, len);
    line[len] = '\0';
    return line;
}

void pac_diag(
    PACDiagLevel level,
    const char* file,
    int line,
    int column,
    const char* src,
    size_t src_len,
    const char* lexeme, // offending token
    int lexeme_len,
    const char* msg 
) {
    const int MAX_LINE_WIDTH = 80;
    char lvl[120];
    char* color = COLOR_RED;

    switch(level) {
        case PAC_ERROR:
            snprintf(lvl, sizeof(lvl), COLOR_RED "error:");
            color = COLOR_RED;
            break;
        case PAC_NOTE:
            snprintf(lvl, sizeof(lvl), COLOR_BOLD COLOR_CYAN "note:");
            color = COLOR_BOLD COLOR_CYAN;
            break;
        case PAC_TIP:
            snprintf(lvl, sizeof(lvl), COLOR_CYAN "tip:");
            color = COLOR_CYAN;
            break;
        case PAC_WARNING:
            snprintf(lvl, sizeof(lvl), COLOR_YELLOW "warning:");
            color = COLOR_YELLOW;
            break;
        default:
            snprintf(lvl, sizeof(lvl), COLOR_RED "error:");
            break;
    }

	char lbuf[12];
	char cbuf[12];

	if (line > 0) {
		lbuf[0] = ':';
		snprintf(lbuf + 1, sizeof(lbuf)-1, "%d", line);
	} else
		lbuf[0] = '\0';
	if (column > 0) {
		cbuf[0] = ':';
		snprintf(cbuf + 1, sizeof(cbuf)-1, "%d", column);
	} else
		cbuf[0] = '\0';

	lbuf[11] = '\0';
	cbuf[11] = '\0';

    if (lexeme) fprintf(stderr, "%s%s%s: %s %s - (\"%s\")\n" COLOR_RESET, file, lbuf, cbuf, lvl, msg, lexeme);
	else fprintf(stderr, "%s%s%s: %s %s\n" COLOR_RESET, file, lbuf, cbuf, lvl, msg);

    if (src != NULL && src_len > 0 && line > 0) {
        int src_linecount = 0;
        char** src_lines = splitlines(src, &src_linecount);
        if (src_linecount < 1) {
            return;
        }
        int start = line - 2;
        if (start < 1) {
            start = 1;
        }
        int end = line + 1;
        if (end > src_linecount) end = src_linecount;

        for(int ln = start; ln <= end; ln++) {
            char prefix = ' ';
            char* line_color = COLOR_GRAY;
            if (ln == line) {
                prefix = '>';
                line_color = color;
            }

            char prefixstr[30];
            snprintf(prefixstr, sizeof(prefixstr), "%s%c %d | ", line_color, prefix, ln);

            fprintf(stderr, "%s%s\n" COLOR_RESET, prefixstr, src_lines[ln - 1]);
            if (ln == line && column != 0) {
                int caret_offset = ((strlen(prefixstr) - strlen(line_color)) + column) - 1; // Arrays are 0 based
                char output[MAX_LINE_WIDTH];
                if (caret_offset > MAX_LINE_WIDTH - 1) return;
                memset(output, ' ', caret_offset);
				memset(output + caret_offset, '^', lexeme_len > 0 && caret_offset + lexeme_len < MAX_LINE_WIDTH ? lexeme_len : 1);
				size_t nullT = lexeme_len > 0 && caret_offset + lexeme_len < MAX_LINE_WIDTH ? caret_offset + lexeme_len : caret_offset + 1;
				output[nullT] = '\0';
                fprintf(stderr, "%s%s\n" COLOR_RESET, color, output);
            }
        }

        freeliness(src_lines, src_linecount);
    }
}