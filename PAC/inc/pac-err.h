#pragma once

#define PAC_ERR

#include <pac-extra.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

typedef enum {
    PAC_ERROR,
    PAC_WARNING,
    PAC_NOTE,
    PAC_TIP
} PACDiagLevel;

static inline char* pac_get_line(const char* src, size_t pos) {
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

static inline void pac_diag(
    PACDiagLevel level,
    const char* file,
    int line,
    int column,
    const char* src,
    size_t src_len,
    const char* lexeme, // offending token
    int lexeme_len,
    const char* msg 
)
{
    const int MAX_LINE_WIDTH = 80;
    char lvl[120];
    char* color = COLOR_RED;

    (void)lexeme; // Tell compiler "Bro, I know this param is unsed, CHILL!!"
    (void)lexeme_len;

    switch(level) {
        case PAC_ERROR:
            snprintf(lvl, sizeof(lvl), COLOR_RED "error:");
            color = COLOR_RED;
            break;
        case PAC_NOTE:
            snprintf(lvl, sizeof(lvl), COLOR_CYAN "note:");
            color = COLOR_CYAN;
            break;
        case PAC_TIP:
            snprintf(lvl, sizeof(lvl), COLOR_BLUE "tip:");
            color = COLOR_BLUE;
            break;
        case PAC_WARNING:
            snprintf(lvl, sizeof(lvl), COLOR_YELLOW "warning:");
            color = COLOR_YELLOW;
            break;
        default:
            snprintf(lvl, sizeof(lvl), COLOR_RED "error:");
            break;
    }

    fprintf(stderr, "%s:%d:%d: %s %s\n" COLOR_RESET, file, line, column, lvl, msg);

    if (src != NULL && src_len != 0 && line != 0) {
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
                int caret_offset = strlen(prefixstr) + column;
                char output[MAX_LINE_WIDTH];
                if (caret_offset > MAX_LINE_WIDTH - 1) return;
                memset(output, ' ', caret_offset);
                output[caret_offset] = '^';
                output[caret_offset + 1] = '\0';
                fprintf(stderr, "%s%s\n" COLOR_RESET, color, output);
            }
        }

        freeliness(src_lines, src_linecount);
    }
}

#define PAC_ERROR(file, line, col, src, src_len, lex, len, msg) pac_diag_ex(PAC_ERR_ERROR, file, line, col, src, src_len, lex, len, msg)

#define PAC_WARNING(file, line, col, src, src_len, lex, len, msg) pac_diag_ex(PAC_ERR_WARNING, file, line, col, src, src_len, lex, len, msg)

#define PAC_NOTE(file, line, col, src, src_len, lex, len, msg) pac_diag_ex(PAC_ERR_NOTE, file, line, col, src, src_len, lex, len, msg)

#define PAC_TIP(file, line, col, src, src_len, lex, len, msg) pac_diag_ex(PAC_ERR_TIP, file, line, col, src, src_len, lex, len, msg)

typedef enum PAC_Errors
{
    /* ============================================================
     * CATEGORY 1: GENERAL ERRORS
     * Range: 0x0000 - 0x00FF
     * ============================================================ */
    PAC_Success = 0,                         // No error occurred, operation successful
    PAC_GeneralError_Start = 0x0001,         // Marker: Start of General Errors

    PAC_Error_Unknown,                       // Unspecified or unknown error
    PAC_Error_NotImplemented,                // Feature not yet implemented
    PAC_Error_InvalidOperation,              // Invalid or unsupported operation
    PAC_Error_NullPointer,                   // Null pointer encountered where not allowed
    PAC_Error_OutOfMemory,                   // Memory allocation failed
    PAC_Error_IndexOutOfRange,               // Index exceeds buffer or array bounds
    PAC_Error_Overflow,                      // Arithmetic or data overflow
    PAC_Error_Underflow,                     // Arithmetic or data underflow
    PAC_Error_TypeMismatch,                  // Generic type or data mismatch
    PAC_Error_InvalidParameter,              // Parameter provided is invalid or out of range
    PAC_Error_UnsupportedFeature,            // Feature not supported by current mode or target
    PAC_Error_InitializationFailed,          // Initialization routine failed
    PAC_Error_ResourceBusy,                  // Resource locked or busy
    PAC_Error_Timeout,                       // Operation timed out
    PAC_Error_StateInvalid,                  // Invalid internal or external state
    PAC_Error_ConfigurationInvalid,          // Invalid or corrupt configuration
    PAC_Error_DependencyMissing,             // Missing dependency or library
    PAC_Error_InternalConsistency,           // Internal consistency or invariant violation
    PAC_Error_PlatformNotSupported,          // Host platform not supported

    PAC_GeneralError_End = 0x00FF,           // Marker: End of General Errors

        /* ============================================================
     * CATEGORY 2: LEXICAL ERRORS
     * Range: 0x0100 - 0x01FF
     * ============================================================ */
    PAC_LexicalError_Start = 0x0100,         // Marker: Start of Lexical Errors

    PAC_Error_InvalidCharacter,              // Illegal or unrecognized character in source
    PAC_Error_InvalidEscapeSequence,         // Invalid escape sequence in string or char literal
    PAC_Error_UnterminatedString,            // String literal not properly closed
    PAC_Error_UnterminatedComment,           // Comment block not properly closed
    PAC_Error_InvalidNumberLiteral,          // Invalid number literal format
    PAC_Error_InvalidIdentifier,             // Identifier contains illegal characters
    PAC_Error_UnexpectedEOF,                 // Unexpected end of file during lexing
    PAC_Error_TooLongIdentifier,             // Identifier exceeds maximum allowed length
    PAC_Error_TooLongLiteral,                // String or numeric literal too long
    PAC_Error_IllegalToken,                  // Token cannot be recognized or parsed
    PAC_Error_EncodingMismatch,              // Source file encoding mismatch or corruption
    PAC_Error_InvalidDirectiveToken,         // Invalid or malformed directive token
    PAC_Error_UnexpectedToken,               // Unexpected token encountered in stream
    PAC_Error_MisplacedToken,                // Token found in invalid lexical context
    PAC_Error_ReservedWordUsedAsIdentifier,  // Attempt to use reserved keyword as identifier
    PAC_Error_IllegalWhitespace,             // Illegal or unexpected whitespace character
    PAC_Error_InvalidPreprocessorSymbol,     // Invalid character in macro or preprocessor name
    PAC_Error_InvalidNumericBase,            // Unsupported numeric literal base (e.g., invalid hex)
    PAC_Error_InvalidCommentNesting,         // Comment nesting not allowed in current mode
    PAC_Error_ExcessiveTokenLength,          // Token exceeds maximum buffer or token length

    PAC_LexicalError_End = 0x01FF,           // Marker: End of Lexical Errors


    /* ============================================================
     * CATEGORY 3: SYNTAX ERRORS
     * Range: 0x0200 - 0x02FF
     * ============================================================ */
    PAC_SyntaxError_Start = 0x0200,          // Marker: Start of Syntax Errors

    PAC_Error_SyntaxUnexpectedToken,         // Unexpected token in current parsing context
    PAC_Error_SyntaxMissingOperand,          // Operand expected but not found
    PAC_Error_SyntaxMissingComma,            // Missing comma between operands or parameters
    PAC_Error_SyntaxMissingColon,            // Missing colon in label or directive
    PAC_Error_SyntaxMissingDirectiveArg,     // Directive missing required argument
    PAC_Error_SyntaxInvalidLabel,            // Invalid or malformed label syntax
    PAC_Error_SyntaxDuplicateLabel,          // Duplicate label in same scope
    PAC_Error_SyntaxUnexpectedEOL,           // Unexpected end of line in statement
    PAC_Error_SyntaxUnexpectedEOF,           // Unexpected end of file in statement
    PAC_Error_SyntaxMismatchedParentheses,   // Mismatched or unbalanced parentheses
    PAC_Error_SyntaxMismatchedBrackets,      // Mismatched brackets or braces
    PAC_Error_SyntaxUnexpectedKeyword,       // Keyword in invalid context
    PAC_Error_SyntaxMisplacedDirective,      // Directive not allowed in this section
    PAC_Error_SyntaxInvalidInstructionForm,  // Invalid syntax for instruction mnemonic
    PAC_Error_SyntaxTooManyOperands,         // Too many operands for instruction
    PAC_Error_SyntaxTooFewOperands,          // Not enough operands for instruction
    PAC_Error_SyntaxInvalidDelimiter,        // Invalid use of separator or punctuation
    PAC_Error_SyntaxUnexpectedIndentation,   // Unexpected indentation or alignment
    PAC_Error_SyntaxDuplicateDefinition,     // Repeated or conflicting definition
    PAC_Error_SyntaxInvalidExpression,       // Malformed arithmetic or logical expression
    PAC_Error_SyntaxInvalidStructure,        // Invalid struct/union declaration syntax
    PAC_Error_SyntaxInvalidFunctionDecl,     // Malformed function declaration or prototype
    PAC_Error_SyntaxDirectiveMisuse,         // Misuse of assembler directive
    PAC_Error_SyntaxSegmentMisplaced,        // Segment or section directive misplaced
    PAC_Error_SyntaxUnexpectedString,        // String literal used where not allowed
    PAC_Error_SyntaxInvalidMacroInvocation,  // Invalid macro syntax or argument pattern
    PAC_Error_SyntaxInvalidOperandType,      // Operand type not allowed for instruction form
    PAC_Error_SyntaxMissingStatement,        // Expected statement not found
    PAC_Error_SyntaxStatementTooLong,        // Statement length exceeds limit
    PAC_Error_SyntaxInvalidSymbolName,       // Invalid symbol name syntax
    PAC_Error_SyntaxMisalignedOperands,      // Operands improperly aligned or formatted
    PAC_Error_SyntaxUnexpectedDirectiveEnd,  // Unexpected end directive encountered

    PAC_SyntaxError_End = 0x02FF,            // Marker: End of Syntax Errors

        /* ============================================================
     * CATEGORY 4: SEMANTIC ERRORS
     * Range: 0x0300 - 0x03FF
     * ============================================================ */
    PAC_SemanticError_Start = 0x0300,        // Marker: Start of Semantic Errors

    PAC_Error_SymbolUndefined,               // Reference to undefined symbol
    PAC_Error_SymbolRedefinition,            // Multiple conflicting symbol definitions
    PAC_Error_SymbolTypeMismatch,            // Symbol type differs between declarations
    PAC_Error_SymbolScopeConflict,           // Symbol declared in invalid scope
    PAC_Error_SymbolForwardReference,        // Invalid or illegal forward reference
    PAC_Error_TypeResolutionFailed,          // Could not resolve type or data kind
    PAC_Error_TypeMismatchAssignment,        // Mismatched types in assignment or directive
    PAC_Error_ConstModification,             // Attempt to modify a constant value
    PAC_Error_ImmutableDataChange,           // Attempt to write to read-only data section
    PAC_Error_ExpressionEvaluationFailed,    // Expression cannot be evaluated statically
    PAC_Error_ExpressionOverflow,            // Expression value out of valid range
    PAC_Error_ExpressionDivisionByZero,      // Division by zero in constant expression
    PAC_Error_InvalidCast,                   // Illegal or unsupported type cast
    PAC_Error_InvalidReference,              // Invalid or dangling reference
    PAC_Error_InvalidPointerOperation,       // Pointer arithmetic or dereference invalid
    PAC_Error_UndefinedStructureMember,      // Structure member not found
    PAC_Error_DuplicateStructureMember,      // Duplicate member name in structure
    PAC_Error_InvalidStructureInitialization,// Improper struct/union initialization
    PAC_Error_FunctionUndefined,             // Function not declared or defined
    PAC_Error_FunctionRedefinition,          // Duplicate or conflicting function definition
    PAC_Error_FunctionParameterMismatch,     // Function called with mismatched arguments
    PAC_Error_FunctionReturnTypeMismatch,    // Function returns wrong type
    PAC_Error_CallToNonFunction,             // Attempt to call non-function symbol
    PAC_Error_VariableShadowing,             // Symbol shadows existing variable
    PAC_Error_ConstantReassignment,          // Attempt to reassign constant symbol
    PAC_Error_LabelNotReachable,             // Unreachable label or code block
    PAC_Error_CodeUnreachable,               // Statement never executed due to flow
    PAC_Error_InvalidBranchTarget,           // Invalid or out-of-range branch target
    PAC_Error_UndefinedSectionReference,     // Reference to undefined section
    PAC_Error_InvalidAlignment,              // Data misaligned for type or architecture
    PAC_Error_InvalidRelocation,             // Invalid relocation type or target
    PAC_Error_CircularDependency,            // Cyclic dependency between modules or symbols
    PAC_Error_SectionRedefinition,           // Section or segment redefined inconsistently
    PAC_Error_DataOverlap,                   // Two data items overlap in memory space
    PAC_Error_ExternResolutionFailed,        // External symbol could not be resolved
    PAC_Error_LinkageConflict,               // Inconsistent linkage specifiers
    PAC_Error_SemanticInvalidDirective,      // Directive semantically invalid
    PAC_Error_SemanticConstantExpected,      // Expected constant expression but got variable
    PAC_Error_SemanticInvalidInitializer,    // Invalid initializer for symbol
    PAC_Error_DeferredResolutionFailed,      // Post-parse symbol resolution failed

    PAC_SemanticError_End = 0x03FF,          // Marker: End of Semantic Errors


    /* ============================================================
     * CATEGORY 5: ARCHITECTURE ERRORS
     * Range: 0x0400 - 0x04FF
     * ============================================================ */
    PAC_ArchitectureError_Start = 0x0400,    // Marker: Start of Architecture Errors

    PAC_Error_InvalidInstruction,            // Unknown or unsupported instruction mnemonic
    PAC_Error_InvalidOpcode,                 // Opcode not valid for selected CPU mode
    PAC_Error_InstructionNotSupported,       // Instruction unsupported on target architecture
    PAC_Error_InstructionSizeMismatch,       // Instruction size incompatible with operands
    PAC_Error_InvalidRegister,               // Invalid or undefined register name
    PAC_Error_RegisterClassMismatch,         // Register class mismatch for instruction
    PAC_Error_RegisterOutOfRange,            // Register index exceeds architecture limit
    PAC_Error_InvalidAddressingMode,         // Addressing mode not supported by instruction
    PAC_Error_IncompatibleAddressingMode,    // Addressing mode not compatible with operands
    PAC_Error_MisalignedAddress,             // Memory address not aligned for access size
    PAC_Error_ImmediateOutOfRange,           // Immediate value exceeds valid range
    PAC_Error_InvalidSegment,                // Invalid or non-existent segment/section
    PAC_Error_InvalidMemoryAccessSize,       // Invalid access size (e.g., word/byte mismatch)
    PAC_Error_UnalignedMemoryAccess,         // Access requires alignment not met
    PAC_Error_InvalidInstructionFormat,      // Encoding or form not valid for instruction
    PAC_Error_InvalidInstructionCombination, // Combination of instruction modifiers invalid
    PAC_Error_InvalidFlagUsage,              // Illegal flag or condition code usage
    PAC_Error_IncompatibleArchitectureMode,  // Opcode or operand incompatible with mode
    PAC_Error_MissingArchitectureContext,    // Architecture context (ISA, CPU) not defined
    PAC_Error_ArchitectureFeatureUnavailable,// CPU feature or extension not enabled
    PAC_Error_InvalidRelocationType,         // Relocation not valid for architecture
    PAC_Error_InvalidSectionAlignment,       // Section alignment not compatible with ISA rules
    PAC_Error_InvalidEndianConversion,       // Invalid byte order or endianness usage
    PAC_Error_InstructionRequiresPrivilege,  // Instruction requires elevated privilege level
    PAC_Error_PrivilegedInstructionInUserMode,// Privileged instruction in user mode
    PAC_Error_InvalidPipelineCombination,    // Illegal combination of pipeline stages (if simulated)
    PAC_Error_InvalidRegisterBank,           // Register bank reference invalid
    PAC_Error_InvalidVectorSize,             // Vector register size invalid for instruction
    PAC_Error_IncompatibleExtension,         // Conflicting ISA extensions or modes
    PAC_Error_InstructionEncodingFailed,     // Failed to encode instruction
    PAC_Error_InstructionDecodingFailed,     // Failed to decode binary to instruction
    PAC_Error_ArchitectureNotSupported,      // Target architecture not supported by assembler
    PAC_Error_FeatureConflict,               // Conflicting architecture features or modes
    PAC_Error_MissingArchitectureDefinition, // Architecture or target definition not loaded
    PAC_Error_InvalidMachineMode,            // Invalid CPU machine or privilege mode
    PAC_Error_ArchitectureResourceLimit,     // Architecture resource exhausted (e.g., registers)
    PAC_Error_IllegalInstructionCombination, // Instruction combination illegal per ISA
    PAC_Error_InvalidISAStateTransition,     // Illegal mode/state switch within ISA

    PAC_ArchitectureError_End = 0x04FF,      // Marker: End of Architecture Errors

        /* ============================================================
     * CATEGORY 6: MEMORY & LINKING ERRORS
     * Range: 0x0500 - 0x05FF
     * ============================================================ */
    PAC_MemoryError_Start = 0x0500,          // Marker: Start of Memory & Linking Errors

    PAC_Error_MemoryAllocationFailed,        // malloc() or allocation failed
    PAC_Error_MemoryReallocationFailed,      // realloc() failed or returned NULL
    PAC_Error_MemoryDeallocationFailed,      // free() or release failed
    PAC_Error_MemoryLeakDetected,            // Memory leak detected during cleanup
    PAC_Error_MemoryCorruption,              // Heap corruption detected
    PAC_Error_MemoryDoubleFree,              // Double free or invalid pointer release
    PAC_Error_MemoryOutOfRange,              // Memory access outside allocated bounds
    PAC_Error_MemoryAlignmentFault,          // Address alignment error
    PAC_Error_MemoryPageFault,               // Access to invalid memory page
    PAC_Error_MemoryWriteToConst,            // Attempt to write to const or read-only memory
    PAC_Error_MemoryZeroAllocation,          // Attempted to allocate 0 bytes
    PAC_Error_BufferOverflow,                // Buffer overflow detected
    PAC_Error_BufferUnderflow,               // Buffer underflow (read before start)
    PAC_Error_InvalidHeapPointer,            // Invalid heap pointer passed to allocator
    PAC_Error_MemoryExhausted,               // System or allocator out of memory
    PAC_Error_InvalidMemoryPool,             // Invalid or uninitialized memory pool used
    PAC_Error_HeapFragmentation,             // Severe heap fragmentation detected
    PAC_Error_InvalidSectionReference,       // Section reference invalid or null
    PAC_Error_SectionNotFound,               // Referenced section not found
    PAC_Error_SectionAlreadyExists,          // Attempt to redefine section
    PAC_Error_SectionReadOnly,               // Write attempt to read-only section
    PAC_Error_SectionFull,                   // Section has no space for new data
    PAC_Error_RelocationFailed,              // Relocation process failed
    PAC_Error_RelocationOverflow,            // Relocation offset out of range
    PAC_Error_RelocationUndefinedSymbol,     // Symbol required by relocation not defined
    PAC_Error_RelocationInvalidType,         // Unsupported relocation type for target
    PAC_Error_RelocationOutOfBounds,         // Relocation address out of section bounds
    PAC_Error_InvalidLinkerDirective,        // Invalid linker or segment directive
    PAC_Error_MissingEntryPoint,             // No valid entry point defined
    PAC_Error_DuplicateEntryPoint,           // Multiple entry points defined
    PAC_Error_LinkerSymbolConflict,          // Symbol collision during link
    PAC_Error_LinkerResolutionFailed,        // Linker failed to resolve all externals
    PAC_Error_OutputWriteFailed,             // Failed to write final output binary
    PAC_Error_InvalidBinaryFormat,           // Output format invalid or corrupted
    PAC_Error_OutputFileLocked,              // Output file locked or in use
    PAC_Error_OutputFileAccessDenied,        // Output file permission denied
    PAC_Error_OutputFileCorrupted,           // Generated binary file corrupted
    PAC_Error_ExecutableNotLoadable,         // Resulting binary cannot be executed
    PAC_Error_InvalidObjectFile,             // Invalid or malformed object file
    PAC_Error_UnsupportedObjectFormat,       // Object file format not supported
    PAC_Error_InvalidSectionLayout,          // Section alignment/layout invalid
    PAC_Error_ArchiveCorrupted,              // Archive (.lib/.a) file corrupted
    PAC_Error_InvalidSymbolTable,            // Symbol table inconsistent or malformed
    PAC_Error_MissingRelocationTable,        // Expected relocation table not found
    PAC_Error_LinkerScriptError,             // Linker script syntax or semantic error
    PAC_Error_MemoryAccessViolation,         // Memory access violation during linking
    PAC_Error_LinkerOutOfMemory,             // Linker memory exhausted
    PAC_Error_InvalidSegmentAlignment,       // Segment misaligned
    PAC_Error_CodeOverflow,                  // Code section exceeds maximum capacity

    PAC_MemoryError_End = 0x05FF,            // Marker: End of Memory & Linking Errors


    /* ============================================================
     * CATEGORY 7: FUNCTION, STRUCTURE & ARGUMENT ERRORS
     * Range: 0x0600 - 0x06FF
     * ============================================================ */
    PAC_FunctionError_Start = 0x0600,        // Marker: Start of Function, Structure & Argument Errors

    /* --- Function-related errors --- */
    PAC_Error_FunctionNotFound,              // Referenced function not declared
    PAC_Error_FunctionRedefined,             // Duplicate function definition
    PAC_Error_FunctionCallMismatch,          // Call does not match declaration signature
    PAC_Error_FunctionTooManyArgs,           // Too many arguments in call
    PAC_Error_FunctionTooFewArgs,            // Missing required arguments
    PAC_Error_FunctionInvalidReturnType,     // Invalid return type for declared function
    PAC_Error_FunctionReturnMissing,         // Missing return statement in non-void function
    PAC_Error_FunctionNestingInvalid,        // Function declared within another illegally
    PAC_Error_FunctionRecursionNotAllowed,   // Recursive function call not supported
    PAC_Error_FunctionInlineConflict,        // Inline and non-inline definition conflict
    PAC_Error_FunctionOverloadConflict,      // Overloaded function with incompatible signatures
    PAC_Error_FunctionCallInConstantContext, // Function call not allowed in constant expression
    PAC_Error_FunctionFrameCorrupted,        // Stack or frame pointer invalid
    PAC_Error_FunctionParameterCorruption,   // Parameter corruption during call
    PAC_Error_FunctionBodyMissing,           // Declared function missing implementation

    /* --- Structure & type errors --- */
    PAC_Error_StructNotDefined,              // Struct/union type not declared
    PAC_Error_StructRedefinition,            // Conflicting struct definition
    PAC_Error_StructMemberUndefined,         // Referenced struct member not found
    PAC_Error_StructMemberDuplicate,         // Duplicate member name in struct
    PAC_Error_StructIncomplete,              // Struct has incomplete or missing fields
    PAC_Error_StructTooLarge,                // Struct size exceeds architecture limit
    PAC_Error_StructAlignmentInvalid,        // Struct alignment invalid for target
    PAC_Error_StructInitializationInvalid,   // Struct initialization does not match layout
    PAC_Error_StructCircularReference,       // Struct references itself recursively
    PAC_Error_UnionMemberConflict,           // Conflicting union members overlap improperly

    /* --- Argument / Parameter errors --- */
    PAC_Error_ArgumentMissing,               // Argument expected but not provided
    PAC_Error_ArgumentInvalidType,           // Argument has incompatible type
    PAC_Error_ArgumentOutOfRange,            // Argument value outside allowed range
    PAC_Error_ArgumentHasNoValue,            // Argument defined but has no value assigned
    PAC_Error_ArgumentInvalidUsage,          // Argument used in wrong context
    PAC_Error_ArgumentRedefined,             // Argument redefined within same call
    PAC_Error_ArgumentKeywordConflict,       // Argument name conflicts with keyword
    PAC_Error_ArgumentUninitialized,         // Argument used before initialization
    PAC_Error_ArgumentExcessive,             // Too many arguments passed
    PAC_Error_ArgumentNameMissing,           // Expected argument name missing
    PAC_Error_ArgumentInvalidFormat,         // Invalid argument literal or format
    PAC_Error_ArgumentPointerNull,           // Null argument pointer
    PAC_Error_ArgumentRequired,              // Required argument omitted
    PAC_Error_ArgumentUnexpected,            // Argument passed but not expected
    PAC_Error_ArgumentValueInvalid,          // Invalid argument value
    PAC_Error_ArgumentDefaultInvalid,        // Default argument initialization invalid

    /* --- Allocation & Resource-related --- */
    PAC_Error_ResourceAllocationFailed,      // Failed to allocate internal resource
    PAC_Error_ResourceHandleInvalid,         // Invalid or stale resource handle
    PAC_Error_ResourceReleaseFailed,         // Failed to release allocated resource
    PAC_Error_ResourcePoolEmpty,             // No available resources in pool
    PAC_Error_ResourceLimitExceeded,         // Resource limit reached
    PAC_Error_StackOverflow,                 // Stack exceeded capacity
    PAC_Error_StackUnderflow,                // Stack empty when value expected
    PAC_Error_HeapCorruptionDetected,        // Heap corruption detected in function call
    PAC_Error_InvalidFramePointer,           // Frame pointer corrupted or misaligned
    PAC_Error_StackFrameCorrupted,           // Call stack frame data invalid

    PAC_FunctionError_End = 0x06FF,          // Marker: End of Function, Structure & Argument Errors

        /* ============================================================
     * CATEGORY 8: I/O & FILE ERRORS
     * Range: 0x0700 - 0x07FF
     * ============================================================ */
    PAC_IOError_Start = 0x0700,              // Marker: Start of I/O & File Errors

    PAC_Error_FileNotFound,                  // File could not be located
    PAC_Error_FileAccessDenied,              // Permission denied for file operation
    PAC_Error_FileAlreadyExists,             // File exists when creating new
    PAC_Error_FileReadFailed,                // Failed to read from file
    PAC_Error_FileWriteFailed,               // Failed to write to file
    PAC_Error_FileSeekFailed,                // Failed to seek within file
    PAC_Error_FileTruncateFailed,            // Failed to truncate file
    PAC_Error_FileLockFailed,                // Failed to lock file for exclusive access
    PAC_Error_FileUnlockFailed,              // Failed to unlock file
    PAC_Error_FileCorrupted,                 // File appears corrupted or invalid
    PAC_Error_FileFormatUnsupported,         // File format not supported
    PAC_Error_FileEOFUnexpected,             // Unexpected end-of-file encountered
    PAC_Error_FileBufferOverflow,            // Buffer too small to read/write file
    PAC_Error_FileNameTooLong,               // File name exceeds allowed length
    PAC_Error_FilePathInvalid,               // File path invalid or malformed
    PAC_Error_FileOpenFailed,                // Failed to open file
    PAC_Error_FileCloseFailed,               // Failed to close file
    PAC_Error_FileDeleteFailed,              // Failed to delete file
    PAC_Error_FilePermissionConflict,        // Conflicting file permissions
    PAC_Error_DirectoryNotFound,             // Directory not found
    PAC_Error_DirectoryCreateFailed,         // Failed to create directory
    PAC_Error_DirectoryAccessDenied,         // Directory access denied
    PAC_Error_DirectoryNotEmpty,             // Attempt to remove non-empty directory
    PAC_Error_IOBufferInvalid,               // I/O buffer invalid or null
    PAC_Error_IODeviceUnavailable,           // I/O device not accessible
    PAC_Error_IOTimeout,                     // I/O operation timed out
    PAC_Error_IOOperationInterrupted,        // I/O operation interrupted
    PAC_Error_IOInvalidParameter,            // Invalid parameter for I/O function
    PAC_Error_IOReadWriteConflict,           // Read/write conflict on same resource
    PAC_Error_IOUnexpectedError,             // Generic unexpected I/O error

    PAC_IOError_End = 0x07FF,                // Marker: End of I/O & File Errors


    /* ============================================================
     * CATEGORY 9: DIRECTIVE & MACRO ERRORS
     * Range: 0x0800 - 0x08FF
     * ============================================================ */
    PAC_DirectiveError_Start = 0x0800,       // Marker: Start of Directive & Macro Errors

    PAC_Error_DirectiveUnknown,              // Directive not recognized
    PAC_Error_DirectiveMissingArgument,      // Directive missing required argument
    PAC_Error_DirectiveInvalidArgument,      // Directive argument invalid
    PAC_Error_DirectiveRedefinition,         // Directive redefined in invalid context
    PAC_Error_DirectiveIllegalContext,       // Directive used in invalid location
    PAC_Error_MacroUndefined,                // Macro not declared
    PAC_Error_MacroRedefinition,             // Macro redefined
    PAC_Error_MacroArgumentMismatch,         // Number/type of macro args mismatch
    PAC_Error_MacroRecursionNotAllowed,      // Recursive macro invocation prohibited
    PAC_Error_MacroExpansionFailed,          // Macro expansion failed
    PAC_Error_MacroInvalidUsage,             // Macro used in invalid context
    PAC_Error_MacroParameterMissing,         // Macro parameter expected but missing
    PAC_Error_MacroParameterRedefined,       // Macro parameter redefined within macro
    PAC_Error_MacroParameterUnused,          // Parameter defined but not used
    PAC_Error_MacroTooManyArguments,         // Excessive macro arguments
    PAC_Error_MacroTooFewArguments,          // Not enough macro arguments
    PAC_Error_DirectiveDeprecated,           // Directive is deprecated
    PAC_Error_DirectiveUnsupported,          // Directive not supported in current mode
    PAC_Error_ConditionalDirectiveMismatch,  // #if/#endif mismatch
    PAC_Error_IncludeFileNotFound,           // Included file not found
    PAC_Error_IncludeFileCircular,           // Circular inclusion detected
    PAC_Error_IncludeFileInvalid,            // Included file invalid or corrupted
    PAC_Error_PragmaUnsupported,             // Unsupported pragma directive
    PAC_Error_PragmaInvalid,                 // Invalid pragma syntax
    PAC_Error_RepeatDirectiveInvalid,        // .repeat/.endrepeat misuse
    PAC_Error_MacroInfiniteExpansion,        // Macro expansion exceeds limit
    PAC_Error_DirectiveArgumentConflict,     // Conflicting directive arguments
    PAC_Error_MacroInvocationInvalid,        // Macro call invalid
    PAC_Error_DirectiveValueOutOfRange,      // Directive argument exceeds range
    PAC_Error_DirectiveIllegalOperation,     // Directive operation illegal for context

    PAC_DirectiveError_End = 0x08FF,         // Marker: End of Directive & Macro Errors


    /* ============================================================
     * CATEGORY 10: RUNTIME / EMULATION ERRORS
     * Range: 0x0900 - 0x09FF
     * ============================================================ */
    PAC_RuntimeError_Start = 0x0900,         // Marker: Start of Runtime / Emulation Errors

    PAC_Error_RuntimeDivisionByZero,         // Division by zero during execution
    PAC_Error_RuntimeOverflow,               // Arithmetic overflow detected
    PAC_Error_RuntimeUnderflow,              // Arithmetic underflow detected
    PAC_Error_RuntimeInvalidInstruction,     // Executed invalid instruction
    PAC_Error_RuntimeInvalidMemoryAccess,    // Memory access violation
    PAC_Error_RuntimeStackOverflow,          // Stack overflow during execution
    PAC_Error_RuntimeStackUnderflow,         // Stack underflow during execution
    PAC_Error_RuntimeNullPointerDereference, // Dereference of null pointer
    PAC_Error_RuntimeSegmentationFault,      // Access to invalid memory segment
    PAC_Error_RuntimeUninitializedMemory,    // Use of uninitialized memory
    PAC_Error_RuntimeBreakpointHit,          // Breakpoint hit during emulation
    PAC_Error_RuntimeInterruptUnhandled,     // Unhandled interrupt occurred
    PAC_Error_RuntimeIllegalOpcode,          // CPU executed illegal opcode
    PAC_Error_RuntimePrivilegeViolation,     // Privileged instruction in wrong mode
    PAC_Error_RuntimeTimerExpired,           // Timer expired during execution
    PAC_Error_RuntimeInvalidSystemCall,      // System call invalid or unsupported
    PAC_Error_RuntimeIOError,                 // Runtime I/O error
    PAC_Error_RuntimeDivisionOverflow,        // Overflow during division
    PAC_Error_RuntimeFloatingPointError,     // Floating point exception
    PAC_Error_RuntimeInvalidMemoryMapping,   // Invalid memory mapping for execution
    PAC_Error_RuntimeCallFrameCorrupted,     // Call frame corrupted at runtime
    PAC_Error_RuntimeFunctionFailed,         // Function execution failed
    PAC_Error_RuntimeAssertionFailed,        // Runtime assertion failure
    PAC_Error_RuntimeTrap,                   // Trapped exception
    PAC_Error_RuntimeEmulationLimitExceeded, // Exceeded emulation limit
    PAC_Error_RuntimeInfiniteLoopDetected,   // Infinite loop detected
    PAC_Error_RuntimeStackCorruption,        // Stack corrupted during execution

    PAC_RuntimeError_End = 0x09FF,           // Marker: End of Runtime / Emulation Errors


    /* ============================================================
     * CATEGORY 11: INTERNAL & SYSTEM ERRORS
     * Range: 0x0A00 - 0x0AFF
     * ============================================================ */
    PAC_InternalError_Start = 0x0A00,        // Marker: Start of Internal & System Errors

    PAC_Error_InternalNullPointer,           // Internal null pointer detected
    PAC_Error_InternalLogicError,            // Logic invariant violated
    PAC_Error_InternalStateCorrupted,        // Internal state corruption detected
    PAC_Error_InternalAssertionFailed,       // Internal assertion failed
    PAC_Error_InternalInvalidParameter,      // Internal function received invalid parameter
    PAC_Error_InternalBufferOverflow,        // Internal buffer overflow
    PAC_Error_InternalResourceConflict,      // Internal resource conflict
    PAC_Error_InternalUnhandledException,    // Exception not handled internally
    PAC_Error_InternalNotImplemented,        // Feature or method not implemented
    PAC_Error_InternalModuleLoadFailed,      // Internal module failed to load
    PAC_Error_InternalDataCorrupted,         // Internal data corrupted
    PAC_Error_InternalCacheInvalid,          // Cache invalid or inconsistent
    PAC_Error_InternalThreadError,           // Thread or concurrency issue
    PAC_Error_InternalStateMismatch,         // State mismatch detected
    PAC_Error_InternalIndexOutOfRange,       // Internal index out of valid range
    PAC_Error_InternalAllocationFailed,      // Internal allocation failed
    PAC_Error_InternalConfigurationError,    // Invalid configuration detected
    PAC_Error_InternalEventNotHandled,       // Event not handled internally
    PAC_Error_InternalVersionMismatch,       // Internal version mismatch
    PAC_Error_InternalStackOverflow,         // Internal stack overflow
    PAC_Error_InternalStackUnderflow,        // Internal stack underflow
    PAC_Error_InternalDependencyMissing,     // Missing internal dependency
    PAC_Error_InternalFileCorrupted,         // Internal file corrupted
    PAC_Error_InternalSemaphoreError,        // Semaphore or sync object failure
    PAC_Error_InternalTimerError,            // Timer failure
    PAC_Error_InternalIOError,               // Internal I/O failure
    PAC_Error_InternalMemoryLeak,            // Internal memory leak detected
    PAC_Error_InternalUnknownError,          // Unknown internal error occurred

    PAC_InternalError_End = 0x0AFF           // Marker: End of Internal & System Errors
} PAC_Errors;

const char* PAC_ErrorString(PAC_Errors error)
{
    switch (error)
    {
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
