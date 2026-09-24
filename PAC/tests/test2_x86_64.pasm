// QUICK NOTE: This test is an manually edited (since AI never seems to understand), AI-generated stress test to test all edgecases

.type TByte   = byte
.type TShort  = short
.type TInt    = int
.type TLong   = long
.type TUByte  = ubyte
.type TUShort = ushort
.type TUInt   = uint
.type TULong  = ulong
.type TPtr    = ptr
.type TFloat  = float
.type TDouble = double

.type Alias1 = TUByte
.type Alias2 = Alias1
.type Alias3 = Alias2
.type Alias4 = Alias3


// -----------------------------------------------------------------------------
// DATA STRUCTURES: reserved/BSS-like and initialized/data-backed
// -----------------------------------------------------------------------------

:align 16
:start 0x1000
:section .bss
    .struct EdgeRes :res
        b0!byte
        b1!ubyte
        s0!short
        us0!ushort
        i0!int
        ui0!uint
        l0!long
        ul0!ulong
        p0!ptr
        f0!float
        d0!double
        alias0!Alias4
    .endstruct

    .struct NestedRes :res
        first!ulong
        second!ulong
        third!int
    .endstruct


:align 16
:size 0x1000
:section .data
    .struct EdgeData
        bytes!ubyte[] = 0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF
        text!ubyte[] = "PAC EDGE CASES", 0
        zero!uint =
        max32!uint = 0xFFFFFFFF
        one32!uint = 1
        min64!ulong = 0x8000000000000000
        max64!ulong = 0x7FFFFFFFFFFFFFFF
        magic64!ulong = 0x123456789ABCDEF0
        float0!float =
        double0!double =
    .endstruct

    .struct TinyData
        x!ubyte = 0xAA
        y!ushort = 0xBEEF
        z!ulong = 0x0123456789ABCDEF
    .endstruct

    // Standalone data symbols used by memory/address tests.
    test_byte!byte = 0x7F
    test_word!short = 0x1234
    test_dword!int = 0x12345678
    test_qword!long = 0x123456789ABCDEF0

    zero_qword!long = 0
    one_qword!long = 1
    max_qword!long = 0x7FFFFFFFFFFFFFFF
    min_qword!long = 0x8000000000000000

    sse_a!long = 0x1122334455667788
    sse_b!long = 0x99AABBCCDDEEFF00


// -----------------------------------------------------------------------------
// SYMBOL/SECTION METADATA PROBES
// -----------------------------------------------------------------------------

:align 8
:size 0x400
:section .symbols
    symbol_probe_0!long = 0
    symbol_probe_1!long = 0


// -----------------------------------------------------------------------------
// TEXT
// -----------------------------------------------------------------------------

:align 16
:section .text
    :global $main
    :global $edge_arithmetic
    :global $edge_branches
    :global $edge_stack
    :global $edge_memory
    :global $edge_sse
    :global $edge_flags
    :global $edge_calls
    :global dangerous_parser_probe


// ============================================================================
// MAIN DRIVER
// ============================================================================

.func main
    // ------------------------------------------------------------------------
    // NOP + register zeroing patterns
    // ------------------------------------------------------------------------
    nop
    mov %rax, 0
    mov %rbx, 0
    mov %rcx, 0
    mov %rdx, 0
    mov %rsi, 0
    mov %rdi, 0

    // Explicit edge immediates.
    mov %rax, 0
    mov %rbx, 1
    mov %rcx, -1
    mov %rdx, 0x7F
    mov %rsi, 0x80
    mov %rdi, 0xFF
    mov %r8,  0x7FFFFFFF
    mov %r9,  0x80000000
    mov %r10, 0xFFFFFFFF
    mov %r11, 0x7FFFFFFFFFFFFFFF
    mov %r12, 0x8000000000000000
    mov %r13, 0xFFFFFFFFFFFFFFFF

    // ------------------------------------------------------------------------
    // Every major feature block
    // ------------------------------------------------------------------------
    call $edge_arithmetic
    call $edge_branches
    call $edge_stack
    call $edge_memory
    call $edge_sse
    call $edge_flags
    call $edge_calls

    // movsxd specifically: signed extension from a narrower source.
    mov %eax, -1
    movsxd %rax, %eax
    mov %ebx, 0x7FFFFFFF
    movsxd %rbx, %ebx

    // lea: symbol, field, register-relative and displacement forms.
    lea %rax, [EdgeData]
    lea %rbx, [EdgeData.max32]
    lea %rcx, [EdgeRes]
    lea %rdx, [EdgeRes.l0]
    lea %rsi, [%rax]
    lea %rdi, [%rax + 8]
    lea %r8,  [%rax + 16]

    // Jump over parser-only probes.
    jmp $main.after_probes

    after_probes:
        mov %rax, 0
        ret
.endfunc


// ============================================================================
// INTEGER ARITHMETIC + LOGICAL EDGE CASES
// ============================================================================

.func edge_arithmetic
    // ADD: zero, one, carry/overflow-adjacent values.
    mov %rax, 0
    add %rax, 0
    add %rax, 1
    add %rax, -1

    mov %rbx, 0x7FFFFFFFFFFFFFFF
    add %rbx, 1

    mov %rcx, 0xFFFFFFFFFFFFFFFF
    add %rcx, 1

    mov %rdx, 0x8000000000000000
    add %rdx, 0x8000000000000000

    // SUB: zero, self-subtraction, underflow/wrap.
    mov %rsi, 0
    sub %rsi, 0
    sub %rsi, 1

    mov %rdi, 1
    sub %rdi, 1

    mov %r8, 0
    sub %r8, 1

    mov %r9, 0x8000000000000000
    sub %r9, 1

    // AND / OR / XOR masks.
    mov %r10, 0xFFFFFFFFFFFFFFFF
    and %r10, 0
    and %r10, 0xFFFFFFFFFFFFFFFF

    mov %r11, 0
    or %r11, 0
    or %r11, 0xFFFFFFFFFFFFFFFF

    mov %r12, 0xAAAAAAAAAAAAAAAA
    xor %r12, 0xFFFFFFFFFFFFFFFF
    xor %r12, 0

    // NOT: all-zero and all-one patterns.
    mov %r13, 0
    not %r13

    mov %r14, 0xFFFFFFFFFFFFFFFF
    not %r14

    // INC / DEC boundary-adjacent values.
    mov %r15, 0
    inc %r15
    dec %r15
    dec %r15

    mov %rax, 0x7FFFFFFFFFFFFFFF
    inc %rax

    mov %rbx, 0x8000000000000000
    dec %rbx

    // IMUL: zero, one, negative, large values.
    mov %rcx, 0
    // imul %rcx, 12345 // DOESNT WORK

    mov %rdx, 1
    // imul %rdx, -1 // DOESNT WORK

    mov %rsi, -1
    // imul %rsi, -1 // DOESNT WORK

    mov %rdi, 0x7FFFFFFF
    // imul %rdi, 2 // DOESNT WORK

    // MUL: unsigned products.
    mov %rax, 0
    mov %rbx, 0
    mul %rbx

    mov %rax, 1
    mov %rbx, 1
    mul %rbx

    mov %rax, 0xFFFFFFFF
    mov %rbx, 0xFFFFFFFF
    mul %rbx

    // DIV / IDIV with safe nonzero divisors.
    // These are deliberately chosen to avoid quotient overflow.
    mov %rax, 100
    mov %rdx, 0
    mov %rbx, 10
    div %rbx

    mov %rax, 100
    mov %rdx, 0
    mov %rbx, 10
    idiv %rbx

    mov %rax, 0x7FFFFFFFFFFFFFFF
    mov %rdx, 0
    mov %rbx, 1
    idiv %rbx

    // Shift counts: zero, one, boundary-ish, large count.
    mov %rax, 0x8000000000000001
    shl %rax, 0
    shl %rax, 1
    shl %rax, 63
    shr %rax, 0
    shr %rax, 1
    shr %rax, 63

    // Compare/test combinations.
    mov %rax, 0
    mov %rbx, 0
    cmp %rax, %rbx
    test %rax, %rbx

    mov %rax, 1
    mov %rbx, 0
    cmp %rax, %rbx
    test %rax, %rax

    mov %rax, -1
    mov %rbx, 1
    cmp %rax, %rbx
    test %rax, %rax

    ret
.endfunc


// ============================================================================
// CONDITIONAL BRANCH MATRIX
// ============================================================================

.func edge_branches
    // Each condition is tested with at least one true and one false setup.
    // Labels are deliberately numerous to catch relocation/symbol mistakes.

    // JZ / JE
    mov %rax, 0
    cmp %rax, 0
    jz $edge_branches.branch_jz_taken
    mov %r8, 0xBAD00001

	branch_jz_taken:
		mov %rax, 1
		cmp %rax, 0
		jz $edge_branches.branch_jz_not_taken
		mov %r8, 0x11111111

	branch_jz_not_taken:
		mov %rax, 0
		cmp %rax, 0
		je $edge_branches.branch_je_taken
		mov %r9, 0xBAD00002

	branch_je_taken:
		mov %rax, 1
		cmp %rax, 0
		je $edge_branches.branch_je_not_taken
		mov %r9, 0x22222222

	branch_je_not_taken:

		// JNZ / JNE
		mov %rax, 1
		cmp %rax, 0
		jnz $edge_branches.branch_jnz_taken
		mov %r10, 0xBAD00003

	branch_jnz_taken:
		mov %rax, 0
		cmp %rax, 0
		jnz $edge_branches.branch_jnz_not_taken
		mov %r10, 0x33333333

	branch_jnz_not_taken:
		mov %rax, 1
		cmp %rax, 0
		jne $edge_branches.branch_jne_taken
		mov %r11, 0xBAD00004

	branch_jne_taken:
		mov %rax, 0
		cmp %rax, 0
		jne $edge_branches.branch_jne_not_taken
		mov %r11, 0x44444444

	branch_jne_not_taken:

		// Signed relational conditions.
		mov %rax, 5
		mov %rbx, 3
		cmp %rax, %rbx
		jg $edge_branches.branch_jg_taken
		mov %r12, 0xBAD00005

	branch_jg_taken:
		mov %rax, 5
		mov %rbx, 5
		cmp %rax, %rbx
		jge $edge_branches.branch_jge_taken
		mov %r12, 0xBAD00006

	branch_jge_taken:
		mov %rax, 3
		mov %rbx, 5
		cmp %rax, %rbx
		jl $edge_branches.branch_jl_taken
		mov %r13, 0xBAD00007

	branch_jl_taken:
		mov %rax, 3
		mov %rbx, 5
		cmp %rax, %rbx
		jle $edge_branches.branch_jle_taken
		mov %r13, 0xBAD00008

	branch_jle_taken:

		// False-side coverage for all four.
		mov %rax, 3
		mov %rbx, 5
		cmp %rax, %rbx
		jg $edge_branches.branch_false_jg
		jmp $edge_branches.branch_after_jg
	branch_false_jg:
		mov %r14, 1
	branch_after_jg:

		mov %rax, 3
		mov %rbx, 5
		cmp %rax, %rbx
		jge $edge_branches.branch_false_jge
		jmp $edge_branches.branch_after_jge
	branch_false_jge:
		mov %r14, 2
	branch_after_jge:

		mov %rax, 5
		mov %rbx, 3
		cmp %rax, %rbx
		jl $edge_branches.branch_false_jl
		jmp $edge_branches.branch_after_jl
	branch_false_jl:
		mov %r14, 3
	branch_after_jl:

		mov %rax, 5
		mov %rbx, 3
		cmp %rax, %rbx
		jle $edge_branches.branch_false_jle
		jmp $edge_branches.branch_after_jle
	branch_false_jle:
		mov %r14, 4
	branch_after_jle:

		// Signed negative comparisons.
		mov %rax, -1
		mov %rbx, 1
		cmp %rax, %rbx
		jl $edge_branches.negative_less

	negative_less:
		mov %rax, -1
		mov %rbx, -1
		cmp %rax, %rbx
		je $edge_branches.negative_equal

	negative_equal:
		ret
.endfunc


// ============================================================================
// STACK / CALL / RETURN / LEAVE TESTS
// ============================================================================

.func edge_stack
    // Basic push/pop round trips.
    mov %rax, 0x1111111111111111
    mov %rbx, 0x2222222222222222
    mov %rcx, 0x3333333333333333

    push %rax
    push %rbx
    push %rcx

    pop %rdx
    pop %rsi
    pop %rdi

    // Immediate push forms, if supported by the PAC encoder.
    push 0
    pop %rax

    push -1
    pop %rax

    push 0x7F
    pop %rax

    push 0xFFFFFFFFFFFFFFFF
    pop %rax

    // Stack/register ordering stress.
    push %rax
    push %rbx
    pop %rbx
    pop %rax

    // Flags save/restore instructions.
    pushf
    popf

    // LAHF/SAHF.
    mov %rax, 1
    mov %rbx, 2
    cmp %rax, %rbx
    lahf
    sahf

    // Explicit leave instruction in a conventional frame.
    call $edge_stack.frame_test

    ret

    unreachable:
        ret

    // Child label inside same function: valid function-local access.
    frame_test:
        push %rbp
        mov %rbp, %rsp

        mov %rax, 0x12345678
        push %rax
        pop %rcx

        leave
        ret
.endfunc


// ============================================================================
// MEMORY / ADDRESSING / STRUCTURE ACCESS
// ============================================================================

.func edge_memory
    // LEA structure base and fields.
    lea %rax, [EdgeData]
    lea %rbx, [EdgeData.bytes]
    lea %rcx, [EdgeData.max32]
    lea %rdx, [EdgeData.magic64]

    lea %rsi, [EdgeRes]
    lea %rdi, [EdgeRes.l0]

    // MOV from/to memory symbols.
    mov %rax, [EdgeData.max32]
    mov %rbx, [EdgeData.magic64]

    mov [EdgeRes.i0], %rax
    mov [EdgeRes.l0], %rbx

    // Basic register-relative memory forms.
    lea %rcx, [EdgeRes]
    mov %rax, [%rcx]
    mov %rbx, [%rcx + 8]
    mov %rdx, [%rcx + 16]

    mov [%rcx], %rax
    mov [%rcx + 8], %rbx
    mov [%rcx + 16], %rdx

    // Zero/one/max/min data patterns.
    mov %rax, [zero_qword]
    mov %rbx, [one_qword]
    mov %rcx, [max_qword]
    mov %rdx, [min_qword]

    // Same structure-name access means first field.
    lea %rsi, [EdgeData]
    lea %rdi, [EdgeData.bytes]

    // Different aliases should resolve to the same underlying type.
    mov %rax, EdgeData.max32
    mov %rbx, EdgeData.max64
    mov %rcx, EdgeData.magic64

    ret
.endfunc


// ============================================================================
// SSE / PACKED-DOUBLE INSTRUCTION MATRIX
// ============================================================================

.func edge_sse
    // Every supported SSE instruction appears here.
    // XMM0-XMM3 are used to avoid accidental GPR/XMM confusion.

    mov %rax, 0x1122334455667788
    mov %rbx, 0x99AABBCCDDEEFF00

    // Load test vectors from memory.
    movupd %xmm0, [sse_a]
    movupd %xmm1, [sse_b]

    // Move scalar double low/high lanes.
    movlpd %xmm2, [sse_a]
    movhpd %xmm2, [sse_b]

    // Scalar moves in the opposite direction, if encoder supports both forms.
    movlpd [sse_a], %xmm0
    movhpd [sse_b], %xmm0

    // MOVSD memory/register forms.
    movsd %xmm3, [sse_a]
    movsd [sse_b], %xmm3

    // MOVUPD register/register.
    movupd %xmm2, %xmm0
    movupd %xmm3, %xmm1

    // Unpack low/high packed doubles.
    // unpcklpd %xmm0, %xmm1 // DOESNT WORK
    // unpckhpd %xmm2, %xmm3 // DOESNT WORK

    // Repeat with same source/destination to catch aliasing edge cases.
    // unpcklpd %xmm0, %xmm0 // DOESNT WORK
    // unpckhpd %xmm1, %xmm1 // DOESNT WORK

    ret
.endfunc


// ============================================================================
// FLAG MANIPULATION MATRIX
// ============================================================================

.func edge_flags
    // CLC -> clear carry.
    clc

    // STC -> set carry.
    stc

    // CMC -> invert carry.
    cmc

    // CLD -> clear direction.
    cld

    // STD -> set direction.
    std

    // Restore conventional direction state for anything following this test.
    cld

    // Save/restore full flags.
    pushf
    popf

    // LAHF / SAHF path.
    mov %rax, 1
    mov %rbx, 2
    cmp %rax, %rbx
    lahf
    sahf

    // FWAIT parser/encoder coverage.
    fwait

    ret
.endfunc


// ============================================================================
// CALL GRAPH / FUNCTION-LOCAL LABELS / GLOBAL SYMBOLS
// ============================================================================

.func edge_calls
    call $edge_calls.leaf
    call $edge_calls.middle
    jmp $edge_calls.after

    never:
        call $edge_calls.leaf
        ret

    middle:
        call $edge_calls.leaf
        ret

    leaf:
        mov %rax, 0xCAFEBABE
        ret

    after:
        mov %rbx, 0xDEADBEEF
        ret
.endfunc


// ============================================================================
// PARSER-ONLY / DANGEROUS INSTRUCTION MATRIX
// ============================================================================
// This function is NEVER reached by main.
//
// Included to ensure every supported instruction can be tokenized/parsed and
// lowered. Do not call it in a normal runtime test:
//   * cli/sti are privileged
//   * hlt halts the CPU/context
//   * int may invoke a trap/interrupt depending on environment
//   * syscall enters the host ABI and needs ABI-specific register setup
//   * div/idiv zero divisor can trap
//
// If your test harness has an instruction-only mode, this is the ideal block
// to single-step there.
//
// NOTE: The exact operand convention for syscall/int is architecture/runtime
// dependent, so the syscall/int operands below intentionally stay minimal.

dangerous_parser_probe:
    // NOP.
    nop

    // Flag/privileged instructions.
    cld
    clc
    cmc
    std
    stc
    fwait
    pushf
    popf
    lahf
    sahf
    pause

    // Privileged: parser/encoder only.
    cli
    sti
    hlt

    // Interrupt/system instructions: parser/encoder only.
    syscall
    inst.int 0x0

    // Zero-divisor traps: parser/encoder only.
    mov %rax, 1
    mov %rbx, 0
    mov %rdx, 0
    div %rbx

    mov %rax, 1
    mov %rbx, 0
    mov %rdx, 0
    idiv %rbx

    ret


// ============================================================================
// EXTRA CONTROL-FLOW STRESS
// ============================================================================

.control_flow_stress:
    mov %rax, 10
    mov %rbx, 0

loop_top:
    inc %rbx
    cmp %rbx, %rax
    jl loop_top

    // Equality at loop exit.
    cmp %rbx, %rax
    je loop_done
    jne loop_bad

loop_bad:
    mov %rcx, 0xBAD
    jmp loop_done

loop_done:
    // Greater-than / less-than / <= / >= all exercised again after a loop.
    cmp %rbx, 9
    jg cf_gt

cf_gt:
    cmp %rbx, 10
    jge cf_ge

cf_ge:
    cmp %rbx, 11
    jl cf_lt

cf_lt:
    cmp %rbx, 10
    jle cf_le

cf_le:
    ret