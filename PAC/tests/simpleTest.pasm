// ==========================================================
//  Phoenix Assembler Collection (PAC) Example Test
//  File: simpleTest.pasm
//  Description: Tests alignment, sections, labels, and datatypes.
//  Compatible with PAC dev0.1
// ==========================================================

// ----------------------------------------------------------
//  SECTION 1: Data Section - default alignment (8 bytes)
// ----------------------------------------------------------

:section .data

msg1!ubyte[] = "Hello World", 10 // string
num1!int   = 1234 // 4 bytes
flag!byte  = 1 // 1 byte

// Alignment test variable
pad!ubyte  = 'A' // char (1 bytes) -> padded up to 8 boundary

// ----------------------------------------------------------
//  SECTION 2: BSS Section - manual alignment override
// ----------------------------------------------------------

:align 32
:section .bss 

:res aligned_msg!ubyte
:res aligned_num!int
:res aligned_long!long
:res aligned_ptr!ptr // test pointer alignment (8 bytes)

// ----------------------------------------------------------
//  SECTION 3: Read-Only Data (rodata)
// ----------------------------------------------------------

:section .rodata

const_msg!ubyte[] = "Hello This is a constant message!", 10
const_val!long = 0x1122334455667788

// ----------------------------------------------------------
//  SECTION 4: Text (Code)
// ----------------------------------------------------------

:section .text
:global main

// main: (MOV tests work)
    // mov %al, %bl
    // mov %ax, %bx
    // mov %eax, %ebx
    // mov %rax, %rbx

    // mov %r8b, %r9b
    // mov %r8w, %r9w
    // mov %r8d, %r9d
    // mov %r8,  %r9

    // mov [%rbx], %rax
    // mov [%rax], %rbx
    // mov [%rcx], %rdx
    // mov [%rdx], %r8

    // mov %rax, [%rbx]
    // mov %rbx, [%rax]
    // mov %rdx, [%rcx]
    // mov %r8, [%rdx]

    // mov %rdx, [%rcx + 0]
    // mov %rdx, [%rcx + 4]
    // mov %rdx, [%rcx + 128]
    // mov %rdx, [%rcx - 4]
    // mov %rdx, [%rcx - 128]

    // mov %rax, [%rbp + 0]
    // mov %rax, [%rbp + 8]
    // mov %rbp, [%rbp + 0]

    // mov %rax, [%rip]
    // mov %rbx, [%rip + 0]
    // mov %rcx, [%rip + 4]
    // mov [%rip], %rax
    // mov [%rip + 0], %rbx

    // mov %r8, %rax
    // mov %rax, %r8

    // mov %r9, %r10
    // mov %r10, %r11

    // mov [%r12], %r13
    // mov %r14, [%r15]

    // mov %rax, [%rbx + 0]
    // mov %rax, [%rbx + 0]
    // mov %rax, [%rbx + 0]

    // mov %rax, %rbx
    // mov %rbx, %rax

    // mov %r8, %r9
    // mov %r9, %r8

main:
    add %al, %bl
    add %ax, %bx
    add %eax, %ebx
    add %rax, %rbx

    add %r8b, %r9b
    add %r8w, %r9w
    add %r8d, %r9d
    add %r8,  %r9

    add %r9, %r10
    add %r10, %r11
    add %r11, %r12
    add %r12, %r13

    add %bl, %al
    add %bx, %ax
    add %ebx, %eax
    add %rbx, %rax

    add %r9b, %r8b
    add %r9w, %r8w
    add %r9d, %r8d
    add %r9,  %r8

    add %rax, [%rbx]
    add %rbx, [%rax]
    add %rcx, [%rdx]
    add %r8,  [%r9]

    add [%rbx], %rax
    add [%rax], %rbx
    add [%rcx], %rdx
    add [%rdx], %r8

    add %rdx, [%rcx + 0]
    add %rdx, [%rcx + 4]
    add %rdx, [%rcx + 16]
    add %rdx, [%rcx + 128]

    add %rdx, [%rcx - 4]
    add %rdx, [%rcx - 16]
    add %rdx, [%rcx - 128]

    add %rax, [%rbp + 0]
    add %rax, [%rbp + 8]
    add %rbp, [%rbp + 0]

    add %rax, [%rip]
    add %rbx, [%rip + 0]
    add %rcx, [%rip + 4]
    add %rdx, [%rip + 8]

    add [%rip], %rax
    add [%rip + 0], %rbx

    add %al, 1
    add %ax, 10
    add %eax, 100
    add %rax, 1000

    add %r8b, 2
    add %r8w, 20
    add %r8d, 200
    add %r8,  2000

    add %rax, 0x123456
    add %rbx, 0x7F

    add [%rbx], 1
    add [%rbx], 2
    add [%rbx], 4
    add [%rbx], 8

    add [%rcx + 8], 1
    add [%rcx + 16], 255
    add [%rcx - 8], 10

    add %r12b, %r13b
    add %r14w, %r15w
    add %r12d, %r13d
    add %r14,  %r15

    add %r15, %r8
    add %r8,  %r15

    add %r8,  [%rip + 32]
    add %r9,  [%rip + 64]
    add [%rip + 128], %r10
    add [%rip + 256], %r11