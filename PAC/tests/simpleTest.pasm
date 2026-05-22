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

main:
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
