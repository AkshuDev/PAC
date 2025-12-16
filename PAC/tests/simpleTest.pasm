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
    lea %rax, [const_msg]
    mov [aligned_num], %rax
    mov [%rax - 4], %rax
    mov [%rax + 4], %rax
    mov %rax, [%rax - 4]
    mov %rax, [%rax + 4]
    mov %rbx, 34
    call $print

    call $exit

.func exit
    mov %rdi, %rax
    mov %rax, 60
    syscall
.endfunc

.func print
    mov %rsi, %rax
    mov %rdx, %rbx
    jmp $print.do_print
do_print:
    mov %rax, 1
    mov %rdi, 1
    syscall
    ret
.endfunc
