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

msg1!ubyte = 'H' // ubyte
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
:res aligned_ptr!ptr // test pointer alignment (8 bytes)

// ----------------------------------------------------------
//  SECTION 3: Read-Only Data (rodata)
// ----------------------------------------------------------

:section .rodata

const_msg!ubyte = 'U'
const_val!long = 0x1122334455667788

// ----------------------------------------------------------
//  SECTION 4: Text (Code)
// ----------------------------------------------------------

:section .text
:global main

main:
    lea %rax, [const_msg]
    mov %rbx, 1
    call $print
    mov %rbx, 0 // Return code

    jmp exit

exit:
    mov %rax, 60
    mov %rdi, %rbx
    syscall

.func print
    push %rax // To keep stack aligned
    push %rdi
    push %rsi
    push %rdx
    push %rax
    push %rbx
    push %rax
    push %rbx
    mov %rax, 1
    mov %rdi, 1
    jmp $print.do_print
do_print:
    pop %rdx
    pop %rsi
    syscall
    jmp $print.end
end:
    pop %rbx
    pop %rax
    pop %rdx
    pop %rsi
    pop %rdi
    pop %rax
    ret
.endfunc