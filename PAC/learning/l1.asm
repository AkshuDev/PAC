; This is just for my learning purposes
BITS 64
section .data
msg1 db 'H' ; ubyte
num1 dd 1234 ; 4 bytes
flag db 1 ; 1 byte

; Alignment test variable
pad db 'A' ; char (1 bytes) -> padded up to 8 boundary

; ----------------------------------------------------------
;  SECTION 2: BSS Section - manual alignment override
; ----------------------------------------------------------

ALIGN 32
section .bss 

aligned_msg resb 1
aligned_num resb 4
aligned_ptr resb 8 ; test pointer alignment (8 bytes)

; ----------------------------------------------------------
;  SECTION 3: Read-Only Data (rodata)
; ----------------------------------------------------------

section .rodata
const_msg db 'U'
const_val dq 0x1122334455667788

; ----------------------------------------------------------
;  SECTION 4: Text (Code)
; ----------------------------------------------------------

section .text
global main

main:
    cmp rax, rbx
    cmp rax, 0xFFFF
    cmp rbx, [rax]

    je .other
    jne .other
    jg .other
    jl .other
    jge .other
    jle .other
    jmp .other
.other:
    mov rax, rbx