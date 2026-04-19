:section .rodata
    msg!ubyte[] = "This is a message! WOW!", 10

:section .text
    :global main

main:
    mov %qg1, 24
    mov %qg0, 0x10020
    mov %qg2, 0xFFFFFFFFFF
    
    mov [%qg0], 'H'
    exception 0x1 // Privilaged
