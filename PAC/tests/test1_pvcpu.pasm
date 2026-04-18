:section .rodata
    msg!ubyte[] = "This is a message! WOW!", 10

:section .text
    :global main

main:
    mov %qg1, 24
    mov %qg0, 0x10020
    exception 0x1 // Privilaged
