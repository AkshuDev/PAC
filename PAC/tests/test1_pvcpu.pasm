:section .rodata
    msg!ubyte[] = "This is a message! WOW!", 10

:section .text
    :global main

main:
    mov %qg0, [msg]
    mov %g1, 24
    exception 0x1 // Privilaged
