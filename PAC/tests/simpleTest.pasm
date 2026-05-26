:section .rodata
    const_msg!ubyte[] = "Hello This is a constant message!", 10

:section .text
    :global _start

_start:
	and %rax, %rbx