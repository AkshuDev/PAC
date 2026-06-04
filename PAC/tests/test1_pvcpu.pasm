:section .rodata
    msg!ubyte[] = "This is a message! WOW!", 10

:section .bss
	.struct mStruct :res
		f1!ubyte
		f2!ubyte
		f3!ulong
	.endstruct

:section .text
    :global _start

_start:
    mov %qg0, 5
	ucmp %qg0, 5
	je exit

	push %qg5
	mov %qg8, [mStruct.f2]

exit:
	
