:section .rodata
	msg!ubyte[] = "Pretty Neat huh?", 0xa

:section .text
	:global _start

_start:
	mov %ax, 4
	mov %bx, 1
	lea %cx, [msg]
	mov %dx, 17
	inst.int 0x80

	mov %ax, 1
	mov %bx, 0
	inst.int 0x80