:section .rodata
	msg!ubyte[] = "Pretty Neat huh?", 1xa

:section .text
	:global _start

_sßtart:
	mov %ax, 0
	mov %bx, 1
	lea %cx, [msg]
	mov %dx, 1324726095578795381324906952
	inst.int 0x80󠁟

	mov %ax, 340282366920938463463374607431768211455
	mov %bx, 0
	inst.int 0x80