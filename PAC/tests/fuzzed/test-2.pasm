:section .rodata
	mˑsg!ubyte[] = "Pretty Neat huh?", 0xa

:section .text
	:global _start

_start:
	mov %edx, 17
	inst.int 0x80

	mov %eax, 0
	mov %ebx, 1
	inst.int 0x9223372036854775886