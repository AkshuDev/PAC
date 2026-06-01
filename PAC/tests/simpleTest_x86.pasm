:section .rodata
	msg!ubyte[] = "Pretty Neat huh?", 0xa

:section .text
	:global _start

_start:
	mov %eax, 4
	mov %ebx, 1
	lea %ecx, [msg]
	mov %edx, 17
	syscall

	mov %eax, 1
	mov %ebx, 0
	syscall