:section .text
	:global _start
_start:
	cld
	cli
	clc
	cmc
	std
	sti
	stc
	hlt
	wait
	fwait
	leave
	pushf
	popf
	lahf
	sahf
	pause

	mov %rax, 10
	mul [%rip + 0xFF]
	imul %rbx
	div [%rip - 0xFF]
	idiv %rcx
