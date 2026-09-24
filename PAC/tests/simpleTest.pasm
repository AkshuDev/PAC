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
	wait
	fwait
	leave
	pushf
	popf
	lahf
	sahf
	pause
	hlt

	movupd %xmm0, %xmm1
	movlpd %xmm0, [%rip - 0x4]
	movhpd %xmm1, [%rbp]
	movsd %xmm10, %xmm11
	unpcklpd %xmm11, [%rcx]
	unpckhpd %xmm15, [%rip]
