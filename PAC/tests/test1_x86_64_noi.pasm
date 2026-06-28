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