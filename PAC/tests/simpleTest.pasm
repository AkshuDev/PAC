@def testMacro 1 + 1

:section .text
	:global main
	:external _start

main:
	mov %rax, testMacro
	mov %rbx, -8+90-76
	mov %rcx, 998 >> testMacro
	mov %rdx, @sizeof(testMacro) + ++testMacro++ / 2 + 2 % 10
	jmp _start

:section .bss
	:res mydata!ubyte[-1*-1*@sizeof(testMacro)*2]