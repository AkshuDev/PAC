@def testMacro 1 + 1

:section .text
	:global main
	:external _start

main:
	mov %rax, testMacro
	mov %rbx, -8+90-76
	mov %rcx, 998 >> testMacro
	mov %rdx, @sizeof(testMacro) + testMacro / 2
	jmp _start