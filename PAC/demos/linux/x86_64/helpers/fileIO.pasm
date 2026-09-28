@inc "sys.pasm"

@def STDOUT 1

:section .text
	:global $readf
	:global $writef
	:global $print

// int readf(int fd, void* buf, size_t n)
.func readf
	// Argument Mapping: rdi = fd, rsi = buf, rdx = n
	// Arguments already match
	mov %rax, SYSCALL_READ
	syscall

	ret
.endfunc


// int writef(int fd, const void* buf, size_t n)
.func writef
	// Argument Mapping: rdi = fd, rsi = buf, rdx = n
	// Arguments already match
	mov %rax, SYSCALL_WRITE
	syscall

	ret
.endfunc

// void print(const void* buf, size_t n)
.func print
	// Argument Mapping: rdi = buf, rsi = n
	
	mov %rax, SYSCALL_WRITE
	
	mov %rdx, %rsi
	mov %rsi, %rdi
	mov %rdi, STDOUT // STDOUT

	syscall

	xor %rax, %rax
	ret
.endfunc