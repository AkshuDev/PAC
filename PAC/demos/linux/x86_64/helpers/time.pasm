@inc "sys.pasm"

:section .text
	:global $time_ssleep

// void time_ssleep(uint64_t seconds)
.func time_ssleep
	// Argument Mapping: rdi = seconds
	mov [sleep_time.t0], %rdi
	xor %rax, %rax
    mov [sleep_time.t1], %rax

	lea %rdi, [sleep_time.t0]
	lea %rsi, [sleep_time.t1]
	
	mov %rax, SYSCALL_NANOSLEEP
	syscall
	ret
.endfunc

:section .bss
	.struct sleep_time :res
		t0!ulong
		t1!ulong
	.endstruct