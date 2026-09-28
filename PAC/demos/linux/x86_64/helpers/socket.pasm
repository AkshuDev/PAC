@inc "sys.pasm"

:section .text
	:global $socket
	:global $socket_connect

// int socket(int type, int domain, int protocol)
.func socket
	// Argument Mapping: rdi = type, rsi = domain, rdx = protocol
	// Arguments already match
	mov %rax, SYSCALL_SOCKET
	syscall

	ret
.endfunc

// int socket_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);
.func socket_connect
	// Argument Mapping: rdi = sockfd, rsi = addr, rdx = addrlen
	// Arguments already match

	mov %rax, SYSCALL_CONNECT
	syscall
	
	ret
.endfunc