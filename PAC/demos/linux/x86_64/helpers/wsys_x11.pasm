// Window System X11

// Requires Linking with: fileIO.pasm, socket.pasm

@inc "sys.pasm"

:section .text
	:external $readf
	:external $writef
	:external $print

	:external $socket
	:external $socket_connect

	:global $wsys_x11_connect
	:global $wsys_x11_close
	:global $wsys_x11_setup

// bool wsys_x11_connect(void)
.func wsys_x11_connect
	// Try to connect to /tmp/.X11-unix/X0
	
	// socket(AF_UNIX, SOCK_STREAM, 0)
	mov %rdi, SYS_AF_UNIX
	mov %rsi, SYS_SOCK_STREAM
	mov %rdx, 0
	call $socket

	cmp %rax, 0
	jl $wsys_x11_connect.fail_socket

	mov [x11_fd], %rax

	// socket_connect(fd, &x11_sockaddr, 110)
	mov %rdi, %rax // x11_fd
	lea %rsi, [x11_sockaddr]
	mov %rdx, 110
	call $socket_connect

	cmp %rax, 0
	jl $wsys_x11_connect.fail_socket

	success:
		mov %rax, 1 // true
		ret

	fail:
		mov %rax, 0 // false
		ret

	fail_socket:
		// print((char*)err_msg_socket_failed, strlen(err_msg_socket_failed))
		lea %rdi, [err_msg_socket_failed]
		mov %rsi, 44
		call $print

		jmp $wsys_x11_connect.fail
.endfunc

// void wsys_x11_close(void)
.func wsys_x11_close
    mov %rdi, [x11_fd]

    mov %rax, SYSCALL_CLOSE
    syscall

    ret
.endfunc

// bool wsys_x11_setup(void)
.func wsys_x11_setup
    mov %al, 'l'
    mov [x11_setup_request+0], %al

    mov %al, 0
    mov [x11_setup_request+1], %al

    // Protocol major = 11
    mov %al, 11
    mov [x11_setup_request+2], %al

    mov %al, 0
    mov [x11_setup_request+3], %al

    // Protocol minor = 0
    mov %al, 0
    mov [x11_setup_request+4], %al
    mov [x11_setup_request+5], %al

    // Authentication name length = 0
    mov [x11_setup_request+6], %al
    mov [x11_setup_request+7], %al

    // Authentication data length = 0
    mov [x11_setup_request+8], %al
    mov [x11_setup_request+9], %al

    // Unused = 0
    mov [x11_setup_request+10], %al
    mov [x11_setup_request+11], %al

    // writef(x11_fd, request, 12)
    mov %rdi, [x11_fd]
    lea %rsi, [x11_setup_request]
    mov %rdx, 12
	call $writef

    cmp %rax, 12
    jne $wsys_x11_setup.fail


    // Read setup reply header.
    // Header is 8 bytes:
    // ubyte status
    // ubyte reason length
    // ushort major
    // ushort minor
    // ushort additional length

	// readf(x11_fd, x11_setup_reply, 8)
    mov %rdi, [x11_fd]
    lea %rsi, [x11_setup_reply]
    mov %rdx, 8
	call $readf

    cmp %rax, 8
    jne $wsys_x11_setup.fail


    // Check status:
    // 1 = success
    // 0 = failed
    // 2 = authenticate
    mov %al, [x11_setup_reply]

    cmp %al, 1
    jne $wsys_x11_setup.success

	// Additional length
    mov %rax, [x11_setup_reply+6]
    shl %rax, 2

    mov [x11_setup_extra_size], %rax

    cmp %rax, 0
    je $wsys_x11_setup.success

	// readf(x11_fd, x11_setup_extra, %rax)
    mov %rdi, [x11_fd]
    lea %rsi, [x11_setup_extra]
    mov %rdx, %rax
	call $readf

    cmp %rax, [x11_setup_extra_size]
    jne $wsys_x11_setup.fail

	success:
		mov %rax, 1
		ret

	fail:
		mov %rax, 0
		ret
.endfunc

:section .rodata
	err_msg_socket_failed!ubyte[45] = "[WSYS X11] Failed to connect to X11 socket!", 0xa, 0

:section .data
    // struct sockaddr_un {
    //     unsigned short sun_family;
    //     char sun_path[108];
    // };
    //
    // Total = 110 bytes.
	.struct x11_sockaddr
		sun_family!ushort = 256
		sun_path!ubyte[108] = "/tmp/.X11-unix/X0", 0
	.endstruct

    x11_setup_request!ubyte[12] = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    x11_setup_reply!ubyte[8] = 0, 0, 0, 0, 0, 0, 0, 0

    x11_setup_extra_size!ulong = 0

:section .bss
	:res x11_fd!int
	
	:res x11_setup_extra!ubyte[65536]
