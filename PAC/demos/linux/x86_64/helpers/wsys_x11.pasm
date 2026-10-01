// Window System X11

// Requires Linking with: fileIO.pasm, socket.pasm

@inc "sys.pasm"

:section .text
	:external $readf
	:external $writef
	:external $seekf
	:external $print

	:external $socket
	:external $socket_connect

	:global $wsys_x11_connect
	:global $wsys_x11_close
	:global $wsys_x11_setup

// int read_exact(int fd, void* buf, size_t n)
.func read_exact
	mov %r8, %rsi // void* cbuf = buf;
	mov %rbx, %rdx // size_t total = n;

	xor %rcx, %rcx // size_t bytes = 0;
	loop:
		// size_t bytes_read = readf(fd, cbuf + bytes, total - bytes);
		// if (bytes_read <= 0) return false;
		mov %rsi, %r8
		add %rsi, %rcx
		
		mov %rdx, %rbx
		sub %rdx, %rcx

		call $readf
		cmp %rax, 0
		jle $read_exact.done

		// bytes += bytes_read;
		// if (bytes >= n) return true;
		add %rcx, %rax
		cmp %rcx, %rdx
		jge $read_exact.done

		jmp $read_exact.loop

	done: // requires bytes read in rcx
		mov %rax, %rcx
		ret
.endfunc

// uint64_t align_up(uint64_t v, uint64_t alignment)
.func align_up
	sub %rsi, 1 // align -= 1;

	// uint64_t out = v + align;
	mov %rax, %rdi
	add %rax, %rsi

	// align = ~align;
	not %rsi

	// out = out & align;
	and %rax, %rsi
	ret
.endfunc

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

	mov [x11_fd], %eax

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
		mov %rsi, @sizeof(err_msg_socket_failed)
		call $print

		jmp $wsys_x11_connect.fail
.endfunc

// void wsys_x11_close(void)
.func wsys_x11_close
	xor %rdi, %rdi
    mov %edi, [x11_fd]

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
	xor %rdi, %rdi
    mov %edi, [x11_fd]
    lea %rsi, [x11_setup_request]
    mov %rdx, @sizeof(x11_setup_request)
	call $writef

    cmp %rax, @sizeof(x11_setup_request)
    jne $wsys_x11_setup.fail

	// read_exact(x11_fd, x11_setup_reply, 8)
	xor %rdi, %rdi
    mov %edi, [x11_fd]
    lea %rsi, [x11_setup_reply]
    mov %rdx, 8
	call $read_exact

    cmp %rax, 8
    jne $wsys_x11_setup.fail


    // Check status:
    // 1 = success
    // 0 = failed
    // 2 = authenticate
    mov %al, [x11_setup_reply]

    cmp %al, 1
    jne $wsys_x11_setup.fail

	// Additional length
	xor %rax, %rax
    mov %ax, [x11_setup_reply+6]
    shl %rax, 2

    mov [x11_setup_size], %rax

    cmp %rax, @sizeof(x11_setup_prefix)
    jl $wsys_x11_setup.fail

	// read_exact(x11_fd, x11_setup_prefix, sizeof(x11_setup_prefix))
	xor %rdi, %rdi
    mov %edi, [x11_fd]
    lea %rsi, [x11_setup_prefix]
    mov %rdx, @sizeof(x11_setup_prefix)
	call $read_exact

    cmp %rax, @sizeof(x11_setup_prefix)
    jne $wsys_x11_setup.fail

	// Read Screens
	mov %rbx, @sizeof(x11_setup_prefix)
	add %rbx, [x11_setup_prefix.vendor_length]

	mov %rdi, %rbx
	mov %rsi, @sizeof(uint)
	call $align_up
	mov %rbx, %rax

	mov %rax, [x11_setup_prefix.pixmap_formats_len]
	shl %rax, 3
	add %rbx, %rax

	mov %rdi, [x11_fd]
	mov %rsi, %rbx
	mov %rdx, FIO_SEEK_SET
	call $seekf

	// read_exact(x11_fd, x11_screen, sizeof(x11_screen))
	mov %rdi, [x11_fd]
	lea %rsi, [x11_screen]
	mov %rdx, @sizeof(x11_screen)
	call $read_exact

	cmp %rax, @sizeof(x11_screen)
	jl $wsys_x11_setup.fail

	success:
		mov %rax, 1
		ret

	fail:
		mov %rax, 0
		ret
.endfunc

:section .rodata
	err_msg_socket_failed!ubyte[] = "[WSYS X11] Failed to connect to X11 socket!", 0xa, 0

:section .data
	.struct x11_sockaddr
		sun_family!ushort = SYS_AF_UNIX
		sun_path!ubyte[108] = "/tmp/.X11-unix/X0", 0
	.endstruct

    x11_setup_request!ubyte[12] = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    x11_setup_reply!ubyte[8] = 0, 0, 0, 0, 0, 0, 0, 0

    x11_setup_size!ulong = 0

:section .bss
	:res x11_fd!int

	:res x11_root_window!ulong
	:res x11_root_visual!ulong
	:res x11_root_depth!ubyte

	:res x11_next_resource_id!ulong
	
	.struct x11_setup_prefix :res
		release_number!uint
		resource_id_base!uint
		resource_id_mask!uint
		motion_buffer_size!uint

		vendor_length!ushort
		maximum_request_length!ushort

		roots_len!ubyte
		pixmap_formats_len!ubyte

		image_byte_order!ubyte
		bitmap_bit_order!ubyte
		scanline_unit!ubyte
		scanline_pad!ubyte

		min_keycode!ubyte
		max_keycode!ubyte

		unused!ubyte[4]
	.endstruct

	.struct x11_screen :res
		root!uint
		default_colormap!uint
		white_pixel!uint
		black_pixel!uint
		current_input_masks!uint

		width_in_pixels!ushort
		height_in_pixels!ushort
		width_in_millimeters!ushort
		height_in_millimeters!ushort

		min_installed_maps!ushort
		max_installed_maps!ushort

		root_visual!uint

		backing_stores!ubyte
		save_unders!ubyte
		root_depth!ubyte
		allowed_depths_len!ubyte
	.endstruct
