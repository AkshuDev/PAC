// Requires Linking with: wsys_x11.pasm, fileIO.pasm

@inc "sys.pasm"

:section .text
	:external $print

	:external $wsys_x11_connect
	:external $wsys_x11_close
	:external $wsys_x11_setup
	:external $wsys_x11_create_window

	:external $time_ssleep

	:global _start

_start:
	jmp $core

.func core
	// print(msg_start, strlen(msg_start))
	lea %rdi, [msg_start]
	mov %rsi, @sizeof(msg_start)
	call $print

	// wsys_x11_connect()
	call $wsys_x11_connect

	cmp %rax, 1
	jne $core.connect_failed

	// print(msg_connected, strlen(msg_connected))
	lea %rdi, [msg_connected]
	mov %rsi, @sizeof(msg_connected)
	call $print

	// wsys_x11_setup()
	call $wsys_x11_setup

	cmp %rax, 1
	jne $core.setup_failed

	// print(msg_setup_ok, strlen(msg_setup_ok))
	lea %rdi, [msg_setup_ok]
	mov %rsi, @sizeof(msg_setup_ok)
	call $print

	// wsys_x11_create_window(window_title, 800, 400)
	lea %rdi, [window_title]
	mov %rsi, 800
	mov %rdx, 400
	call $wsys_x11_create_window

	cmp %rax, 1
	jne $core.window_creation_failed

	// print(msg_window_created, strlen(msg_window_created))
	lea %rdi, [msg_window_created]
	mov %rsi, @sizeof(msg_window_created)
	call $print

	// time_ssleep(5)
	mov %rdi, 5
	call $time_ssleep

	// wsys_x11_close()
	call $wsys_x11_close

	// exit(0)
	mov %rax, SYSCALL_EXIT
	xor %rdi, %rdi
	syscall

	connect_failed:
		// print(msg_connect_failed, strlen(msg_connect_failed))
		lea %rdi, [msg_connect_failed]
		mov %rsi, @sizeof(msg_connect_failed)
		call $print

		// exit(1)
		mov %rax, SYSCALL_EXIT
		mov %rdi, 1
		syscall

	setup_failed:
		// print(msg_setup_failed, strlen(msg_setup_failed))
		lea %rdi, [msg_setup_failed]
		mov %rsi, @sizeof(msg_setup_failed)
		call $print

		// wsys_x11_close()
		call $wsys_x11_close

		// exit(2)
		mov %rax, SYSCALL_EXIT
		mov %rdi, 2
		syscall

	window_creation_failed:
		// print(msg_window_creation_failed, strlen(msg_window_creation_failed))
		lea %rdi, [msg_window_creation_failed]
		mov %rsi, @sizeof(msg_window_creation_failed)
		call $print

		// wsys_x11_close()
		call $wsys_x11_close

		// exit(3)
		mov %rax, SYSCALL_EXIT
		mov %rdi, 3
		syscall
.endfunc

:section .rodata
	window_title!ubyte[] = "Game Time", 0

	msg_start!ubyte[] = "Connecting to X11...", 0xa, 0
	msg_connected!ubyte[] = "X11 socket connected!", 0xa, 0
	msg_setup_ok!ubyte[] = "X11 setup succeeded!", 0xa, 0
	msg_window_created!ubyte[] = "X11 Window created!", 0xa, 0

	msg_connect_failed!ubyte[] = "X11 connection failed!", 0xa, 0
	msg_setup_failed!ubyte[] = "X11 setup failed!", 0xa, 0
	msg_window_creation_failed!ubyte[] = "X11 Window creation failed!", 0xa, 0