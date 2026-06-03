// Just a simple snake game

@def grid_mx 10
@def grid_my 10

:section .text
    :global _start

.func print // Linux x64
	mov %rdx, %rsi
	mov %rsi, %rdi
	mov %rax, 1
	mov %rdi, 1
	syscall
	ret
.endfunc

.func input // Linux x86_64
	mov %rdx, %rsi
	mov %rsi, %rdi
	mov %rax, 0
	mov %rdi, 0
	syscall
	ret
.endfunc

.func sleep // Linux x86_64
    mov %rax, 35
    lea %rdi, [sleep_time]
    xor %rsi, %rsi
    syscall
    ret
.endfunc

.func render
    lea %rdi, [res_mposstr]
    mov %rsi, 3
    call $print

    mov %rbx, 0
y_loop:
    mov %rax, 0
x_loop:
    push %rax
    push %rbx

    cmp %rax, [snake_x]
    jne $render.check_food

    cmp %rbx, [snake_y]
    je $render.draw_snake
check_food:
    cmp %rax, [food_x]
    jne $render.draw_space

    cmp %rbx, [food_y]
    je $render.draw_food
draw_space:
    lea %rdi, [spacechar]
    mov %rsi, 1
    call $print
    jmp $render.restore
draw_snake:
    lea %rdi, [snakechar]
    mov %rsi, 1
    call $print
    jmp $render.restore
draw_food:
    lea %rdi, [foodchar]
    mov %rsi, 1
    call $print
restore:
    pop %rbx
    pop %rax

    inc %rax
    cmp %rax, grid_mx
    jl $render.x_loop

    lea %rdi, [nl_char]
    mov %rsi, 1
    call $print

    inc %rbx
    cmp %rbx, grid_my
    jl $render.y_loop

    ret
.endfunc

.func update_snake
    mov %al, [direction]

    cmp %al, 255
    je $update_snake.done

    cmp %al, 0
    jne $update_snake.down

    dec [snake_y]
    ret

down:
    cmp %al, 1
    jne $update_snake.left

    inc [snake_y]
    ret

left:
    cmp %al, 2
    jne $update_snake.right

    dec [snake_x]
    ret

right:
    inc [snake_x]
    ret

done:
    ret
.endfunc

.func read_input
	mov %rax, [snake_x]
	mov %rbx, [snake_y]
	cmp %rax, 0
	jl $read_input.death

	cmp %rax, grid_mx
	jge $read_input.death

	cmp %rbx, 0
	jl $read_input.death

	cmp %rbx, grid_my
	jge $read_input.death

	lea %rdi, [input_buffer]
	mov %rsi, 1
	call $input

    mov %al, [input_buffer]

	cmp %al, 'q'
	jne $read_input.check_w

ret_to_exit:
    lea %rdi, [showstr]
    mov %rsi, 6
    call $print

    mov %rax, 60
    xor %rdi, %rdi
    syscall

death:
	lea %rdi, [uded]
    mov %rsi, 17
    call $print

	lea %rdi, [showstr]
    mov %rsi, 6
    call $print

    mov %rax, 60
    xor %rdi, %rdi
    syscall

check_w:
    cmp %al, 'w'
    jne $read_input.check_s

    mov [direction], 0
    ret

check_s:
    cmp %al, 's'
    jne $read_input.check_a

    mov [direction], 1
    ret

check_a:
    cmp %al, 'a'
    jne $read_input.check_d

    mov [direction], 2
    ret

check_d:
    cmp %al, 'd'
    jne $read_input.done

    mov [direction], 3

done:
    ret
.endfunc

.func game_loop
	loop:
		call $sleep

		call $render
		call $read_input
		call $update_snake
		jmp $game_loop.loop
.endfunc

_start:
	lea %rdi, [startup]
	mov %rsi, 46
	call $print

	lea %rdi, [hidestr]
	mov %rsi, 6
	call $print

	lea %rdi, [save_mposstr]
	mov %rsi, 3
	call $print

    call $game_loop

	lea %rdi, [showstr]
	mov %rsi, 6
	call $print

    mov %rax, 60
    xor %rdi, %rdi
    syscall


// A bunch of typedefs
.type Str=ubyte

:section .rodata
    startup!Str[] = "Welcome to SimpleTest-Snake v1, Made for PAC!", 10, 0
    clearstr!Str[] = 27, "[2J", 27, "[H", 0
	uded!Str[] = "U died .........", 10, 0
    snakechar!Str[] = "#", 0
    foodchar!Str[] = "*", 0
	spacechar!Str[] = " ", 0
	hidestr!Str[] = 27, "[?25l"
	showstr!Str[] = 27, "[?25h"
	save_mposstr!Str[] = 27, "[s"
	res_mposstr!Str[] = 27, "[u"
	nl_char!ubyte = 0xa

:section .data
    snake_x!ulong = 5
    snake_y!ulong = 5

    food_x!ulong = 0
    food_y!ulong = 0

    direction!ulong = 255

	.struct sleep_time
		t0!ulong =
		t1!ulong = 100000000
	.endstruct

:section .bss
    :res input_buffer!uint[8]
