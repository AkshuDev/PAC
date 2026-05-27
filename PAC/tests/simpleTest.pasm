// Just a simple snake game

:section .rodata
    startup!ubyte[] = "Welcome to SimpleTest-Snake v1, Made for PAC!", 10, 0
    clearstr!ubyte[] = "", 27, "[2J", 27, "[H", 0
    snakechar!ubyte[] = "@", 0
    foodchar!ubyte[] = "*", 0

:section .data
    snake_x!byte = 10
    snake_y!byte = 10

    food_x!byte = 20
    food_y!byte = 12

    direction!byte = 0

:section .bss
    :res input_buffer!byte[8]

:section .text
    :global _start

_start:
    call $print_startup
    // call $game_loop

    mov %rax, 60
    xor %rdi, %rdi
    syscall

.func print_startup
    mov %rax, 1
    mov %rdi, 1
    lea %rsi, [startup]
    mov %rdx, 50
    syscall
    ret
.endfunc

.func clear_screen
    mov %rax, 1
    mov %rdi, 1
    lea %rsi, [clearstr]
    mov %rdx, 7
    syscall
    ret
.endfunc

.func draw_snake
    // ANSI escape:
    // ESC[row;colH

    // write ESC
    mov %rax, 1
    mov %rdi, 1
    lea %rsi, [snakechar]
    mov %rdx, 1
    syscall

    ret
.endfunc

.func read_input
    mov %rax, 0
    mov %rdi, 0
    lea %rsi, [input_buffer]
    mov %rdx, 1
    syscall

    mov %al, [input_buffer]

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

.func update_snake
    mov %al, [direction]

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
.endfunc

.func game_loop

loop:
    call $clear_screen

    call $draw_snake

    call $read_input

    call $update_snake

    // nanosleep substitute
    mov %rcx, 90000000

delay:
    dec %rcx
    jnz $game_loop.delay

    jmp $game_loop.loop

.endfunc