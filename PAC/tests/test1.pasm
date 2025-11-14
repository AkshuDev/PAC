// ==========================================================
//  Pheonix Assembler Collection (PAC) Example
//  File: test1.pasm
//  Description: Demonstrates PAC syntax features Version 1.0.
// ==========================================================

// --- Preprocessing ---
@def MSG "Hello, PAC World \
Hi!"
@def COUNT 3

// --- Data Section ---
:section .data
msg!ubyte[22] = MSG + '\0' // Variable Arrays are not allowed, also 22 for NULL at end
count: int = COUNT

// --- Structure Definition ---
.struct Point
    int x
    int y
.endstruct

// --- Code Section ---
:section .text
:global main

.func main
    // Type the point structure (Optional)
    .type Point p1 // Function scoped
    p1.x = 10
    p1.y = 20

    // Print loop
loop:
    mov rax, count
    cmp rax, 0
    jle end

    // Simulated print (architecture-specific later)
    call $print_msg

    sub count, 1
    jmp loop

end:
    ret
.endfunc

// --- Print Routine ---
.func print_msg
    // Imagine this calls a system-level write for now
    mov rdi, msg
    mov rsi, MSG
    // Later tests will have this, they will use macros <print placeholder>
    ret
.endfunc
