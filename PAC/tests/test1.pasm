// ==========================================================
//  Pheonix Assembler Collection (PAC) Example
//  File: test1.pasm
//  Description: Demonstrates PAC syntax features Version 1.0.
// ==========================================================

// --- Preprocessing ---
@def MSG "Hello, PAC World!"
@def COUNT 3

// --- Data Section ---
:section .data
msg: ubyte[] = @MSG
count: int = @COUNT

// --- Structure Definition ---
.struct Point
    int x
    int y
.endstruct

// --- Code Section ---
:section .text
:global main

.func main
    // Create a structure instance
    Point p1
    p1.x = 10
    p1.y = 20

    // Print loop
loop:
    mov rax, count
    cmp rax, 0
    jle $end

    // Simulated print (architecture-specific later)
    call $print_msg

    sub count, 1
    jmp $loop

end:
    ret
.endfunc

// --- Print Routine ---
.func print_msg
    // Imagine this calls a system-level write for now
    mov rdi, msg
    mov rsi, @MSG
    // In PAC-VM or native mode, this will print msg
    ret
.endfunc
