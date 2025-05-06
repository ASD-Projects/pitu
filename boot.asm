; boot.asm
global start

section .text
bits 32
start:
    ; Set up stack
    mov esp, stack_top

    ; Call kernel_main
    extern kernel_main
    call kernel_main

    ; Halt the CPU
    cli
.hang:
    hlt
    jmp .hang

section .bss
align 4
stack_bottom:
    resb 16384 ; 16 KB
stack_top: