; boot64.asm - 64-bit boot code for PituKernel

[BITS 32]  ; Start in 32-bit mode

; Multiboot header constants
MBALIGN     equ  1 << 0            ; align loaded modules on page boundaries
MEMINFO     equ  1 << 1            ; provide memory map
MBFLAGS     equ  MBALIGN | MEMINFO ; this is the Multiboot 'flag' field
MAGIC       equ  0x1BADB002        ; 'magic number' lets bootloader find the header
CHECKSUM    equ -(MAGIC + MBFLAGS) ; checksum of above to prove we are multiboot

; Multiboot2 constants
MB2_MAGIC   equ  0xE85250D6        ; magic number for multiboot2
MB2_ARCH    equ  0                 ; architecture (i386)
MB2_LENGTH  equ  mb2_hdr_end - mb2_hdr
MB2_CHECKSUM equ -(MB2_MAGIC + MB2_ARCH + MB2_LENGTH)

; Constants for long mode setup
PAGE_PRESENT    equ 1 << 0
PAGE_WRITE      equ 1 << 1
PAGE_SIZE_2MB   equ 1 << 7

section .multiboot
align 4
    dd MAGIC
    dd MBFLAGS
    dd CHECKSUM

section .multiboot2
align 8
mb2_hdr:
    dd MB2_MAGIC
    dd MB2_ARCH
    dd MB2_LENGTH
    dd MB2_CHECKSUM
    
    ; End tag
    dw 0    ; type
    dw 0    ; flags
    dd 8    ; size
mb2_hdr_end:

section .bss
align 16
stack_bottom:
    resb 16384 ; 16 KiB
stack_top:

; Page tables for long mode
align 4096
pml4_table:
    resb 4096
pdpt_table:
    resb 4096
pd_table:
    resb 4096

section .text
global _start
extern kernel_main

; Check if CPUID is supported
check_cpuid:
    ; Save EFLAGS
    pushfd
    
    ; Store EFLAGS in EAX
    pop eax
    mov ecx, eax
    
    ; Flip ID bit (bit 21)
    xor eax, 1 << 21
    
    ; Load modified EFLAGS
    push eax
    popfd
    
    ; Get EFLAGS again
    pushfd
    pop eax
    
    ; Restore original EFLAGS
    push ecx
    popfd
    
    ; Check if bit 21 was changed
    xor eax, ecx
    test eax, 1 << 21
    jz no_cpuid
    ret

no_cpuid:
    mov al, "1"
    jmp error

; Check if long mode is available
check_long_mode:
    ; Check if extended CPUID function is available
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb no_long_mode
    
    ; Check for long mode using extended function
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29  ; LM bit
    jz no_long_mode
    ret

no_long_mode:
    mov al, "2"
    jmp error

; Configure page tables for identity mapping
setup_page_tables:
    ; Clear page tables first
    mov edi, pml4_table
    mov ecx, 4096 * 3 / 4  ; Size of all tables in dwords
    xor eax, eax
    rep stosd
    
    ; PML4 first entry -> PDPT
    mov eax, pdpt_table
    or eax, PAGE_PRESENT | PAGE_WRITE
    mov [pml4_table], eax
    
    ; PDPT first entry -> PD
    mov eax, pd_table
    or eax, PAGE_PRESENT | PAGE_WRITE
    mov [pdpt_table], eax
    
    ; Map first 2MB with 2MB pages
    mov ecx, 0         ; Counter
    
.map_pd_entry:
    ; Calculate physical address (2MB * entry index)
    mov eax, 0x200000  ; 2MB
    mul ecx
    or eax, PAGE_PRESENT | PAGE_WRITE | PAGE_SIZE_2MB
    mov [pd_table + ecx * 8], eax
    
    inc ecx
    cmp ecx, 512       ; Map 1GB (512 entries)
    jne .map_pd_entry
    
    ret

; Enable paging for long mode
enable_paging:
    ; Load PML4 address into CR3
    mov eax, pml4_table
    mov cr3, eax
    
    ; Enable PAE
    mov eax, cr4
    or eax, 1 << 5     ; Set PAE flag
    mov cr4, eax
    
    ; Enable long mode by setting the EFER.LME flag
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8     ; Set LME flag
    wrmsr
    
    ; Enable paging
    mov eax, cr0
    or eax, 1 << 31    ; Set PG flag
    mov cr0, eax
    
    ret

; 64-bit GDT
section .rodata
gdt64:
    ; Null descriptor
    dq 0
    
    ; Code segment
    dq (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53)
    
.pointer:
    dw $ - gdt64 - 1   ; Size of GDT
    dd gdt64           ; Address of GDT (32-bit pointer)

; Main entry point
_start:
    ; Set up stack
    mov esp, stack_top
    
    ; Check requirements for long mode
    call check_cpuid
    call check_long_mode
    
    ; Set up identity paging
    call setup_page_tables
    call enable_paging
    
    ; Load 64-bit GDT
    lgdt [gdt64.pointer]
    
    ; Jump to 64-bit code segment
    jmp 0x08:long_mode_start

; Display error code and halt
error:
    ; Print "ERR: X" where X is the error code
    mov dword [0xB8000], 0x4F524F45
    mov dword [0xB8004], 0x4F3A4F52
    mov dword [0xB8008], 0x4F204F20
    mov byte  [0xB800A], al
    hlt

; 64-bit code - must be after the 32-bit code
[BITS 64]
long_mode_start:
    ; Update segment registers
    mov ax, 0
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    
    ; Update stack pointer to full 64-bit
    mov rsp, stack_top
    
    ; Clear interrupts
    cli
    
    ; Call C kernel main function
    call kernel_main
    
    ; If kernel returns, halt system
    cli
    hlt
    
    ; Infinite loop if hlt doesn't work
.hang:
    jmp .hang