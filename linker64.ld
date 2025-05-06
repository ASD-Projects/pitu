/* linker64.ld - Linker script for the x86_64 kernel */
ENTRY(_start)
SECTIONS
{
    /* Set the kernel higher half address */
    . = 1M;

    .boot :
    {
        *(.multiboot)
        *(.multiboot2)
    }

    .text :
    {
        *(.text)
    }

    .rodata :
    {
        *(.rodata)
    }

    .data :
    {
        *(.data)
    }

    .bss :
    {
        *(COMMON)
        *(.bss)
    }
}