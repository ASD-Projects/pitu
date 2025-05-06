# Pitu Basic Kernel Makefile with dual architecture support

ASM=nasm
CC=gcc
LD=ld
ISO_TOOL=grub-mkrescue

# Common flags
COMMON_CFLAGS=-nostdlib -nostdinc -fno-builtin -fno-stack-protector -nostartfiles -nodefaultlibs -Wall -Wextra -c

# 32-bit architecture flags
CFLAGS_32=-m32 $(COMMON_CFLAGS)
LDFLAGS_32=-T linker.ld -melf_i386
ASFLAGS_32=-f elf32

# 64-bit architecture flags
CFLAGS_64=-m64 $(COMMON_CFLAGS) -mcmodel=large -mno-red-zone -DARCH_64
LDFLAGS_64=-T linker64.ld -melf_x86_64
ASFLAGS_64=-f elf64

# Object files for both architectures
OBJECTS_32=boot.o pitu.o
OBJECTS_64=boot64.o pitu64.o

# Default architecture is 32-bit
ARCH ?= 32

# Main targets
all: kernel-$(ARCH).elf

# Conditionally set flags based on architecture
ifeq ($(ARCH),64)
    CFLAGS=$(CFLAGS_64)
    LDFLAGS=$(LDFLAGS_64)
    ASFLAGS=$(ASFLAGS_64)
    OBJECTS=$(OBJECTS_64)
    OUTPUT=kernel-64.elf
    BOOT_SRC=boot64.asm
    KERNEL_SRC=pitu.c
else
    CFLAGS=$(CFLAGS_32)
    LDFLAGS=$(LDFLAGS_32)
    ASFLAGS=$(ASFLAGS_32)
    OBJECTS=$(OBJECTS_32)
    OUTPUT=kernel-32.elf
    BOOT_SRC=boot.asm
    KERNEL_SRC=pitu.c
endif

# ISO output directory
ISO_DIR=iso_root
ISO_BOOT=$(ISO_DIR)/boot
ISO_GRUB=$(ISO_BOOT)/grub

# 32-bit targets
kernel-32.elf: boot.o pitu.o
	$(LD) $(LDFLAGS_32) boot.o pitu.o -o kernel-32.elf

boot.o: boot.asm
	$(ASM) $(ASFLAGS_32) boot.asm -o boot.o

pitu.o: pitu.c
	$(CC) $(CFLAGS_32) pitu.c -o pitu.o

# 64-bit targets
kernel-64.elf: boot64.o pitu64.o
	$(LD) $(LDFLAGS_64) boot64.o pitu64.o -o kernel-64.elf

boot64.o: boot64.asm
	$(ASM) $(ASFLAGS_64) boot64.asm -o boot64.o

pitu64.o: pitu.c
	$(CC) $(CFLAGS_64) pitu.c -o pitu64.o

# Build both architectures
all-archs: kernel-32.elf kernel-64.elf

# Create bootable ISO
iso: kernel-$(ARCH).elf
	# Create directory structure
	mkdir -p $(ISO_GRUB)
	
	# Copy kernel
	cp kernel-$(ARCH).elf $(ISO_BOOT)/kernel.elf
	
	# Create GRUB config
	echo "set timeout=3" > $(ISO_GRUB)/grub.cfg
	echo "set default=0" >> $(ISO_GRUB)/grub.cfg
	echo "" >> $(ISO_GRUB)/grub.cfg
	echo "menuentry \"Pitu Basic Kernel $(ARCH)-bit\" {" >> $(ISO_GRUB)/grub.cfg
	echo "    multiboot /boot/kernel.elf" >> $(ISO_GRUB)/grub.cfg
	echo "    boot" >> $(ISO_GRUB)/grub.cfg
	echo "}" >> $(ISO_GRUB)/grub.cfg
	
	# Create ISO using GRUB
	$(ISO_TOOL) -o pitu-$(ARCH).iso $(ISO_DIR)
	
	# Clean up
	rm -rf $(ISO_DIR)

# Run in QEMU (if installed)
run: kernel-$(ARCH).elf
	qemu-system-$(shell if [ "$(ARCH)" = "64" ]; then echo "x86_64"; else echo "i386"; fi) -kernel kernel-$(ARCH).elf -m 128M

# Run ISO in QEMU (if installed)
run-iso: iso
	qemu-system-$(shell if [ "$(ARCH)" = "64" ]; then echo "x86_64"; else echo "i386"; fi) -cdrom pitu-$(ARCH).iso -m 128M

# Combined ISO with both architectures
dual-iso: kernel-32.elf kernel-64.elf
	# Create directory structure
	mkdir -p $(ISO_GRUB)
	
	# Copy kernels
	cp kernel-32.elf $(ISO_BOOT)/kernel32.elf
	cp kernel-64.elf $(ISO_BOOT)/kernel64.elf
	
	# Create GRUB config
	echo "set timeout=10" > $(ISO_GRUB)/grub.cfg
	echo "set default=0" >> $(ISO_GRUB)/grub.cfg
	echo "terminal_output console" >> $(ISO_GRUB)/grub.cfg
	echo "insmod vbe" >> $(ISO_GRUB)/grub.cfg
	echo "insmod vga" >> $(ISO_GRUB)/grub.cfg
	echo "insmod video_bochs" >> $(ISO_GRUB)/grub.cfg
	echo "insmod video_cirrus" >> $(ISO_GRUB)/grub.cfg
	echo "insmod all_video" >> $(ISO_GRUB)/grub.cfg
	echo "insmod gfxterm" >> $(ISO_GRUB)/grub.cfg
	echo "set gfxpayload=keep" >> $(ISO_GRUB)/grub.cfg
	echo "" >> $(ISO_GRUB)/grub.cfg
	echo "menuentry \"Pitu Basic Kernel (32-bit)\" {" >> $(ISO_GRUB)/grub.cfg
	echo "    multiboot /boot/kernel32.elf" >> $(ISO_GRUB)/grub.cfg
	echo "    boot" >> $(ISO_GRUB)/grub.cfg
	echo "}" >> $(ISO_GRUB)/grub.cfg
	echo "" >> $(ISO_GRUB)/grub.cfg
	echo "menuentry \"Pitu Basic Kernel (64-bit)\" {" >> $(ISO_GRUB)/grub.cfg
	echo "    multiboot /boot/kernel64.elf" >> $(ISO_GRUB)/grub.cfg
	echo "    boot" >> $(ISO_GRUB)/grub.cfg
	echo "}" >> $(ISO_GRUB)/grub.cfg
	
	# Create ISO using GRUB
	$(ISO_TOOL) -o pitu-dual.iso $(ISO_DIR)
	
	# Clean up
	rm -rf $(ISO_DIR)

# Run dual ISO in QEMU (if installed)
run-dual: dual-iso
	qemu-system-x86_64 -cdrom pitu-dual.iso -m 128M

# Clean up
clean:
	rm -f *.o kernel-*.elf pitu-*.iso
	rm -rf $(ISO_DIR)