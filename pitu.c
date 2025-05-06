// pitu.c - Main kernel source file with dual-architecture support (x86/x86_64)

// Define standard types since we can't use standard headers in kernel mode
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#ifdef ARCH_64
typedef unsigned long long uint64_t;
#else
typedef unsigned long long uint64_t; // Still define it for 32-bit for compatibility
#endif
typedef unsigned long size_t;
#define NULL ((void*)0)

// CPU feature flags (CPUID)
#define CPUID_FEAT_EDX_PAE        (1 << 6)
#define CPUID_FEAT_EDX_APIC       (1 << 9)
#define CPUID_FEAT_EDX_LONG_MODE  (1 << 29)

// Time structure
typedef struct {
    uint8_t second;
    uint8_t minute;
    uint8_t hour;
    uint8_t day;
    uint8_t month;
    uint16_t year;
} time_info_t;

typedef struct {
    uint32_t days;
    uint32_t hours;
    uint32_t minutes;
    uint32_t seconds;
} uptime_info_t;

// Enhanced process structure
typedef struct {
    uint32_t pid;
    char name[32];
    uint8_t status;     // 0 = stopped, 1 = running, 2 = sleeping, 3 = zombie
    uint32_t memory_usage;
    uint32_t cpu_time;  // CPU time in milliseconds
    uint32_t priority;  // Process priority (0-10)
    uint32_t parent_pid; // Parent process ID
    void* stack_pointer; // Process stack pointer
    void* entry_point;   // Process entry point
} process_t;

// Process table with dynamic allocation
#define MAX_PROCESSES 64
static process_t process_table[MAX_PROCESSES];
static uint32_t next_pid = 1;
static uint32_t current_process = 0; // Currently running process
static uint8_t process_count = 0;

// Architecture detection
typedef enum {
    ARCH_X86,
    ARCH_X86_64
} cpu_arch_t;

static cpu_arch_t current_arch = ARCH_X86;

// String functions
void* memcpy(void* dest, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dest;
    const uint8_t* s = (const uint8_t*)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

char* strcpy(char* dest, const char* src) {
    char* d = dest;
    while ((*dest++ = *src++) != '\0');
    return d;
}

char* strcat(char* dest, const char* src) {
    char* d = dest;
    while (*dest) dest++;
    while ((*dest++ = *src++) != '\0');
    return d;
}

size_t strlen(const char* str) {
    size_t len = 0;
    while (str[len])
        len++;
    return len;
}

// Multiboot header constants
#define MULTIBOOT_MAGIC 0x1BADB002
#define MULTIBOOT_FLAGS 0x00000003  // Aligned modules + memory info
#define MULTIBOOT_CHECKSUM (-(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS))

// Multiboot2 header for 64-bit support
#define MULTIBOOT2_MAGIC 0xE85250D6
#define MULTIBOOT2_ARCH 0 // i386
#define MULTIBOOT2_HEADER_LEN 24
#define MULTIBOOT2_CHECKSUM -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH + MULTIBOOT2_HEADER_LEN)

// VGA text mode constants
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define VGA_MEMORY 0xB8000

// Keyboard ports
#define KEYBOARD_DATA_PORT 0x60
#define KEYBOARD_STATUS_PORT 0x64

// RTC (Real Time Clock) ports and registers
#define RTC_INDEX_PORT 0x70
#define RTC_DATA_PORT 0x71
#define RTC_SECOND 0x00
#define RTC_MINUTE 0x02
#define RTC_HOUR 0x04
#define RTC_DAY 0x07
#define RTC_MONTH 0x08
#define RTC_YEAR 0x09

// Buffer size
#define COMMAND_BUFFER_SIZE 256
#define MAX_FILE_ENTRIES 20
#define MAX_FILENAME_LENGTH 32

// Page size
#define PAGE_SIZE 4096

// VGA colors
enum vga_color {
    VGA_BLACK = 0,
    VGA_BLUE = 1,
    VGA_GREEN = 2,
    VGA_CYAN = 3,
    VGA_RED = 4,
    VGA_MAGENTA = 5,
    VGA_BROWN = 6,
    VGA_LIGHT_GREY = 7,
    VGA_DARK_GREY = 8,
    VGA_LIGHT_BLUE = 9,
    VGA_LIGHT_GREEN = 10,
    VGA_LIGHT_CYAN = 11,
    VGA_LIGHT_RED = 12,
    VGA_LIGHT_MAGENTA = 13,
    VGA_LIGHT_BROWN = 14,
    VGA_WHITE = 15,
};

// System info structure
typedef struct {
    char current_user[64];
    enum vga_color bg_color;
    enum vga_color fg_color;
    char cpu_vendor[13];
    char cpu_name[48];
    cpu_arch_t arch;
    uint8_t is_long_mode;
} system_info_t;

// Simple file system structure
typedef struct {
    char name[MAX_FILENAME_LENGTH];
    char content[256];
    size_t size;
} file_entry_t;

typedef struct directory_entry {
    char name[MAX_FILENAME_LENGTH];
    uint8_t is_directory;
    struct directory_entry* parent;
    struct directory_entry* subdirs;
    size_t subdir_count;
    file_entry_t* files;
    size_t file_count;
} directory_entry_t;

static file_entry_t file_system[MAX_FILE_ENTRIES] = {
    {"readme.txt", "Welcome to PituFS, the simple file system for Pitu Basic Kernel.", 60},
    {"help.txt", "Type 'list' to see all available commands.", 42}
};
static size_t file_count = 2;

// Global variables
static uptime_info_t system_uptime = {0, 0, 0, 0};
static uint32_t boot_time = 0;
static directory_entry_t root_directory = {"/", 1, NULL, NULL, 0, NULL, 0};
static directory_entry_t* current_directory = &root_directory;

// Forward function declarations
static void terminal_initialize(void);
static void terminal_putchar(char c);
static void terminal_write(const char* data);
static void terminal_writestring(const char* data);
static void print_prompt(void);
static void handle_command(char* cmd);
static int strcmp(const char* s1, const char* s2);
static void clear_screen(void);
static void change_terminal_color(enum vga_color bg);
static enum vga_color parse_color(const char* color);
static void process_keypress(void);
static void get_system_time(time_info_t* time);
static void print_file_contents(const char* filename);
static void create_file(const char* filename, const char* content);
static void list_files(void);
static void show_processes(void);
static void system_poweroff(void);
static void system_reboot(void);
static void detect_cpu(void);
static void setup_long_mode(void);
static void show_system_info(void);
static void init_process_table(void);
static uint32_t create_process(const char* name, void* entry_point, uint32_t priority, uint32_t parent_pid);
static int terminate_process(uint32_t pid);
static int change_process_status(uint32_t pid, uint8_t status);
static process_t* get_process(uint32_t pid);
static void update_process_times(void);
static void handle_process_commands(char* command, char* arg);
static void update_uptime(void);
static directory_entry_t* create_directory(const char* name, directory_entry_t* parent);
static directory_entry_t* find_directory(const char* path);
static void update_current_dir_string(void);

// String compare function
int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

// Multiboot header for 32-bit compatibility
__attribute__((section(".multiboot")))
const uint32_t multiboot_header[] = {
    MULTIBOOT_MAGIC,
    MULTIBOOT_FLAGS,
    MULTIBOOT_CHECKSUM
};

// Multiboot2 header for 64-bit compatibility
__attribute__((section(".multiboot2")))
const uint32_t multiboot2_header[] = {
    MULTIBOOT2_MAGIC,
    MULTIBOOT2_ARCH,
    MULTIBOOT2_HEADER_LEN,
    MULTIBOOT2_CHECKSUM,
    0, 8,  // End tag type and flags
    8, 0   // End tag size
};

// Paging structures for 64-bit mode
__attribute__((aligned(PAGE_SIZE)))
static uint64_t pml4_table[512];

__attribute__((aligned(PAGE_SIZE)))
static uint64_t pdpt_table[512];

__attribute__((aligned(PAGE_SIZE)))
static uint64_t pd_table[512];

// Global variables
static uint16_t* vga_buffer = (uint16_t*)VGA_MEMORY;
static size_t terminal_row = 0;
static size_t terminal_column = 0;
static uint8_t terminal_color;
static char current_dir[256] = "/";
static char command_buffer[COMMAND_BUFFER_SIZE];
static size_t buffer_pos = 0;

// Initialize system_info
static system_info_t system_info = {
    .bg_color = VGA_BLACK,
    .fg_color = VGA_LIGHT_GREY,
    .cpu_vendor = "Unknown",
    .cpu_name = "Unknown CPU",
    .arch = ARCH_X86,
    .is_long_mode = 0
};

// Function to read from I/O ports
static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

// Function to write to I/O ports
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" :: "a"(val), "Nd"(port));
}

// Initialize process table
void init_process_table(void) {
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        process_table[i].pid = 0; // 0 means slot is free
        process_table[i].status = 0;
    }
    
    // Create kernel process (PID 1)
    process_table[0].pid = next_pid++;
    strcpy(process_table[0].name, "kernel");
    process_table[0].status = 1; // Running
    process_table[0].memory_usage = 1024; // 1MB
    process_table[0].cpu_time = 0;
    process_table[0].priority = 0; // Highest priority
    process_table[0].parent_pid = 0; // No parent
    process_count = 1;
    current_process = 0;
}

// Create a new process
uint32_t create_process(const char* name, void* entry_point, uint32_t priority, uint32_t parent_pid) {
    if (process_count >= MAX_PROCESSES) {
        return 0; // Process table full
    }
    
    // Find a free slot
    uint32_t slot = 0;
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid == 0) {
            slot = i;
            break;
        }
    }
    
    // Initialize process
    process_table[slot].pid = next_pid++;
    strcpy(process_table[slot].name, name);
    process_table[slot].status = 1; // Running
    process_table[slot].memory_usage = 256; // Default 256KB
    process_table[slot].cpu_time = 0;
    process_table[slot].priority = priority;
    process_table[slot].parent_pid = parent_pid;
    process_table[slot].entry_point = entry_point;
    
    // Allocate stack (not actually allocating memory in this demo)
    process_table[slot].stack_pointer = (void*)(0x100000 + (slot * 0x10000));
    
    process_count++;
    return process_table[slot].pid;
}

// Terminate a process
int terminate_process(uint32_t pid) {
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid == pid) {
            // Mark children as orphans (parent_pid = 1)
            for (uint32_t j = 0; j < MAX_PROCESSES; j++) {
                if (process_table[j].parent_pid == pid) {
                    process_table[j].parent_pid = 1; // Kernel adopts orphans
                }
            }
            
            // Clear process slot
            process_table[i].pid = 0;
            process_table[i].status = 0;
            process_count--;
            
            return 1; // Success
        }
    }
    
    return 0; // Process not found
}

// Change process status
int change_process_status(uint32_t pid, uint8_t status) {
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid == pid) {
            process_table[i].status = status;
            return 1; // Success
        }
    }
    
    return 0; // Process not found
}

// Get process by PID
process_t* get_process(uint32_t pid) {
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid == pid) {
            return &process_table[i];
        }
    }
    
    return NULL; // Process not found
}

// Simple scheduler - just increments CPU time for running processes
void update_process_times(void) {
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0 && process_table[i].status == 1) {
            process_table[i].cpu_time++;
        }
    }
}

// Update system uptime
void update_uptime(void) {
    time_info_t current_time;
    get_system_time(&current_time);
    
    uint32_t current_seconds = current_time.hour * 3600 + 
                              current_time.minute * 60 + 
                              current_time.second;
    
    if (boot_time == 0) {
        boot_time = current_seconds;
        return;
    }
    
    uint32_t elapsed = 0;
    if (current_seconds >= boot_time) {
        elapsed = current_seconds - boot_time;
    } else {
        // Прошли через полночь
        elapsed = (24 * 3600 - boot_time) + current_seconds;
    }
    
    system_uptime.days = elapsed / (24 * 3600);
    elapsed %= (24 * 3600);
    system_uptime.hours = elapsed / 3600;
    elapsed %= 3600;
    system_uptime.minutes = elapsed / 60;
    system_uptime.seconds = elapsed % 60;
}

// File system functions
directory_entry_t* create_directory(const char* name, directory_entry_t* parent) {
    if (!parent) {
        return NULL;
    }
    
    // Проверяем, существует ли директория с таким именем
    for (size_t i = 0; i < parent->subdir_count; i++) {
        if (strcmp(parent->subdirs[i].name, name) == 0) {
            return NULL;
        }
    }
    
    // Выделяем память для новой директории
    directory_entry_t* new_subdirs = (directory_entry_t*)memcpy(
        parent->subdirs,
        sizeof(directory_entry_t) * (parent->subdir_count + 1)
    );
    
    if (!new_subdirs) {
        return NULL;
    }
    
    parent->subdirs = new_subdirs;
    directory_entry_t* new_dir = &parent->subdirs[parent->subdir_count];
    
    strcpy(new_dir->name, name);
    new_dir->is_directory = 1;
    new_dir->parent = parent;
    new_dir->subdirs = NULL;
    new_dir->subdir_count = 0;
    new_dir->files = NULL;
    new_dir->file_count = 0;
    
    parent->subdir_count++;
    return new_dir;
}

directory_entry_t* find_directory(const char* path) {
    if (strcmp(path, "/") == 0) {
        return &root_directory;
    }
    
    if (strcmp(path, ".") == 0) {
        return current_directory;
    }
    
    if (strcmp(path, "..") == 0) {
        return current_directory->parent ? current_directory->parent : &root_directory;
    }
    
    // Поиск директории в текущей директории
    for (size_t i = 0; i < current_directory->subdir_count; i++) {
        if (strcmp(current_directory->subdirs[i].name, path) == 0) {
            return &current_directory->subdirs[i];
        }
    }
    
    return NULL;
}

void update_current_dir_string(void) {
    if (current_directory == &root_directory) {
        strcpy(current_dir, "/");
        return;
    }
    
    char temp_path[256] = {0};
    directory_entry_t* dir = current_directory;
    
    while (dir && dir != &root_directory) {
        char temp[256] = {0};
        strcpy(temp, temp_path);
        strcpy(temp_path, "/");
        strcat(temp_path, dir->name);
        strcat(temp_path, temp);
        dir = dir->parent;
    }
    
    if (temp_path[0] == '\0') {
        strcpy(current_dir, "/");
    } else {
        strcpy(current_dir, temp_path);
    }
}

// CPU detection using CPUID - architecture-specific implementation
void detect_cpu(void) {
    uint32_t eax, ebx, ecx, edx;
    char vendor[13];
    
    // Check if CPUID is supported
    #ifdef ARCH_64
    __asm__ volatile(
        "pushfq\n\t"
        "popq %%rax\n\t"
        "movq %%rax, %%rcx\n\t"
        "xorq $0x200000, %%rax\n\t"
        "pushq %%rax\n\t"
        "popfq\n\t"
        "pushfq\n\t"
        "popq %%rax\n\t"
        "pushq %%rcx\n\t"
        "popfq\n\t"
        "xorq %%rcx, %%rax\n\t"
        "movl %%eax, %0"
        : "=r" (eax)
        :: "rax", "rcx"
    );
    #else
    __asm__ volatile(
        "pushfl\n\t"
        "popl %%eax\n\t"
        "movl %%eax, %%ecx\n\t"
        "xorl $0x200000, %%eax\n\t"
        "pushl %%eax\n\t"
        "popfl\n\t"
        "pushfl\n\t"
        "popl %%eax\n\t"
        "pushl %%ecx\n\t"
        "popfl\n\t"
        "xorl %%ecx, %%eax\n\t"
        "movl %%eax, %0"
        : "=r" (eax)
        :: "eax", "ecx"
    );
    #endif
    
    if (!eax) {
        strcpy(system_info.cpu_vendor, "No CPUID");
        return;
    }
    
    // Get vendor ID
    __asm__ volatile(
        "xor %%eax, %%eax\n\t"
        "cpuid"
        : "=b" (ebx), "=c" (ecx), "=d" (edx)
        :: "eax"
    );
    
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    vendor[12] = '\0';
    strcpy(system_info.cpu_vendor, vendor);
    
    // Check for extended CPUID
    __asm__ volatile(
        "mov $0x80000000, %%eax\n\t"
        "cpuid"
        : "=a" (eax)
        :: "ebx", "ecx", "edx"
    );
    
    if (eax >= 0x80000001) {
        // Check for long mode support
        __asm__ volatile(
            "mov $0x80000001, %%eax\n\t"
            "cpuid"
            : "=d" (edx)
            :: "eax", "ebx", "ecx"
        );
        
        if (edx & CPUID_FEAT_EDX_LONG_MODE) {
            system_info.is_long_mode = 1;
            system_info.arch = ARCH_X86_64;
        }
    }
    
    // Get processor brand string
    if (eax >= 0x80000004) {
        char brand[48];
        
        for (int i = 0; i < 3; i++) {
            __asm__ volatile(
                "mov $0x80000002, %%eax\n\t"
                "add %4, %%eax\n\t"
                "cpuid"
                : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
                : "r" (i)
            );
            
            memcpy(brand + i * 16, &eax, 4);
            memcpy(brand + i * 16 + 4, &ebx, 4);
            memcpy(brand + i * 16 + 8, &ecx, 4);
            memcpy(brand + i * 16 + 12, &edx, 4);
        }
        
        brand[47] = '\0';
        strcpy(system_info.cpu_name, brand);
    }

    // In 64-bit mode, we know we're already in long mode
    #ifdef ARCH_64
    system_info.is_long_mode = 1;
    system_info.arch = ARCH_X86_64;
    current_arch = ARCH_X86_64;
    #endif
}

// Setup paging for long mode - x86 specific
void setup_long_mode(void) {
    #ifndef ARCH_64
    if (!system_info.is_long_mode) {
        terminal_writestring("Error: Long mode not supported by CPU\n");
        return;
    }

    // Clear paging tables
    for (int i = 0; i < 512; i++) {
        pml4_table[i] = 0;
        pdpt_table[i] = 0;
        pd_table[i] = 0;
    }

    // Set up identity paging
    // PML4 points to PDPT
    pml4_table[0] = (uint64_t)pdpt_table | 0x3; // Present + writable

    // PDPT points to PD
    pdpt_table[0] = (uint64_t)pd_table | 0x3; // Present + writable

    // Map first 2MB with 2MB pages
    for (int i = 0; i < 1; i++) {
        pd_table[i] = (i * 0x200000) | 0x83; // Present + writable + huge
    }

    // Load PML4 address into CR3
    __asm__ volatile(
        "mov %0, %%cr3"
        :: "r" ((uint32_t)pml4_table)
        : "memory"
    );

    // Enable PAE
    __asm__ volatile(
        "mov %%cr4, %%eax\n\t"
        "or $0x20, %%eax\n\t"
        "mov %%eax, %%cr4"
        ::: "eax", "memory"
    );

    // Set long mode bit in EFER MSR
    __asm__ volatile(
        "mov $0xC0000080, %%ecx\n\t"
        "rdmsr\n\t"
        "or $0x100, %%eax\n\t"
        "wrmsr"
        ::: "eax", "ecx", "edx", "memory"
    );

    // Enable paging
    __asm__ volatile(
        "mov %%cr0, %%eax\n\t"
        "or $0x80000000, %%eax\n\t"
        "mov %%eax, %%cr0"
        ::: "eax", "memory"
    );

    terminal_writestring("Long mode initialized successfully\n");
    current_arch = ARCH_X86_64;
    #else
    // In 64-bit build, we're already in long mode
    terminal_writestring("Already running in 64-bit long mode\n");
    #endif
}

// Show system information
void show_system_info(void) {
    terminal_writestring("=== System Information ===\n");
    
    terminal_writestring("CPU Vendor: ");
    terminal_writestring(system_info.cpu_vendor);
    terminal_writestring("\n");
    
    terminal_writestring("CPU Name: ");
    terminal_writestring(system_info.cpu_name);
    terminal_writestring("\n");
    
    terminal_writestring("Architecture: ");
    #ifdef ARCH_64
    terminal_writestring("x86_64 (64-bit)\n");
    #else
    if (system_info.arch == ARCH_X86_64) {
        terminal_writestring("x86_64 (64-bit)\n");
    } else {
        terminal_writestring("x86 (32-bit)\n");
    }
    #endif
    
    terminal_writestring("Long Mode: ");
    if (system_info.is_long_mode) {
        terminal_writestring("Supported and ");
        if (current_arch == ARCH_X86_64) {
            terminal_writestring("Enabled\n");
        } else {
            terminal_writestring("Available\n");
        }
    } else {
        terminal_writestring("Not Supported\n");
    }
    
    terminal_writestring("Current Mode: ");
    if (current_arch == ARCH_X86_64) {
        terminal_writestring("64-bit\n");
    } else {
        terminal_writestring("32-bit\n");
    }
    
    terminal_writestring("=========================\n");
}

// VGA text mode functions
static inline uint8_t vga_entry_color(enum vga_color fg, enum vga_color bg) {
    return fg | bg << 4;
}

static inline uint16_t vga_entry(unsigned char uc, uint8_t color) {
    return (uint16_t)uc | (uint16_t)color << 8;
}

// Keyboard scancode to ASCII mapping
static const char keyboard_map[] = {
    0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' '
};

// BCD to binary conversion for RTC values
static uint8_t bcd_to_binary(uint8_t bcd) {
    return ((bcd & 0xF0) >> 4) * 10 + (bcd & 0x0F);
}

// Read a value from the RTC
static uint8_t read_rtc_register(uint8_t reg) {
    outb(RTC_INDEX_PORT, reg);
    return inb(RTC_DATA_PORT);
}

void get_system_time(time_info_t* time) {
    time->second = bcd_to_binary(read_rtc_register(RTC_SECOND));
    time->minute = bcd_to_binary(read_rtc_register(RTC_MINUTE));
    time->hour = bcd_to_binary(read_rtc_register(RTC_HOUR));
    time->day = bcd_to_binary(read_rtc_register(RTC_DAY));
    time->month = bcd_to_binary(read_rtc_register(RTC_MONTH));
    time->year = bcd_to_binary(read_rtc_register(RTC_YEAR)) +