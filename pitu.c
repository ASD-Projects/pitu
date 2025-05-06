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

// ACPI Battery Information ports and registers
#define ACPI_PM_CONTROL_PORT 0x1804
#define ACPI_PM_DATA_PORT 0x1805
#define ACPI_BATTERY_STATUS_REG 0x10
#define ACPI_BATTERY_INFO_REG 0x11
#define ACPI_BATTERY_CAPACITY_REG 0x12

// Buffer size
#define COMMAND_BUFFER_SIZE 256
#define MAX_FILE_ENTRIES 20
#define MAX_FILENAME_LENGTH 32
#define MAX_DIRECTORY_ENTRIES 20
#define MAX_DIRECTORY_NAME_LENGTH 32

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
    uint32_t boot_time;
} system_info_t;

// Directory structure
typedef struct {
    char name[MAX_DIRECTORY_NAME_LENGTH];
    int parent_index;  // Index of parent directory, -1 for root
} directory_entry_t;

// Simple file system structure
typedef struct {
    char name[MAX_FILENAME_LENGTH];
    char content[256];
    size_t size;
    int directory_index;  // Index of the directory containing this file
} file_entry_t;

static directory_entry_t directory_system[MAX_DIRECTORY_ENTRIES] = {
    {"/", -1}  // Root directory
};
static size_t directory_count = 1;
static int current_directory_index = 0;  // Start in root directory

static file_entry_t file_system[MAX_FILE_ENTRIES] = {
    {"readme.txt", "Welcome to PituFS, the simple file system for Pitu Basic Kernel.", 60, 0},
    {"help.txt", "Type 'list' to see all available commands.", 42, 0}
};
static size_t file_count = 2;

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
static void show_uptime(void);
static void create_directory(const char* dirname);
static void change_directory(const char* dirname);
static void list_directories(void);
static int get_directory_index(const char* dirname);
static void get_full_path(char* path_buffer, int dir_index);
static void show_battery_status(void);

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
static uint32_t system_tick_counter = 0; // To track system uptime

// Initialize system_info
static system_info_t system_info = {
    .bg_color = VGA_BLACK,
    .fg_color = VGA_LIGHT_GREY,
    .cpu_vendor = "Unknown",
    .cpu_name = "Unknown CPU",
    .arch = ARCH_X86,
    .is_long_mode = 0,
    .boot_time = 0
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

// Write a value to ACPI register
static void write_acpi_register(uint8_t reg, uint8_t value) {
    outb(ACPI_PM_CONTROL_PORT, reg);
    outb(ACPI_PM_DATA_PORT, value);
}

// Read a value from ACPI register
static uint8_t read_acpi_register(uint8_t reg) {
    outb(ACPI_PM_CONTROL_PORT, reg);
    return inb(ACPI_PM_DATA_PORT);
}

// Get the full path of a directory
void get_full_path(char* path_buffer, int dir_index) {
    if (dir_index == 0) {
        strcpy(path_buffer, "/");
        return;
    }
    
    // Temporary buffer to store path parts
    char temp_path[256] = "";
    char part_buffer[MAX_DIRECTORY_NAME_LENGTH + 1];
    int current = dir_index;
    
    // Traverse up the directory tree
    while (current != 0) {
        strcpy(part_buffer, "/");
        strcpy(part_buffer + 1, directory_system[current].name);
        
        // Prepend this part to the temporary path
        char temp_copy[256];
        strcpy(temp_copy, temp_path);
        strcpy(temp_path, part_buffer);
        strcpy(temp_path + strlen(part_buffer), temp_copy);
        
        current = directory_system[current].parent_index;
    }
    
    // If the resulting path is empty, use root
    if (temp_path[0] == '\0') {
        strcpy(path_buffer, "/");
    } else {
        strcpy(path_buffer, temp_path);
    }
}

// Get directory index by name
int get_directory_index(const char* dirname) {
    // Handle special case for root
    if (strcmp(dirname, "/") == 0) {
        return 0;
    }
    
    // Handle special case for current directory
    if (strcmp(dirname, ".") == 0) {
        return current_directory_index;
    }
    
    // Handle special case for parent directory
    if (strcmp(dirname, "..") == 0) {
        return directory_system[current_directory_index].parent_index >= 0 ?
               directory_system[current_directory_index].parent_index : 0;
    }
    
    // Search for the directory in the current directory
    for (size_t i = 1; i < directory_count; i++) {
        if (strcmp(directory_system[i].name, dirname) == 0 && 
            directory_system[i].parent_index == current_directory_index) {
            return i;
        }
    }
    
    return -1; // Directory not found
}

// Create a new directory
void create_directory(const char* dirname) {
    if (directory_count >= MAX_DIRECTORY_ENTRIES) {
        terminal_writestring("Error: Maximum number of directories reached\n");
        return;
    }
    
    // Check if directory already exists
    if (get_directory_index(dirname) != -1) {
        terminal_writestring("Error: Directory already exists: ");
        terminal_writestring(dirname);
        terminal_writestring("\n");
        return;
    }
    
    // Create new directory
    strcpy(directory_system[directory_count].name, dirname);
    directory_system[directory_count].parent_index = current_directory_index;
    directory_count++;
    
    terminal_writestring("Directory created: ");
    terminal_writestring(dirname);
    terminal_writestring("\n");
}

// Change current directory
void change_directory(const char* dirname) {
    int dir_index = get_directory_index(dirname);
    
    if (dir_index == -1) {
        terminal_writestring("Error: Directory not found: ");
        terminal_writestring(dirname);
        terminal_writestring("\n");
        return;
    }
    
    current_directory_index = dir_index;
    get_full_path(current_dir, current_directory_index);
    
    terminal_writestring("Changed to directory: ");
    terminal_writestring(current_dir);
    terminal_writestring("\n");
}

// List all directories in the current directory
void list_directories(void) {
    terminal_writestring("Directories in ");
    terminal_writestring(current_dir);
    terminal_writestring(":\n");
    
    // Always show parent directory option unless at root
    if (current_directory_index != 0) {
        terminal_writestring("- ..\n");
    }
    
    // List all directories that have the current directory as parent
    for (size_t i = 1; i < directory_count; i++) {
        if (directory_system[i].parent_index == current_directory_index) {
            terminal_writestring("- ");
            terminal_writestring(directory_system[i].name);
            terminal_writestring("\n");
        }
    }
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

// Show uptime information
void show_uptime(void) {
    uint32_t uptime_seconds = system_tick_counter / 100;  // Assuming 100 ticks per second
    
    // Calculate days, hours, minutes, seconds
    uint32_t days = uptime_seconds / (24 * 60 * 60);
    uptime_seconds %= (24 * 60 * 60);
    uint32_t hours = uptime_seconds / (60 * 60);
    uptime_seconds %= (60 * 60);
    uint32_t minutes = uptime_seconds / 60;
    uint32_t seconds = uptime_seconds % 60;
    
    terminal_writestring("System uptime: ");
    
    // Convert days to string
    if (days > 0) {
        char days_str[10];
        int i = 0;
        uint32_t temp = days;
        
        if (temp == 0) {
            days_str[i++] = '0';
        } else {
            char rev[10];
            int rev_idx = 0;
            while (temp > 0) {
                rev[rev_idx++] = '0' + (temp % 10);
                temp /= 10;
            }
            while (rev_idx > 0) {
                days_str[i++] = rev[--rev_idx];
            }
        }
        days_str[i] = '\0';
        
        terminal_writestring(days_str);
        terminal_writestring(" day");
        if (days != 1) terminal_writestring("s");
        terminal_writestring(", ");
    }
    
    // Convert hours to string
    char hours_str[3];
    int i = 0;
    uint32_t temp = hours;
    
    if (temp == 0) {
        hours_str[i++] = '0';
    } else {
        char rev[3];
        int rev_idx = 0;
        while (temp > 0) {
            rev[rev_idx++] = '0' + (temp % 10);
            temp /= 10;
        }
        while (rev_idx > 0) {
            hours_str[i++] = rev[--rev_idx];
        }
    }
    hours_str[i] = '\0';
    
    if (hours < 10) terminal_putchar('0');
    terminal_writestring(hours_str);
    terminal_putchar(':');
    
    // Convert minutes to string
    char min_str[3];
    i = 0;
    temp = minutes;
    
    if (temp == 0) {
        min_str[i++] = '0';
    } else {
        char rev[3];
        int rev_idx = 0;
        while (temp > 0) {
            rev[rev_idx++] = '0' + (temp % 10);
            temp /= 10;
        }
        while (rev_idx > 0) {
            min_str[i++] = rev[--rev_idx];
        }
    }
    min_str[i] = '\0';
    
    if (minutes < 10) terminal_putchar('0');
    terminal_writestring(min_str);
    terminal_putchar(':');
    
    // Convert seconds to string
    char sec_str[3];
    i = 0;
    temp = seconds;
    
    if (temp == 0) {
        sec_str[i++] = '0';
    } else {
        char rev[3];
        int rev_idx = 0;
        while (temp > 0) {
            rev[rev_idx++] = '0' + (temp % 10);
            temp /= 10;
        }
        while (rev_idx > 0) {
            sec_str[i++] = rev[--rev_idx];
        }
    }
    sec_str[i] = '\0';
    
    if (seconds < 10) terminal_putchar('0');
    terminal_writestring(sec_str);
    terminal_writestring("\n");
    
    // Show number of processes
    terminal_writestring("Running processes: ");
    char proc_str[10];
    i = 0;
    temp = process_count;
    
    if (temp == 0) {
        proc_str[i++] = '0';
    } else {
        char rev[10];
        int rev_idx = 0;
        while (temp > 0) {
            rev[rev_idx++] = '0' + (temp % 10);
            temp /= 10;
        }
        while (rev_idx > 0) {
            proc_str[i++] = rev[--rev_idx];
        }
    }
    proc_str[i] = '\0';
    
    terminal_writestring(proc_str);
    terminal_writestring("\n");
}

// Show battery status
void show_battery_status(void) {
    // Read battery information from ACPI registers
    uint8_t battery_status = read_acpi_register(ACPI_BATTERY_STATUS_REG);
    uint8_t battery_info = read_acpi_register(ACPI_BATTERY_INFO_REG);
    uint8_t battery_capacity = read_acpi_register(ACPI_BATTERY_CAPACITY_REG);
    
    // Check if battery is present (bit 0 of battery_info)
    if (!(battery_info & 0x01)) {
        terminal_writestring("No battery detected or running on AC power.\n");
        return;
    }
    
    // Check if battery is charging (bit 1 of battery_status)
    terminal_writestring("Battery status: ");
    if (battery_status & 0x02) {
        terminal_writestring("Charging\n");
    } else {
        terminal_writestring("Discharging\n");
    }
    
    // Display battery percentage (battery_capacity is 0-100)
    terminal_writestring("Battery level: ");
    
    // Convert battery_capacity to string
    char capacity_str[4];
    int i = 0;
    uint8_t temp = battery_capacity;
    
    if (temp == 0) {
        capacity_str[i++] = '0';
    } else {
        char rev[4];
        int rev_idx = 0;
        while (temp > 0) {
            rev[rev_idx++] = '0' + (temp % 10);
            temp /= 10;
        }
        while (rev_idx > 0) {
            capacity_str[i++] = rev[--rev_idx];
        }
    }
    capacity_str[i] = '\0';
    
    terminal_writestring(capacity_str);
    terminal_writestring("%\n");
    
    // Display estimated time remaining (roughly calculated)
    if (!(battery_status & 0x02)) {  // If discharging
        terminal_writestring("Estimated time remaining: ");
        
        // Calculate rough estimate (capacity * 2 minutes per percent)
        uint16_t minutes_remaining = battery_capacity * 2;
        uint8_t hours = minutes_remaining / 60;
        uint8_t mins = minutes_remaining % 60;
        
        // Convert hours to string
        char hours_str[3];
        i = 0;
        temp = hours;
        
        if (temp == 0) {
            hours_str[i++] = '0';
        } else {
            char rev[3];
            int rev_idx = 0;
            while (temp > 0) {
                rev[rev_idx++] = '0' + (temp % 10);
                temp /= 10;
            }
            while (rev_idx > 0) {
                hours_str[i++] = rev[--rev_idx];
            }
        }
        hours_str[i] = '\0';
        
        terminal_writestring(hours_str);
        terminal_writestring(" hour");
        if (hours != 1) terminal_writestring("s");
        terminal_writestring(" ");
        
        // Convert minutes to string
        char mins_str[3];
        i = 0;
        temp = mins;
        
        if (temp == 0) {
            mins_str[i++] = '0';
        } else {
            char rev[3];
            int rev_idx = 0;
            while (temp > 0) {
                rev[rev_idx++] = '0' + (temp % 10);
                temp /= 10;
            }
            while (rev_idx > 0) {
                mins_str[i++] = rev[--rev_idx];
            }
        }
        mins_str[i] = '\0';
        
        terminal_writestring(mins_str);
        terminal_writestring(" minute");
        if (mins != 1) terminal_writestring("s");
        terminal_writestring("\n");
    }
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
    time->year = bcd_to_binary(read_rtc_register(RTC_YEAR)) + 2000; // Assuming post-2000
}

void terminal_initialize(void) {
    terminal_row = 0;
    terminal_column = 0;
    terminal_color = vga_entry_color(system_info.fg_color, system_info.bg_color);
    buffer_pos = 0;
    
    for (size_t y = 0; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            const size_t index = y * VGA_WIDTH + x;
            vga_buffer[index] = vga_entry(' ', terminal_color);
        }
    }
    
    terminal_writestring("Welcome to Pitu Basic Kernel (PBK)\n");
    
    #ifdef ARCH_64
    terminal_writestring("64-bit Edition\n\n");
    #else
    terminal_writestring("Dual Architecture Edition\n\n");
    #endif
    
    // Record boot time
    time_info_t current_time;
    get_system_time(&current_time);
    system_info.boot_time = (current_time.hour * 3600) + (current_time.minute * 60) + current_time.second;
}

void terminal_putchar(char c) {
    if (c == '\b') {
        if (terminal_column > 0) {
            terminal_column--;
            size_t index = terminal_row * VGA_WIDTH + terminal_column;
            vga_buffer[index] = vga_entry(' ', terminal_color);
        }
        return;
    }

    if (c == '\n') {
        terminal_column = 0;
        if (++terminal_row == VGA_HEIGHT) {
            // Scroll the screen
            for (size_t y = 1; y < VGA_HEIGHT; y++) {
                for (size_t x = 0; x < VGA_WIDTH; x++) {
                    const size_t to_index = (y - 1) * VGA_WIDTH + x;
                    const size_t from_index = y * VGA_WIDTH + x;
                    vga_buffer[to_index] = vga_buffer[from_index];
                }
            }
            // Clear the last line
            for (size_t x = 0; x < VGA_WIDTH; x++) {
                const size_t index = (VGA_HEIGHT - 1) * VGA_WIDTH + x;
                vga_buffer[index] = vga_entry(' ', terminal_color);
            }
            terminal_row = VGA_HEIGHT - 1;
        }
        return;
    }

    size_t index = terminal_row * VGA_WIDTH + terminal_column;
    vga_buffer[index] = vga_entry(c, terminal_color);
    
    if (++terminal_column == VGA_WIDTH) {
        terminal_column = 0;
        if (++terminal_row == VGA_HEIGHT) {
            // Scroll the screen
            for (size_t y = 1; y < VGA_HEIGHT; y++) {
                for (size_t x = 0; x < VGA_WIDTH; x++) {
                    const size_t to_index = (y - 1) * VGA_WIDTH + x;
                    const size_t from_index = y * VGA_WIDTH + x;
                    vga_buffer[to_index] = vga_buffer[from_index];
                }
            }
            // Clear the last line
            for (size_t x = 0; x < VGA_WIDTH; x++) {
                const size_t index = (VGA_HEIGHT - 1) * VGA_WIDTH + x;
                vga_buffer[index] = vga_entry(' ', terminal_color);
            }
            terminal_row = VGA_HEIGHT - 1;
        }
    }
}

void terminal_write(const char* data) {
    while (*data != '\0') {
        terminal_putchar(*data);
        data++;
    }
}

void terminal_writestring(const char* data) {
    terminal_write(data);
}

void print_prompt(void) {
    #ifdef ARCH_64
    terminal_write("pitu64 | ");
    #else
    if (current_arch == ARCH_X86_64) {
        terminal_write("pitu64 | ");
    } else {
        terminal_write("pitu | ");
    }
    #endif
    terminal_write(current_dir);
    terminal_write(">>> ");
}

void clear_screen(void) {
    for (size_t i = 0; i < VGA_HEIGHT * VGA_WIDTH; i++) {
        vga_buffer[i] = vga_entry(' ', terminal_color);
    }
    terminal_row = 0;
    terminal_column = 0;
}

enum vga_color parse_color(const char* color) {
    if (strcmp(color, "black") == 0) return VGA_BLACK;
    if (strcmp(color, "blue") == 0) return VGA_BLUE;
    if (strcmp(color, "green") == 0) return VGA_GREEN;
    if (strcmp(color, "cyan") == 0) return VGA_CYAN;
    if (strcmp(color, "red") == 0) return VGA_RED;
    if (strcmp(color, "magenta") == 0) return VGA_MAGENTA;
    if (strcmp(color, "brown") == 0) return VGA_BROWN;
    if (strcmp(color, "grey") == 0) return VGA_LIGHT_GREY;
    return VGA_BLACK;
}

void change_terminal_color(enum vga_color bg) {
    system_info.bg_color = bg;
    terminal_color = vga_entry_color(system_info.fg_color, system_info.bg_color);
    
    for (size_t i = 0; i < VGA_HEIGHT * VGA_WIDTH; i++) {
        uint16_t current = vga_buffer[i];
        unsigned char c = current & 0xFF;
        vga_buffer[i] = vga_entry(c, terminal_color);
    }
}

void print_file_contents(const char* filename) {
    for (size_t i = 0; i < file_count; i++) {
        if (strcmp(file_system[i].name, filename) == 0 && 
            file_system[i].directory_index == current_directory_index) {
            terminal_writestring(file_system[i].content);
            terminal_writestring("\n");
            return;
        }
    }
    terminal_writestring("File not found: ");
    terminal_writestring(filename);
    terminal_writestring("\n");
}

void create_file(const char* filename, const char* content) {
    if (file_count >= MAX_FILE_ENTRIES) {
        terminal_writestring("Error: File system is full\n");
        return;
    }
    
    // Check if file already exists in current directory
    for (size_t i = 0; i < file_count; i++) {
        if (strcmp(file_system[i].name, filename) == 0 && 
            file_system[i].directory_index == current_directory_index) {
            strcpy(file_system[i].content, content);
            file_system[i].size = strlen(content);
            terminal_writestring("File updated: ");
            terminal_writestring(filename);
            terminal_writestring("\n");
            return;
        }
    }
    
    // Create new file in current directory
    strcpy(file_system[file_count].name, filename);
    strcpy(file_system[file_count].content, content);
    file_system[file_count].size = strlen(content);
    file_system[file_count].directory_index = current_directory_index;
    file_count++;
    
    terminal_writestring("File created: ");
    terminal_writestring(filename);
    terminal_writestring("\n");
}

void list_files(void) {
    terminal_writestring("Files in ");
    terminal_writestring(current_dir);
    terminal_writestring(":\n");
    
    int files_found = 0;
    
    for (size_t i = 0; i < file_count; i++) {
        if (file_system[i].directory_index == current_directory_index) {
            files_found = 1;
            terminal_writestring("- ");
            terminal_writestring(file_system[i].name);
            terminal_writestring(" (");
            
            // Convert size to string and display
            char size_str[10];
            uint32_t size = file_system[i].size;
            int j = 0;
            
            if (size == 0) {
                size_str[j++] = '0';
            } else {
                char reverse[10];
                int rev_idx = 0;
                
                while (size > 0) {
                    reverse[rev_idx++] = '0' + (size % 10);
                    size /= 10;
                }
                
                while (rev_idx > 0) {
                    size_str[j++] = reverse[--rev_idx];
                }
            }
            size_str[j] = '\0';
            
            terminal_writestring(size_str);
            terminal_writestring(" bytes)\n");
        }
    }
    
    if (!files_found) {
        terminal_writestring("No files in this directory.\n");
    }
}

void show_processes(void) {
    terminal_writestring("Process List (Total: ");
    
    // Convert process_count to string and display
    char count_str[4];
    int count_idx = 0;
    uint8_t temp_count = process_count;
    
    if (temp_count == 0) {
        count_str[count_idx++] = '0';
    } else {
        char rev[4];
        int rev_idx = 0;
        
        while (temp_count > 0) {
            rev[rev_idx++] = '0' + (temp_count % 10);
            temp_count /= 10;
        }
        
        while (rev_idx > 0) {
            count_str[count_idx++] = rev[--rev_idx];
        }
    }
    count_str[count_idx] = '\0';
    
    terminal_writestring(count_str);
    terminal_writestring(")\n");
    
    terminal_writestring("PID  | PPID | NAME           | STATUS   | PRIO | MEM(KB) | CPU(ms)\n");
    terminal_writestring("-----+------+----------------+----------+------+---------+--------\n");
    
    // Display each process
    for (uint32_t i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0) {
            // PID
            char pid_str[6];
            uint32_t pid = process_table[i].pid;
            int j = 0;
            
            if (pid == 0) {
                pid_str[j++] = '0';
            } else {
                char rev[6];
                int rev_idx = 0;
                
                while (pid > 0) {
                    rev[rev_idx++] = '0' + (pid % 10);
                    pid /= 10;
                }
                
                while (rev_idx > 0) {
                    pid_str[j++] = rev[--rev_idx];
                }
            }
            pid_str[j] = '\0';
            
            terminal_writestring(pid_str);
            // Padding for PID
            for (int k = j; k < 5; k++) {
                terminal_putchar(' ');
            }
            
            // Parent PID
            terminal_writestring("| ");
            
            char ppid_str[6];
            uint32_t ppid = process_table[i].parent_pid;
            j = 0;
            
            if (ppid == 0) {
                ppid_str[j++] = '0';
            } else {
                char rev[6];
                int rev_idx = 0;
                
                while (ppid > 0) {
                    rev[rev_idx++] = '0' + (ppid % 10);
                    ppid /= 10;
                }
                
                while (rev_idx > 0) {
                    ppid_str[j++] = rev[--rev_idx];
                }
            }
            ppid_str[j] = '\0';
            
            terminal_writestring(ppid_str);
            // Padding for PPID
            for (int k = j; k < 4; k++) {
                terminal_putchar(' ');
            }
            
            // Name
            terminal_writestring("| ");
            terminal_writestring(process_table[i].name);
            
            // Padding for name
            size_t name_len = strlen(process_table[i].name);
            for (size_t k = name_len; k < 14; k++) {
                terminal_putchar(' ');
            }
            
            // Status
            terminal_writestring("| ");
            
            switch (process_table[i].status) {
                case 0:
                    terminal_writestring("STOPPED  ");
                    break;
                case 1:
                    terminal_writestring("RUNNING  ");
                    break;
                case 2:
                    terminal_writestring("SLEEPING ");
                    break;
                case 3:
                    terminal_writestring("ZOMBIE   ");
                    break;
                default:
                    terminal_writestring("UNKNOWN  ");
            }
            
            // Priority
            terminal_writestring("| ");
            
            char prio_str[4];
            uint32_t prio = process_table[i].priority;
            j = 0;
            
            if (prio == 0) {
                prio_str[j++] = '0';
            } else {
                char rev[4];
                int rev_idx = 0;
                
                while (prio > 0) {
                    rev[rev_idx++] = '0' + (prio % 10);
                    prio /= 10;
                }
                
                while (rev_idx > 0) {
                    prio_str[j++] = rev[--rev_idx];
                }
            }
            prio_str[j] = '\0';
            
            terminal_writestring(prio_str);
            // Padding for priority
            for (int k = j; k < 4; k++) {
                terminal_putchar(' ');
            }
            
            // Memory usage
            terminal_writestring("| ");
            
            char mem_str[8];
            uint32_t mem = process_table[i].memory_usage;
            j = 0;
            
            if (mem == 0) {
                mem_str[j++] = '0';
            } else {
                char rev[8];
                int rev_idx = 0;
                
                while (mem > 0) {
                    rev[rev_idx++] = '0' + (mem % 10);
                    mem /= 10;
                }
                
                while (rev_idx > 0) {
                    mem_str[j++] = rev[--rev_idx];
                }
            }
            mem_str[j] = '\0';
            
            terminal_writestring(mem_str);
            // Padding for memory usage
            for (int k = j; k < 7; k++) {
                terminal_putchar(' ');
            }
            
            // CPU time
            terminal_writestring("| ");
            
            char cpu_str[8];
            uint32_t cpu = process_table[i].cpu_time;
            j = 0;
            
            if (cpu == 0) {
                cpu_str[j++] = '0';
            } else {
                char rev[8];
                int rev_idx = 0;
                
                while (cpu > 0) {
                    rev[rev_idx++] = '0' + (cpu % 10);
                    cpu /= 10;
                }
                
                while (rev_idx > 0) {
                    cpu_str[j++] = rev[--rev_idx];
                }
            }
            cpu_str[j] = '\0';
            
            terminal_writestring(cpu_str);
            terminal_writestring("\n");
        }
    }
}

// Handle process commands
void handle_process_commands(char* command, char* arg) {
    if (strcmp(command, "start") == 0) {
        if (*arg) {
            // For demo purposes, just create a shell process
            uint32_t pid = create_process(arg, NULL, 5, 1);
            if (pid) {
                terminal_writestring("Started process '");
                terminal_writestring(arg);
                terminal_writestring("' with PID ");
                
                char pid_str[10];
                int j = 0;
                char rev[10];
                int rev_idx = 0;
                
                while (pid > 0) {
                    rev[rev_idx++] = '0' + (pid % 10);
                    pid /= 10;
                }
                
                while (rev_idx > 0) {
                    pid_str[j++] = rev[--rev_idx];
                }
                pid_str[j] = '\0';
                
                terminal_writestring(pid_str);
                terminal_writestring("\n");
            } else {
                terminal_writestring("Failed to start process: system resources exhausted\n");
            }
        } else {
            terminal_writestring("Usage: start [process_name]\n");
        }
    }
    else if (strcmp(command, "kill") == 0) {
        if (*arg) {
            // Convert arg to integer PID
            uint32_t pid = 0;
            char* ptr = arg;
            
            while (*ptr >= '0' && *ptr <= '9') {
                pid = pid * 10 + (*ptr - '0');
                ptr++;
            }
            
            if (pid == 1) {
                terminal_writestring("Error: Cannot terminate kernel process (PID 1)\n");
            } else {
                if (terminate_process(pid)) {
                    terminal_writestring("Process with PID ");
                    terminal_writestring(arg);
                    terminal_writestring(" terminated\n");
                } else {
                    terminal_writestring("No process found with PID ");
                    terminal_writestring(arg);
                    terminal_writestring("\n");
                }
            }
        } else {
            terminal_writestring("Usage: kill [pid]\n");
        }
    }
    else if (strcmp(command, "sleep") == 0) {
        if (*arg) {
            // Convert arg to integer PID
            uint32_t pid = 0;
            char* ptr = arg;
            
            while (*ptr >= '0' && *ptr <= '9') {
                pid = pid * 10 + (*ptr - '0');
                ptr++;
            }
            
            if (pid == 1) {
                terminal_writestring("Error: Cannot sleep kernel process (PID 1)\n");
            } else {
                if (change_process_status(pid, 2)) { // 2 = sleeping
                    terminal_writestring("Process with PID ");
                    terminal_writestring(arg);
                    terminal_writestring(" is now sleeping\n");
                } else {
                    terminal_writestring("No process found with PID ");
                    terminal_writestring(arg);
                    terminal_writestring("\n");
                }
            }
        } else {
            terminal_writestring("Usage: sleep [pid]\n");
        }
    }
    else if (strcmp(command, "wake") == 0) {
        if (*arg) {
            // Convert arg to integer PID
            uint32_t pid = 0;
            char* ptr = arg;
            
            while (*ptr >= '0' && *ptr <= '9') {
                pid = pid * 10 + (*ptr - '0');
                ptr++;
            }
            
            if (change_process_status(pid, 1)) { // 1 = running
                terminal_writestring("Process with PID ");
                terminal_writestring(arg);
                terminal_writestring(" is now running\n");
            } else {
                terminal_writestring("No process found with PID ");
                terminal_writestring(arg);
                terminal_writestring("\n");
            }
        } else {
            terminal_writestring("Usage: wake [pid]\n");
        }
    }
    else if (strcmp(command, "top") == 0) {
        show_processes();
    }
}

// Power off the system
void system_poweroff(void) {
    // ACPI shutdown sequence
    outb(0xF4, 0x00);
    
    // If ACPI shutdown doesn't work, try APM
    outb(0xB2, 0x00);
    outb(0x80FE, 0x00);
    
    // If all else fails, notify the user
    terminal_writestring("System poweroff initiated. If the system doesn't power off,\n");
    terminal_writestring("it may be running in an environment that doesn't support\n");
    terminal_writestring("ACPI or APM shutdown. You can safely power off manually.\n");
    
    // Halt the CPU
    __asm__ volatile("hlt");
}

// Reboot the system
void system_reboot(void) {
    // Try keyboard controller reset
    uint8_t temp;
    
    // Disable interrupts
    __asm__ volatile("cli");
    
    // Flush keyboard controller
    do {
        temp = inb(KEYBOARD_STATUS_PORT);
        if (temp & 1) inb(KEYBOARD_DATA_PORT);
    } while (temp & 2);
    
    // Send reset command to keyboard controller
    outb(KEYBOARD_STATUS_PORT, 0xFE);
    
    // If that doesn't work, try triple fault (invalid opcode)
    __asm__ volatile(".byte 0x0f, 0x0b");
    
    // If all else fails
    terminal_writestring("Reboot initiated. If the system doesn't restart,\n");
    terminal_writestring("it may be running in an environment that doesn't support\n");
    terminal_writestring("the reboot method. You can manually restart.\n");
    
    // Halt the CPU
    __asm__ volatile("hlt");
}

void process_keypress(void) {
    if (inb(KEYBOARD_STATUS_PORT) & 0x1) {
        uint8_t keycode = inb(KEYBOARD_DATA_PORT);
        
        if (keycode < sizeof(keyboard_map)) {
            char c = keyboard_map[keycode];
            
            if (c != 0) {
                if (c == '\n') {
                    terminal_putchar(c);
                    command_buffer[buffer_pos] = '\0';
                    handle_command(command_buffer);
                    buffer_pos = 0;
                    print_prompt();
                }
                else if (c == '\b' && buffer_pos > 0) {
                    buffer_pos--;
                    terminal_putchar(c);
                }
                else if (c != '\b' && buffer_pos < COMMAND_BUFFER_SIZE - 1) {
                    command_buffer[buffer_pos++] = c;
                    terminal_putchar(c);
                }
            }
        }
    }
}

void handle_command(char* cmd) {
    char* command = cmd;
    char* arg = cmd;
    while (*arg && *arg != ' ') arg++;
    if (*arg == ' ') {
        *arg = '\0';
        arg++;
    }

    if (strcmp(command, "version") == 0) {
        #ifdef ARCH_64
        terminal_writestring("Pitu Basic Kernel v0.2.2-dev (x86_64 Edition)\n");
        #else
        if (current_arch == ARCH_X86_64) {
            terminal_writestring("Pitu Basic Kernel v0.2.2-dev (x86_64 Mode)\n");
        } else {
            terminal_writestring("Pitu Basic Kernel v0.2.2-dev (x86 Mode)\n");
        }
        #endif
    }
    else if (strcmp(command, "about") == 0) {
        terminal_writestring("=== Pitu Basic Kernel ===\n");
        #ifdef ARCH_64
        terminal_writestring("Version: 0.2.2-dev (x86_64 Edition)\n");
        #else
        terminal_writestring("Version: 0.2.2-dev (Dual Architecture Edition)\n");
        #endif
        terminal_writestring("Build Date: May 5, 2025\n");
        terminal_writestring("Developer: AnmiTaliDev\n");
        terminal_writestring("Features:\n");
        terminal_writestring("- Basic shell interface\n");
        terminal_writestring("- Color customization\n");
        terminal_writestring("- Simple file system\n");
        terminal_writestring("- Process management\n");
        terminal_writestring("- System time access\n");
        terminal_writestring("- Power management\n");
        terminal_writestring("- x86_64 support\n");
        terminal_writestring("- Directory navigation\n");  // New feature
        terminal_writestring("- Uptime tracking\n");       // New feature
        terminal_writestring("- Battery status\n");        // New feature
        terminal_writestring("======================\n");
    }
    else if (strcmp(command, "echo") == 0) {
        if (*arg) {
            terminal_writestring(arg);
            terminal_writestring("\n");
        } else {
            terminal_writestring("Echo command - Usage: echo [text]\n");
        }
    }
    else if (strcmp(command, "clear") == 0) {
        clear_screen();
    }
    else if (strcmp(command, "clr") == 0) {
        if (*arg) {
            enum vga_color new_color = parse_color(arg);
            change_terminal_color(new_color);
            terminal_writestring("Background color changed to ");
            terminal_writestring(arg);
            terminal_writestring("\n");
        } else {
            terminal_writestring("Available colors:\n");
            terminal_writestring("- black\n");
            terminal_writestring("- blue\n");
            terminal_writestring("- green\n");
            terminal_writestring("- cyan\n");
            terminal_writestring("- red\n");
            terminal_writestring("- magenta\n");
            terminal_writestring("- brown\n");
            terminal_writestring("- grey\n");
            terminal_writestring("Usage: clr [color]\n");
        }
    }
    else if (strcmp(command, "time") == 0) {
        time_info_t current_time;
        get_system_time(&current_time);
        
        terminal_writestring("Current system time: ");
        
        // Hour
        if (current_time.hour < 10) terminal_putchar('0');
        char hour_str[3];
        if (current_time.hour == 0) {
            hour_str[0] = '0';
            hour_str[1] = '0';
            hour_str[2] = '\0';
        } else {
            int i = 0;
            uint8_t hour = current_time.hour;
            char rev[3];
            int rev_i = 0;
            while (hour > 0) {
                rev[rev_i++] = '0' + (hour % 10);
                hour /= 10;
            }
            while (rev_i > 0) {
                hour_str[i++] = rev[--rev_i];
            }
            hour_str[i] = '\0';
        }
        terminal_writestring(hour_str);
        
        terminal_putchar(':');
        
        // Minute
        if (current_time.minute < 10) terminal_putchar('0');
        char min_str[3];
        if (current_time.minute == 0) {
            min_str[0] = '0';
            min_str[1] = '0';
            min_str[2] = '\0';
        } else {
            int i = 0;
            uint8_t min = current_time.minute;
            char rev[3];
            int rev_i = 0;
            while (min > 0) {
                rev[rev_i++] = '0' + (min % 10);
                min /= 10;
            }
            while (rev_i > 0) {
                min_str[i++] = rev[--rev_i];
            }
            min_str[i] = '\0';
        }
        terminal_writestring(min_str);
        
        terminal_putchar(':');
        
        // Second
        if (current_time.second < 10) terminal_putchar('0');
        char sec_str[3];
        if (current_time.second == 0) {
            sec_str[0] = '0';
            sec_str[1] = '0';
            sec_str[2] = '\0';
        } else {
            int i = 0;
            uint8_t sec = current_time.second;
            char rev[3];
            int rev_i = 0;
            while (sec > 0) {
                rev[rev_i++] = '0' + (sec % 10);
                sec /= 10;
            }
            while (rev_i > 0) {
                sec_str[i++] = rev[--rev_i];
            }
            sec_str[i] = '\0';
        }
        terminal_writestring(sec_str);
        
        terminal_writestring(" (");
        
        // Day
        char day_str[3];
        if (current_time.day == 0) {
            day_str[0] = '0';
            day_str[1] = '0';
            day_str[2] = '\0';
        } else {
            int i = 0;
            uint8_t day = current_time.day;
            char rev[3];
            int rev_i = 0;
            while (day > 0) {
                rev[rev_i++] = '0' + (day % 10);
                day /= 10;
            }
            while (rev_i > 0) {
                day_str[i++] = rev[--rev_i];
            }
            day_str[i] = '\0';
        }
        terminal_writestring(day_str);
        
        terminal_putchar('/');
        
        // Month
        char month_str[3];
        if (current_time.month == 0) {
            month_str[0] = '0';
            month_str[1] = '0';
            month_str[2] = '\0';
        } else {
            int i = 0;
            uint8_t month = current_time.month;
            char rev[3];
            int rev_i = 0;
            while (month > 0) {
                rev[rev_i++] = '0' + (month % 10);
                month /= 10;
            }
            while (rev_i > 0) {
                month_str[i++] = rev[--rev_i];
            }
            month_str[i] = '\0';
        }
        terminal_writestring(month_str);
        
        terminal_putchar('/');
        
        // Year
        char year_str[5];
        if (current_time.year == 0) {
            year_str[0] = '0';
            year_str[1] = '0';
            year_str[2] = '0';
            year_str[3] = '0';
            year_str[4] = '\0';
        } else {
            int i = 0;
            uint16_t year = current_time.year;
            char rev[5];
            int rev_i = 0;
            while (year > 0) {
                rev[rev_i++] = '0' + (year % 10);
                year /= 10;
            }
            while (rev_i > 0) {
                year_str[i++] = rev[--rev_i];
            }
            year_str[i] = '\0';
        }
        terminal_writestring(year_str);
        
        terminal_writestring(")\n");
    }
    else if (strcmp(command, "cat") == 0) {
        if (*arg) {
            print_file_contents(arg);
        } else {
            terminal_writestring("Usage: cat [filename]\n");
        }
    }
    else if (strcmp(command, "write") == 0) {
        char* filename = arg;
        char* content = arg;
        
        // Parse filename and content
        while (*content && *content != ' ') content++;
        if (*content == ' ') {
            *content = '\0';
            content++;
            create_file(filename, content);
        } else {
            terminal_writestring("Usage: write [filename] [content]\n");
        }
    }
    else if (strcmp(command, "ls") == 0) {
        list_files();
    }
    else if (strcmp(command, "ps") == 0) {
        show_processes();
    }
    else if (strcmp(command, "start") == 0 || strcmp(command, "kill") == 0 || 
             strcmp(command, "sleep") == 0 || strcmp(command, "wake") == 0 || 
             strcmp(command, "top") == 0) {
        handle_process_commands(command, arg);
    }
    else if (strcmp(command, "poweroff") == 0) {
        terminal_writestring("Shutting down the system...\n");
        system_poweroff();
    }
    else if (strcmp(command, "reboot") == 0) {
        terminal_writestring("Rebooting the system...\n");
        system_reboot();
    }
    else if (strcmp(command, "sysinfo") == 0) {
        show_system_info();
    }
    else if (strcmp(command, "longmode") == 0) {
        #ifdef ARCH_64
        terminal_writestring("Already running in 64-bit mode (x86_64 build)\n");
        #else
        if (current_arch == ARCH_X86_64) {
            terminal_writestring("64-bit mode is already enabled.\n");
        } else {
            if (system_info.is_long_mode) {
                terminal_writestring("Switching to 64-bit long mode...\n");
                setup_long_mode();
            } else {
                terminal_writestring("Error: Long mode is not supported by this CPU.\n");
            }
        }
        #endif
    }
    // New command: uptime
    else if (strcmp(command, "uptime") == 0) {
        show_uptime();
    }
    // New command: mkdir
    else if (strcmp(command, "mkdir") == 0) {
        if (*arg) {
            create_directory(arg);
        } else {
            terminal_writestring("Usage: mkdir [directory_name]\n");
        }
    }
    // New command: cd
    else if (strcmp(command, "cd") == 0) {
        if (*arg) {
            change_directory(arg);
        } else {
            // Default to root directory if no argument is provided
            change_directory("/");
        }
    }
    // New command: dir (to list directories)
    else if (strcmp(command, "dir") == 0) {
        list_directories();
    }
    // New command: battery
    else if (strcmp(command, "battery") == 0) {
        show_battery_status();
    }
    else if (strcmp(command, "list") == 0) {
        terminal_writestring("Available commands:\n");
        terminal_writestring("- version: Display kernel version\n");
        terminal_writestring("- about: Show detailed kernel information\n");
        terminal_writestring("- echo [text]: Display text\n");
        terminal_writestring("- clear: Clear screen\n");
        terminal_writestring("- clr [color]: Change background color\n");
        terminal_writestring("- time: Display current system time\n");
        terminal_writestring("- uptime: Display system uptime\n");          // New command
        terminal_writestring("- cat [filename]: Display file contents\n");
        terminal_writestring("- write [filename] [content]: Create or update a file\n");
        terminal_writestring("- ls: List all files in current directory\n");
        terminal_writestring("- dir: List all directories in current directory\n"); // New command
        terminal_writestring("- mkdir [dirname]: Create a new directory\n");        // New command
        terminal_writestring("- cd [dirname]: Change current directory\n");         // New command
        terminal_writestring("- battery: Show battery status\n");                   // New command
        terminal_writestring("- ps: Show running processes\n");
        terminal_writestring("- top: Detailed process information\n");
        terminal_writestring("- start [name]: Start a new process\n");
        terminal_writestring("- kill [pid]: Terminate a process\n");
        terminal_writestring("- sleep [pid]: Put a process to sleep\n");
        terminal_writestring("- wake [pid]: Wake up a sleeping process\n");
        terminal_writestring("- sysinfo: Show system information\n");
        
        #ifndef ARCH_64
        if (system_info.is_long_mode && current_arch != ARCH_X86_64) {
            terminal_writestring("- longmode: Switch to 64-bit long mode\n");
        }
        #endif
        
        terminal_writestring("- poweroff: Shut down the system\n");
        terminal_writestring("- reboot: Restart the system\n");
        terminal_writestring("- list: Show available commands\n");
    }
    else if (command[0] != '\0') {
        terminal_writestring("Unknown command. Type 'list' for available commands.\n");
    }
}

void kernel_main(void) {
    // Initialize terminal
    terminal_initialize();
    
    // Detect CPU features
    detect_cpu();
    
    // Initialize process table
    init_process_table();
    
    // Create initial processes
    create_process("terminal", NULL, 2, 1);
    create_process("idle", NULL, 10, 1);
    
    // Print welcome message
    #ifdef ARCH_64
    terminal_writestring("64-bit mode active.\n");
    #else
    if (system_info.is_long_mode) {
        terminal_writestring("64-bit CPU detected. Type 'longmode' to switch to 64-bit mode.\n");
    } else {
        terminal_writestring("32-bit mode only. This CPU does not support 64-bit long mode.\n");
    }
    #endif
    
    // Begin command prompt
    print_prompt();
    
    // Main loop
    while (1) {
        process_keypress();
        
        // Update process times every ~100ms and increment system tick counter
        if (system_tick_counter++ % 100 == 0) {
            update_process_times();
        }
    }
}