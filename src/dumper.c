#include "dumper.h" // Include the header file for declarations
#include <stdio.h>  // Standard I/O for file operations
#include <stdlib.h> // Standard library for memory allocation
#include <execinfo.h> // For backtrace functionality
#include <fcntl.h>  // For file control operations like open
#include <unistd.h> // For close function

// Function to collect and dump stack trace to a file
void collect_stack_dump() {
    void *array[20]; // Array to store stack frame addresses (adjust size as needed)
    size_t size; // To store the number of stack frames captured
    char **strings; // Array to store symbols (function names) of stack frames
    int fd; // File descriptor for the stack dump file

    // Open the stack dump file with write, create, and append options
    fd = open("stack_dump.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd < 0) {
        perror("Failed to open stack dump file"); // Error handling for file opening failure
        return;
    }

    // Capture stack frames
    size = backtrace(array, sizeof(array) / sizeof(void*));
    // Convert addresses to strings (symbols)
    strings = backtrace_symbols(array, size);

    if (strings != NULL) {
        // Write each symbol to file
        for (size_t i = 0; i < size; i++) {
            dprintf(fd, "%s\n", strings[i]);
        }
        free(strings); // Free the allocated memory for symbols
    }

    close(fd); // Close the file descriptor
}
