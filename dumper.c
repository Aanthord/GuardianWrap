#include "dumper.h" // Include the header file for declarations
#include <stdio.h>  // Standard I/O for file operations
#include <stdlib.h> // Standard library for memory allocation
#include <execinfo.h> // For backtrace functionality
#include <fcntl.h>  // For file control operations like open
#include <unistd.h> // For close function

void collect_stack_dump() {
    void *array[20]; // Increase stack frame capture depth
    size_t size; // To store the number of stack frames captured
    char **strings; // For storing the symbols (function names) of stack frames
    int fd; // File descriptor for the stack dump file

    // Open the stack dump file with write, create, and append options
    fd = open("stack_dump.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd < 0) {
        perror("Failed to open stack dump file"); // Error handling
        return;
    }

    size = backtrace(array, sizeof(array) / sizeof(void*)); // Capture stack frames
    strings = backtrace_symbols(array, size); // Convert addresses to strings

    if (strings != NULL) {
        for (size_t i = 0; i < size; i++) {
            dprintf(fd, "%s\n", strings[i]); // Write each symbol to file
        }
        free(strings); // Free the allocated memory for symbols
    }

    close(fd); // Close the file descriptor
}

