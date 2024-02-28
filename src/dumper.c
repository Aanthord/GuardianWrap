#include "dumper.h"
#include "logger.h" // Include logger for error logging
#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>

void collect_stack_dump() {
    void *array[20]; // Increase stack frame capture depth
    size_t size; // To store the number of stack frames captured
    char **strings; // For storing the symbols (function names) of stack frames
    int fd; // File descriptor for the stack dump file

    // Open the stack dump file with write, create, and append options
    fd = open("stack_dump.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd < 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to open stack dump file in collect_stack_dump function.");
        return;
    }

    size = backtrace(array, sizeof(array) / sizeof(void*)); // Capture stack frames
    strings = backtrace_symbols(array, size); // Convert addresses to strings

    if (strings != NULL) {
        for (size_t i = 0; i < size; i++) {
            dprintf(fd, "%s\n", strings[i]); // Write each symbol to file
        }
        free(strings); // Free the allocated memory for symbols
    } else {
        log_message(LOG_LEVEL_ERROR, "Failed to obtain stack frame symbols in collect_stack_dump function.");
    }

    close(fd); // Close the file descriptor
}
