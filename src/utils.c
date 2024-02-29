#include "utils.h" // Include the custom utils header
#include <stdio.h> // Standard I/O operations
#include <stdlib.h> // Standard library functions
#include <signal.h> // Signal handling functions

// Function to convert bytes to hexadecimal string
char* bytes_to_hex(const uint8_t* bytes, size_t len) {
    // Allocate memory for the hexadecimal string (twice the size of bytes + 1 for null terminator)
    char* hex_str = (char*)malloc(len * 2 + 1);
    if (!hex_str) {
        perror("Failed to allocate memory for hexadecimal string");
        return NULL;
    }

    // Convert each byte to two hexadecimal characters
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + i * 2, "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0'; // Null terminate the string
    return hex_str;
}

// Function to register signal handlers
void register_signal_handlers(void (*handler)(int)) {
    // Register signal handlers for common signals
    signal(SIGINT, handler);
    signal(SIGTERM, handler);
    signal(SIGQUIT, handler);
}
