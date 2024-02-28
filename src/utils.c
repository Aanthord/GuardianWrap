#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to convert bytes to hexadecimal string
char* bytes_to_hex(const uint8_t* bytes, size_t len) {
    // Allocate memory for the hexadecimal string (two characters per byte plus one for null terminator)
    char* hex_string = malloc((len * 2) + 1);
    if (hex_string == NULL) {
        perror("Memory allocation failed"); // Handle memory allocation failure
        exit(EXIT_FAILURE);
    }

    // Convert each byte to hexadecimal representation
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]); // Format each byte as two hexadecimal characters
    }
    hex_string[len * 2] = '\0'; // Add null terminator

    return hex_string;
}

// Function to register signal handlers for specified signals
void register_signal_handlers(void (*handler)(int)) {
    // Example: Registering signal handler for SIGINT
    if (signal(SIGINT, handler) == SIG_ERR) {
        perror("Cannot handle SIGINT!"); // Handle error if signal registration fails
        exit(EXIT_FAILURE);
    }
    // Additional signals can be registered here
}
