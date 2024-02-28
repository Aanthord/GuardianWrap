#include "utils.h"
#include "logger.h" // Include logger for error logging
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* bytes_to_hex(const uint8_t* bytes, size_t len) {
    char* hex_string = malloc((len * 2) + 1);
    if (hex_string == NULL) {
        log_message(LOG_LEVEL_ERROR, "Memory allocation failed in bytes_to_hex.");
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    hex_string[len * 2] = '\0';
    return hex_string;
}

void register_signal_handlers(void (*handler)(int)) {
    // Example for SIGINT
    if (signal(SIGINT, handler) == SIG_ERR) {
        log_message(LOG_LEVEL_ERROR, "Cannot handle SIGINT!");
        exit(EXIT_FAILURE);
    }
    // Additional signals could be registered here
}
