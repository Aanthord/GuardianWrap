#include "logger.h"
#include "blake3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Global variables
FILE *log_file = NULL;
const char *log_file_path = "application.log";

// Function to initialize the logger
void init_logger() {
    // Open log file in append mode
    log_file = fopen(log_file_path, "a");
    if (!log_file) {
        perror("Failed to open log file"); // Handle file opening error
        exit(EXIT_FAILURE);
    }
}

// Function to log a message with timestamp and hash
void log_message(const char *message) {
    if (!log_file) {
        fprintf(stderr, "Logger not initialized\n");
        return;
    }

    // Get current time
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline character

    // Compute BLAKE3 hash of the message
    uint8_t hash[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (const uint8_t *)message, strlen(message));
    blake3_hasher_finalize(&hasher, hash, sizeof(hash));

    // Convert hash to hexadecimal string
    char hex_hash[BLAKE3_OUT_LEN * 2 + 1];
    for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
        sprintf(&hex_hash[i * 2], "%02x", hash[i]);
    }

    // Log message with timestamp and hash
    fprintf(log_file, "[%s] %s %s\n", time_str, hex_hash, message);
    fflush(log_file); // Flush buffer to ensure immediate write to file
}

// Function to close the logger
void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
