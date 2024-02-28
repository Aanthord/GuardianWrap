#include "logger.h"
#include "blake3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

FILE *log_file = NULL;
const char *log_file_path = "application.log";

void init_logger() {
    log_file = fopen(log_file_path, "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
}

void log_message(const char *message) {
    if (!log_file) {
        fprintf(stderr, "Logger not initialized\n");
        return;
    }

    // Timestamp for the log entry
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline

    // Compute BLAKE3 hash
    uint8_t hash[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (const uint8_t *)message, strlen(message));
    blake3_hasher_finalize(&hasher, hash, sizeof(hash));

    // Convert hash to hex string
    char hex_hash[BLAKE3_OUT_LEN * 2 + 1];
    for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
        sprintf(&hex_hash[i * 2], "%02x", hash[i]);
    }

    // Log with structured format: timestamp, hash, and message
    fprintf(log_file, "[%s] %s %s\n", time_str, hex_hash, message);
    fflush(log_file); // Ensure log entry is written immediately
}

void close_logger() {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

