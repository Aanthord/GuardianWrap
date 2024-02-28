#include "immutable_logger.h"
#include "logger.h" // Include logger for error logging
#include <stdio.h>
#include <stdlib.h>

// Function to append data to an immutable log file
void immutable_append(const char *data) {
    // Open the log file in append mode to ensure data is only added
    FILE *fp = fopen("immutable_log.txt", "a");
    if (fp == NULL) {
        log_message(LOG_LEVEL_ERROR, "Failed to open immutable log file");
        return;
    }

    fprintf(fp, "%s\n", data); // Append the data to the file with a newline

    if (fclose(fp) != 0) {
        log_message(LOG_LEVEL_ERROR, "Failed to close immutable log file");
    }
}
