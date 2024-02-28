#include <stdio.h>  // Standard I/O for file operations
#include <stdlib.h> // Standard library for exit

// Function to append data to an immutable log file
void immutable_append(const char *data) {
    // Open the log file in append mode to ensure data is only added
    FILE *fp = fopen("immutable_log.txt", "a");
    if (fp == NULL) {
        perror("Failed to open immutable log file"); // Error handling if file cannot be opened
        exit(EXIT_FAILURE); // Exit the program on failure
    }

    fprintf(fp, "%s\n", data); // Append the data to the file with a newline
    fclose(fp); // Close the file after appending
}

