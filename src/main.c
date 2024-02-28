#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "blake3.h"
#include "sha256.h"

// Define a custom stack canary structure
typedef struct {
    uint64_t value;
    char magic[8]; // Magic bytes for extra validation
} StackCanary;

#define STACK_CANARY_MAGIC "CANARY42"

#define STACK_CANARY_LOW 0
#define STACK_CANARY_HIGH 1

#define SALTSIZE 16
#define SHA256_DIGEST_LENGTH 32

// Function prototypes
void setup_canary_monitoring(StackCanary *canary, int protection_level);
void validate_canary(StackCanary *canary);
void perform_cleanup();
void handle_child_process(char *const argv[]);
void signal_handler(int sig);
void register_signal_handlers();
void rand_bytes(uint8_t *buf, size_t len);

// Volatile variable for signal handling
volatile sig_atomic_t child_exited = 0;

int main(int argc, char *argv[]) {
    // Validate command-line arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <application> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }
    // Check if the provided application path is accessible
    if (access(argv[1], F_OK) == -1) {
        perror("Error accessing application path");
        return EXIT_FAILURE;
    }

    // Initialize logger
    init_logger();
    log_message("Guardian Wrapper initiated.");

    // Seed random number generator
    srand(time(NULL));

    // Define and initialize a stack canary with high protection level
    StackCanary canary;
    setup_canary_monitoring(&canary, STACK_CANARY_HIGH);

    // Register signal handlers
    register_signal_handlers();

    // Fork a child process to execute the target application
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        handle_child_process(&argv[1]);
    } else if (pid > 0) {
        // Parent process
        int status;
        // Continuously validate the stack canary until child process exits
        while (!child_exited) {
            validate_canary(&canary);
            pause(); // Wait for signals
        }
        // Collect child's exit status
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            log_message("Application exited normally.");
        } else {
            log_message("Application terminated unexpectedly.");
        }
    } else {
        // Fork failed
        perror("Failed to fork");
        perform_cleanup();
        close_logger();
        return EXIT_FAILURE;
    }

    // Cleanup and exit
    perform_cleanup();
    close_logger();
    return EXIT_SUCCESS;
}

// Setup stack canary monitoring
void setup_canary_monitoring(StackCanary *canary, int protection_level) {
    // Generate a random value and salt
    uint64_t random_value = (uint64_t)rand();
    uint8_t salt[SALTSIZE];
    rand_bytes(salt, SALTSIZE);

    // Use BLAKE3 to hash the random value and salt
    blake3_hasher hasher_blake3;
    blake3_hasher_init(&hasher_blake3);
    blake3_hasher_update(&hasher_blake3, &random_value, sizeof(random_value));
    blake3_hasher_update(&hasher_blake3, salt, SALTSIZE);

    // Finalize the BLAKE3 hash output
    uint8_t hash_output_blake3[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher_blake3, hash_output_blake3, BLAKE3_OUT_LEN);

    // Use SHA-256 to hash the BLAKE3 hash output
    uint8_t hash_output_sha256[SHA256_DIGEST_LENGTH];
    sha256(hash_output_blake3, BLAKE3_OUT_LEN, hash_output_sha256);

    // Copy the hashed value to the canary value
    memcpy(&canary->value, hash_output_sha256, sizeof(canary->value));

    // Randomize the location of the canary in memory
    int offset = rand() % (sizeof(StackCanary) - sizeof(uint64_t));
    uint64_t *canary_location = (uint64_t *)((char *)canary + offset);

    // Set magic bytes for additional validation
    strncpy(canary->magic, STACK_CANARY_MAGIC, sizeof(canary->magic));

    // Store the canary value at the randomized location
    *canary_location = canary->value;

    // Increase protection level by XORing canary value with magic bytes
    if (protection_level == STACK_CANARY_HIGH) {
        canary->value ^= *((uint64_t *)canary->magic);
    }

    log_message("Stack canary monitoring setup initiated.");
}

// Validate stack canary
void validate_canary(StackCanary *canary) {
    // Retrieve the location of the canary
    uint64_t *canary_location = (uint64_t *)((char *)canary + (rand() % (sizeof(StackCanary) - sizeof(uint64_t))));

    // Check if the canary value matches the expected value
    if (*canary_location != canary->value) {
        log_message("Stack canary validation failed. Possible buffer overflow attempt detected.");
        // Perform appropriate action (e.g., terminate program, log incident)
        exit(EXIT_FAILURE);
    }
}

// Perform cleanup operations
void perform_cleanup() {
    log_message("Performing cleanup operations.");
}

// Handle execution of the target application
void handle_child_process(char *const argv[]) {
    if (execvp(argv[0], argv) == -1) {
        perror("Error launching application");
        exit(EXIT_FAILURE);
    }
}

// Signal handler for SIGCHLD
void signal_handler(int sig) {
    switch (sig) {
        case SIGCHLD:
            child_exited = 1;
            break;
        // Handle other signals as needed
        default:
            break;
    }
}

// Register signal handlers
void register_signal_handlers() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("Error registering signal handler");
        exit(EXIT_FAILURE);
    }
    // Register other signal handlers as needed
}

// Generate random bytes
void rand_bytes(uint8_t *buf, size_t len) {
    FILE *urand = fopen("/dev/urandom", "rb");
    if (!urand) {
        perror("Failed to open /dev/urandom");
        exit(EXIT_FAILURE);
    }
    if (fread(buf, 1, len, urand) != len) {
        perror("Failed to read random bytes");
        fclose(urand);
        exit(EXIT_FAILURE);
    }
    fclose(urand);
}
