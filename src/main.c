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

// Define constants for stack canary protection levels
#define STACK_CANARY_LOW 0
#define STACK_CANARY_HIGH 1

// Constants for BLAKE3 hashing
#define SALTSIZE 16 // Size of the salt in bytes
#define NUM_ROUNDS 3 // Number of hashing rounds

// Constants for SHA-256 hashing
#define SHA256_DIGEST_LENGTH 32 // SHA-256 digest length in bytes

void setup_canary_monitoring(StackCanary *canary, int protection_level);
void validate_canary(StackCanary *canary);
void perform_cleanup();
void handle_child_process(char *const argv[]);
void signal_handler(int sig);
void register_signal_handlers();
void rand_bytes(uint8_t *buf, size_t len);

volatile sig_atomic_t child_exited = 0;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <application> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    init_logger();
    log_message(LOG_LEVEL_INFO, "Guardian Wrapper initiated.");

    // Seed random number generator
    srand(time(NULL));

    // Define and initialize a stack canary with high protection level
    StackCanary canary;
    setup_canary_monitoring(&canary, STACK_CANARY_HIGH);

    register_signal_handlers();

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        handle_child_process(&argv[1]);
    } else if (pid > 0) {
        // Parent process
        int status;
        while (!child_exited) {
            validate_canary(&canary); // Runtime canary validation
            pause(); // Wait for signals
        }
        waitpid(pid, &status, 0); // Collect child's exit status
        if (WIFEXITED(status)) {
            log_message(LOG_LEVEL_INFO, "Application exited normally.");
        } else {
            log_message(LOG_LEVEL_ERROR, "Application terminated unexpectedly.");
        }
    } else {
        // Fork failed
        perror("Failed to fork");
        perform_cleanup();
        close_logger();
        return EXIT_FAILURE;
    }

    perform_cleanup();
    close_logger();
    return EXIT_SUCCESS;
}

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

    log_message(LOG_LEVEL_INFO, "Stack canary monitoring setup initiated.");
}

void validate_canary(StackCanary *canary) {
    // Retrieve the location of the canary
    uint64_t *canary_location = (uint64_t *)((char *)canary + (rand() % (sizeof(StackCanary) - sizeof(uint64_t))));

    // Check if the canary value matches the expected value
    if (*canary_location != canary->value) {
        log_message(LOG_LEVEL_ERROR, "Stack canary validation failed. Possible buffer overflow attempt detected.");
        // Perform appropriate action (e.g., terminate program, log incident)
        exit(EXIT_FAILURE);
    }
}

void perform_cleanup() {
    log_message(LOG_LEVEL_INFO, "Performing cleanup operations.");
}

void handle_child_process(char *const argv[]) {
    if (execvp(argv[0], argv) == -1) {
        perror("Error launching application");
        exit(EXIT_FAILURE);
    }
}

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
