#include "logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

void setup_canary_monitoring();
void perform_cleanup();
void handle_child_process(char *const argv[]);
void signal_handler(int sig);
void register_signal_handlers();

volatile sig_atomic_t child_exited = 0;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <application> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    init_logger();
    log_message("Guardian Wrapper initiated.");

    setup_canary_monitoring();
    register_signal_handlers();

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        handle_child_process(&argv[1]);
    } else if (pid > 0) {
        // Parent process
        int status;
        while (!child_exited) {
            pause(); // Wait for signals
        }
        waitpid(pid, &status, 0); // Collect child's exit status
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

    perform_cleanup();
    close_logger();
    return EXIT_SUCCESS;
}

void setup_canary_monitoring() {
    log_message("Stack canary monitoring setup initiated.");
}

void perform_cleanup() {
    log_message("Performing cleanup operations.");
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

