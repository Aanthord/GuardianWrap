#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/perf_event.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

// Define a custom stack canary structure
typedef struct {
    uint64_t value; // Value of the canary
    char magic[8]; // Magic bytes for extra validation
} StackCanary;

#define STACK_CANARY_MAGIC "CANARY42" // Define magic bytes for the canary
#define STACK_CANARY_LOW 0 // Define constant for low stack canary protection level
#define STACK_CANARY_HIGH 1 // Define constant for high stack canary protection level

#define SALTSIZE 16 // Define salt size for generating canary
#define SHA256_DIGEST_LENGTH 32 // Define length of SHA-256 hash

// Function prototypes
void setup_canary_monitoring(StackCanary *canary, int protection_level);
void validate_canary(StackCanary *canary);
void perform_cleanup();
void handle_child_process(char *const argv[]);
void signal_handler(int sig);
void register_signal_handlers();
void rand_bytes(uint8_t *buf, size_t len);
int load_bpf_program();
int setup_perf_events();
int setup_network_events();
void monitor_perf_events(int fd);
void monitor_network_events(int sock_fd);

// Volatile variable for signal handling
volatile sig_atomic_t child_exited = 0;

// Main function
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

    // Initialize SELinux context
    security_context_t app_context;
    get_default_context(argv[1], &app_context);
    setexeccon(app_context);

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

    // Load and attach eBPF program
    int prog_fd = load_bpf_program();
    if (prog_fd < 0) {
        log_message("Failed to load eBPF program. Exiting.");
        return EXIT_FAILURE;
    }

    // Setup and monitor performance events
    int perf_fd = setup_perf_events();
    if (perf_fd < 0) {
        log_message("Failed to setup performance events. Exiting.");
        return EXIT_FAILURE;
    }

    // Setup and monitor network events
    int sock_fd = setup_network_events();
    if (sock_fd < 0) {
        log_message("Failed to setup network events. Exiting.");
        return EXIT_FAILURE;
    }

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
            monitor_perf_events(perf_fd);
            monitor_network_events(sock_fd);
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

int load_bpf_program() {
    int prog_fd;
    struct bpf_insn prog[] = {
        // eBPF program code to monitor system calls
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),            // Store syscall number in register R6
        BPF_LD_ABS(BPF_B, BPF_PSEUDO_CALL, 0),         // Load syscall number from stack
        BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 0xff),       // Mask syscall number with 0xff
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, __NR_write, 2), // Jump to ALLOW block if syscall is write
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, __NR_read, 2),  // Jump to ALLOW block if syscall is read
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, __NR_open, 2),  // Jump to ALLOW block if syscall is open
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, __NR_close, 2), // Jump to ALLOW block if syscall is close
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, __NR_exit, 2),  // Jump to ALLOW block if syscall is exit
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_6, __NR_exit_group, 2), // Jump to ALLOW block if syscall is exit_group
        BPF_MOV64_IMM(BPF_REG_0, SECCOMP_RET_ALLOW),    // Return ALLOW if syscall is whitelisted
        BPF_EXIT_INSN(),                                // Exit syscall
        BPF_MOV64_IMM(BPF_REG_0, SECCOMP_RET_KILL),     // Return KILL if syscall is not whitelisted
        BPF_EXIT_INSN(),                                // Exit syscall
    };
    struct bpf_load_program_attr attr = {
        .insns = (unsigned long)prog,
        .insn_cnt = sizeof(prog) / sizeof(struct bpf_insn),
        .license = "GPL"
    };

    // Load eBPF program
    prog_fd = bpf_load_program(&attr);
    if (prog_fd < 0) {
        perror("Failed to load eBPF program");
        return -1;
    }

    // Attach eBPF program to suitable hook
    if (bpf_attach_program(prog_fd, BPF_PROG_TYPE_SOCKET_FILTER) < 0) {
        perror("Failed to attach eBPF program");
        close(prog_fd);
        return -1;
    }

    return prog_fd;
}

// Setup and monitor performance events
int setup_perf_events() {
    int fd;
    struct perf_event_attr attr = {};
    // Configure perf event attributes
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.size = sizeof(attr);
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1000000; // Sample every 1 second
    // Create perf event
    fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
    if (fd == -1) {
        perror("Failed to create perf event");
        return -1;
    }
    return fd;
}

// Setup and monitor network events
int setup_network_events() {
    int sock_fd;
    // Create a raw socket for monitoring network events
    sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_fd < 0) {
        perror("Failed to create socket");
        return -1;
    }
    return sock_fd;
}

// Monitor performance events
void monitor_perf_events(int fd) {
    uint64_t value;
    // Read perf event value
    read(fd, &value, sizeof(value));
    // Log the value or perform desired actions
}

// Monitor network events
void monitor_network_events(int sock_fd) {
    // Placeholder code for monitoring network events
    // Add your custom logic here
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

// Setup Seccomp for syscall filtering
void setup_seccomp() {
    struct sock_filter filter[] = {
        /* Validate architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        /* Load syscall number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

        /* List allowed syscalls */
        // Add your syscall rules here

        /* Deny other syscalls */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl");
        exit(EXIT_FAILURE);
    }
}
