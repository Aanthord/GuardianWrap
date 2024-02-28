# Guardian Wrapper Project Overview

The Guardian Wrapper Project enhances Linux application security through advanced monitoring techniques. It includes stack canary monitoring to detect buffer overflows, secure logging with BLAKE3 hashing for log integrity, and dynamic response mechanisms for real-time security incident handling.

## Project Objectives

- **Enhance Application Security:** Monitor applications in real-time for security breaches and respond dynamically to threats.
- **Secure Logging:** Implement secure logging mechanisms using BLAKE3 hashing to ensure log integrity.
- **Automated Response:** Develop automated response strategies for various security incidents, enhancing application resilience.

## Project Components and Progress

1. **Stack Canary Monitoring**
   - **Objective:** Detect memory corruption incidents like buffer overflows.
   - **Progress:** 70% complete. Basic structure implemented, pending final testing and integration.

2. **Secure Logging System**
   - **Objective:** Securely log application activities, incorporating BLAKE3 hashing.
   - **Progress:** 80% complete. Implementation in place, pending optimizations and enhancements.

3. **Dynamic Response Mechanisms**
   - **Objective:** Automate responses to monitoring alerts for robust incident handling.
   - **Progress:** 75% complete. Actions defined and partially implemented, awaiting full integration.

4. **Utility Functions**
   - **Objective:** Provide essential utility functions for the project, such as signal handling.
   - **Progress:** 90% complete. Core utilities implemented, with room for additional features.

5. **Integration and System Testing**
   - **Objective:** Ensure cohesive operation of all components under various scenarios.
   - **Progress:** 50% complete. Initial integration done, comprehensive testing required.

6. **Documentation and User Guides**
   - **Objective:** Offer detailed setup, configuration, and operational guidance.
   - **Progress:** 40% complete. Basic documentation available, extensive guides needed.

## Documentation and User Guides

This section offers detailed setup, configuration, and operational guidance to effectively utilize the Guardian Wrapper Project. It encompasses explanations of individual components, including the Go orchestration layer, which plays a crucial role in monitoring, logging, and dynamically responding to system calls.

### Go Orchestration Layer Detailed Guide

The Go orchestration layer serves as the central component for managing eBPF program interactions, WebSocket communications for real-time event streaming, and signal handling for graceful shutdowns. Below is an in-depth overview of its implementation:

- **Import Dependencies**
  - Standard Libraries: Utilized for basic I/O, logging, HTTP server management, and OS-level operations.
  - Third-party Libraries: mux for HTTP routing, websocket for WebSocket management, and bcc for eBPF interactions.
- **eBPF Program Loading and Attachment**
  - Function: loadEBPFProgram reads the eBPF program source, compiles it, and attaches it to the execve system call tracepoint.
  - Error Handling: Critical errors during eBPF operations result in immediate termination to prevent insecure states.
- **WebSocket Event Streaming Handler**
  - Function: eventWebSocket upgrades HTTP connections to WebSocket and streams eBPF event data to connected clients.
  - Concurrency: Utilizes goroutines to handle multiple WebSocket connections and event streams concurrently.
- **Alert Handling Over WebSocket**
  - Function: alertWebSocket listens on a channel for alerts and forwards them over WebSocket connections to clients, enabling real-time security notifications.
- **Signal Handling for Graceful Shutdown**
  - Implements signal listening for os.Interrupt and syscall.SIGTERM to gracefully terminate the server and cleanup resources.

- **Main Function Workflow**
  - **eBPF Program Initialization:** Loads and attaches the eBPF program at startup.
  - **HTTP Server Setup:** Configures routes and starts the HTTP server for client interactions.
  - **Graceful Shutdown Handling:** Waits for termination signals to cleanly exit the application.

### Getting Started

#### Prerequisites
- Linux operating system
- GCC compiler
- BLAKE3 library

#### Installation
```bash
# Clone the repository
git clone <repository_url>

# Compile the project
make all

# Install the application (optional)
sudo make install
Test Scenario: Monitoring and Reacting to execve Syscalls
Objective: Verify that GuardianWrap can monitor execve syscalls, log them immutably, add stack canaries, and dump the stack if specified syscalls are triggered.

Setup Environment

Compile eBPF Program: Follow the compilation steps outlined previously to compile the exec_logger.c eBPF program.
Prepare GuardianWrap Components: Ensure the C wrapper (main.c), Rust component (main.rs), and Go orchestration layer (main.go) are compiled and ready for execution. Make sure the eBPF bytecode is accessible to the GuardianWrap.
Write Test Script

Develop a test script that automates the execution of a test application under the GuardianWrap's supervision.


#!/bin/bash

# Path to the GuardianWrap executable and test application
GUARDIAN_WRAP="./guardianwrap"
TEST_APP="./test_app"
LOG_FILE="/var/log/guardianwrap.log"
STACK_DUMP_FILE="/var/log/guardianwrap_stack_dump.txt"

# Clean up log files
rm -f $LOG_FILE
rm -f $STACK_DUMP_FILE

# Start GuardianWrap with the test application
$GUARDIAN_WRAP $TEST_APP &

# Wait for the test application to complete
wait

# Check log file for execve syscall entries
if grep -q "execve" $LOG_FILE; then
    echo "Test Passed: execve syscalls logged."
else
    echo "Test Failed: execve syscalls not found in log."
    exit 1
fi

# Optionally, check for stack dumps if the test application triggers a monitored condition
if [ -f "$STACK_DUMP_FILE" ]; then
    echo "Stack dump created for monitored syscalls."
else
    echo "No stack dump file found; either not triggered or test failed."
fi

exit 0
```

Execute the Test
Run the test script and observe the output. Ensure your test application (test_app) performs actions that trigger execve syscalls, and optionally, actions that should trigger stack dumps based on your security policies.

```

chmod +x test_guardianwrap.sh
./test_guardianwrap.sh

```

Evaluate Results
Success Criteria: The test is successful if the execve syscalls are logged as expected and stack dumps are created for specified conditions.
Failure Analysis: If syscalls are not logged or stack dumps are not generated as expected, investigate the integration points between the eBPF program, C wrapper, Rust component, and Go orchestration layer. Ensure the eBPF program is correctly attached and monitoring syscalls, and that GuardianWrap components are correctly handling and logging events.
This test validates the integration and functionality of the GuardianWrap project components in a cohesive workflow, ensuring the system can monitor, log, and react to system calls in a sandboxed environment.
