# Guardian Wrapper Project

The Guardian Wrapper Project enhances Linux application security through advanced monitoring techniques. It includes stack canary monitoring to detect buffer overflows, secure logging with BLAKE3 hashing for log integrity, and dynamic response mechanisms for real-time security incident handling.

## Table of Contents
- [Overview](#overview)
- [Project Objectives](#project-objectives)
- [Project Components and Progress](#project-components-and-progress)
  - [Stack Canary Monitoring](#stack-canary-monitoring)
  - [Secure Logging System](#secure-logging-system)
  - [Dynamic Response Mechanisms](#dynamic-response-mechanisms)
  - [Utility Functions](#utility-functions)
  - [Integration and System Testing](#integration-and-system-testing)
- [Documentation and User Guides](#documentation-and-user-guides)
  - [Go Orchestration Layer Detailed Guide](#go-orchestration-layer-detailed-guide)
  - [Rust Integration for System Monitoring](#rust-integration-for-system-monitoring)
  - [eBPF Exec Logger Documentation](#ebpf-exec-logger-documentation)
- [Getting Started](#getting-started)
- [Test Scenario: Monitoring and Reacting to execve Syscalls](#test-scenario-monitoring-and-reacting-to-execve-syscalls)

## Overview

The Guardian Wrapper Project enhances Linux application security through advanced monitoring techniques. It includes stack canary monitoring to detect buffer overflows, secure logging with BLAKE3 hashing for log integrity, and dynamic response mechanisms for real-time security incident handling.

## Project Objectives

- **Enhance Application Security:** Monitor applications in real-time for security breaches and respond dynamically to threats.
- **Secure Logging:** Implement secure logging mechanisms using BLAKE3 hashing to ensure log integrity.
- **Automated Response:** Develop automated response strategies for various security incidents, enhancing application resilience.

## Project Components and Progress

### Stack Canary Monitoring

- **Objective:** Detect memory corruption incidents like buffer overflows.
- **Progress:** 70% complete. Basic structure implemented, pending final testing and integration.

### Secure Logging System

- **Objective:** Securely log application activities, incorporating BLAKE3 hashing.
- **Progress:** 80% complete. Implementation in place, pending optimizations and enhancements.

### Dynamic Response Mechanisms

- **Objective:** Automate responses to monitoring alerts for robust incident handling.
- **Progress:** 75% complete. Actions defined and partially implemented, awaiting full integration.

### Utility Functions

- **Objective:** Provide essential utility functions for the project, such as signal handling.
- **Progress:** 90% complete. Core utilities implemented, with room for additional features.

### Integration and System Testing

- **Objective:** Ensure cohesive operation of all components under various scenarios.
- **Progress:** 50% complete. Initial integration done, comprehensive testing required.

## Documentation and User Guides

This section offers detailed setup, configuration, and operational guidance to effectively utilize the Guardian Wrapper Project. It encompasses explanations of individual components, including the Go orchestration layer, Rust integration for system monitoring, and the eBPF exec logger.

### Go Orchestration Layer Detailed Guide

The Go orchestration layer serves as the central component for managing eBPF program interactions, WebSocket communications for real-time event streaming, and signal handling for graceful shutdowns. Below is an in-depth overview of its implementation.

### Rust Integration for System Monitoring

The `main.rs` file in the GuardianWrap project plays a crucial role in monitoring system events, particularly focusing on `execve` and file operation events, through the integration of Rust with eBPF. This section provides a comprehensive look at its implementation and functionality.

### eBPF Exec Logger Documentation

This documentation outlines the `exec_logger.c` script, part of the GuardianWrap project, designed to log exec operations performed by processes on a Linux system using eBPF (Extended Berkeley Packet Filter).

## Getting Started

### Prerequisites

- Linux operating system
- GCC compiler
- BLAKE3 library

### Installation

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
bash
Copy code
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
Execute the Test
Run the test script and observe the output. Ensure your test application (test_app) performs actions that trigger execve syscalls, and optionally, actions that should trigger stack dumps based on your security policies.
bash
Copy code
chmod +x test_guardianwrap.sh
./test_guardianwrap.sh
Evaluate Results
Success Criteria: The test is successful if the execve syscalls are logged as expected and stack dumps are created for specified conditions.
Failure Analysis: If syscalls are not logged or stack dumps are not generated as expected, investigate the integration points between the eBPF program, C wrapper, Rust component, and Go orchestration layer. Ensure the eBPF program is correctly attached and monitoring syscalls, and that GuardianWrap components are correctly handling and logging events.
This test validates the integration and functionality of the GuardianWrap project components in a cohesive workflow, ensuring the system can monitor, log, and react to system calls in a sandboxed environment.
