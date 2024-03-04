# Guardian Wrapper Project

The Guardian Wrapper Project aims to enhance Linux application security through the use of eBPF for syscall monitoring, stack canary checks for buffer overflow protection, and secure logging mechanisms. It combines Rust and Go for system-level monitoring and management, leveraging the power of eBPF to provide real-time, low-overhead security measures.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building the Project](#building-the-project)
- [Usage](#usage)
- [Development](#development)
  - [eBPF Component](#ebpf-component)
  - [Go Orchestration Layer](#go-orchestration-layer)
  - [Rust Component](#rust-component)
- [Contributing](#contributing)
- [License](#license)

## Overview

Guardian Wrapper utilizes eBPF for monitoring system calls, Rust for system-level monitoring, and Go for orchestrating eBPF programs and handling secure logging. This blend of technologies allows for a comprehensive security posture that is both efficient and effective.

## Features

- **Real-time Syscall Monitoring:** Uses eBPF programs to monitor and log system calls, detecting potentially malicious activity.
- **Stack Canary Checks:** Implements stack canaries to protect against buffer overflow attacks.
- **Secure Logging:** Utilizes BLAKE3 hashing for secure and tamper-evident logging.
- **Dynamic Threat Response:** Provides mechanisms for dynamic response to detected threats, improving system resilience.
- **Cross-Language Integration:** Leverages the strengths of Rust and Go alongside eBPF for a powerful and flexible security solution.

## Installation

### Prerequisites

- Linux kernel 4.18 or newer with eBPF support.
- Go 1.14 or newer for the orchestration layer.
- Rust 1.41 or newer for system monitoring components.
- LLVM and Clang for compiling eBPF programs.
- libbpf for eBPF program loading and management.
- bpftool for generating eBPF skeletons.

### Building the Project

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/Aanthord/guardianwrap.git
    cd guardianwrapper
    ```

2. **Compile the eBPF Program:**
    - Use Clang to compile the eBPF program:
        ```bash
        clang -O2 -target bpf -c ebpf/exec_logger.bpf.c -o ebpf/exec_logger.bpf.o
        ```
    - Generate the eBPF skeleton with bpftool:
        ```bash
        bpftool gen skeleton ebpf/exec_logger.bpf.o > src/exec_logger.skel.h
        ```

3. **Build Rust and Go Components:**
    - Navigate to the Rust component directory and build:
        ```bash
        cd rust
        cargo build --release
        ```
    - Navigate to the Go component directory and build:
        ```bash
        cd ../go
        go build -o guardianwrap .
        ```

## Usage

Launch an application within Guardian Wrapper's monitored environment:
```bash
./guardianwrap <path_to_application>
```
## Development

### eBPF Component

The `exec_logger.bpf.c` program is responsible for monitoring system calls and emitting events to user space. It's compiled into eBPF bytecode and loaded into the Linux kernel, where it attaches to tracepoints or kprobes to monitor system behavior in real-time.

### Go Orchestration Layer

This layer manages eBPF programs and processes the events they emit. It's designed for logging activities and triggering dynamic responses based on specific system events. The Go layer utilizes channels and goroutines for efficient event processing and management, providing a robust foundation for the system's reactive capabilities.

### Rust Component

The Rust component enhances system monitoring capabilities by leveraging Rust's performance and safety features. It's used for tasks that require high-speed data processing or direct system interaction, complementing the eBPF and Go components to offer comprehensive monitoring and security features.

## Contributing

Contributions to Guardian Wrapper are welcome! If you're interested in helping to improve the project, please follow these steps:

1. Fork the repository on GitHub.
2. Create a new feature branch from the main branch.
3. Implement your feature or bug fix.
4. Commit your changes with a clear and descriptive message.
5. Push your branch and submit a pull request for review.

Your contributions are greatly appreciated and will help make Guardian Wrapper more robust and feature-rich.

## License

Guardian Wrapper is made available under the MIT License. This license allows you to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software and to permit persons to whom the software is furnished to do so, subject to the following conditions:

A copy of the MIT License should be included with the project. For more details, see the [LICENSE](LICENSE) file included with this repository.
