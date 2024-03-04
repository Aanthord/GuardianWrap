GuardianWrap
Overview
GuardianWrap is a security-oriented application designed to enhance the protection of other applications by implementing various security mechanisms. It includes stack canary generation for buffer overflow protection, logging and monitoring capabilities, and an eBPF (extended Berkeley Packet Filter) component for monitoring file operation events.

Components
main.c
The core component of GuardianWrap, responsible for initializing the application, managing stack canaries, and handling child processes. It includes functionality for dynamic stack canary generation, continuous monitoring, and automatic rotation, among others.
dumper.c
Utilizes backtrace and backtrace_symbols for collecting and dumping stack traces to a file, aiding in debugging and post-mortem analysis.
immutable_logger.c
Appends data to an immutable log file, ensuring data integrity and supporting non-repudiation.
logger.c
A logging utility that timestamps and hashes log messages using BLAKE3, providing a secure logging mechanism.
exec_logger.bpf.c
An eBPF program that hooks into the sys_enter_open tracepoint to log file operation events, particularly open syscalls. This component enhances visibility into file access patterns and potential security breaches.
include/
A directory containing header files for the aforementioned components, ensuring modularity and ease of maintenance.
monitor.c
Monitors the application for critical security breaches, buffer overflows, and suspicious activities, and takes appropriate actions based on the type of alert detected.
utils.c
Provides utility functions, including converting bytes to hexadecimal strings and registering signal handlers for graceful shutdown and other signal-based controls.
Features
Stack Canary Protection: Dynamically generates and manages stack canaries to prevent buffer overflow attacks.
eBPF Monitoring: Utilizes eBPF to monitor and log file operation events, enhancing security observability.
Immutable Logging: Ensures that log data cannot be tampered with once written.
Security Alerts and Monitoring: Detects and responds to security breaches, buffer overflows, and other threats.
Modular Design: Organized into multiple components for ease of understanding and maintenance.
Usage
To deploy GuardianWrap:

Compile the application using make.
Run the compiled binary, specifying the target application and any necessary arguments.
Monitor the logs and alerts for any security incidents or operational issues.
Contributing
Contributions are welcome! Please submit pull requests or open issues for bug fixes, feature requests, or other enhancements.

License
GuardianWrap is distributed under the MIT License. See the LICENSE file for more details.
