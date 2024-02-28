main.c
Overview
main.c is the main source code file for the Guardian Wrapper application. This program serves as a protective layer around other applications, enhancing their security by implementing stack canaries to mitigate buffer overflow attacks.

Purpose
The primary purpose of main.c is to create and manage a stack canary, a security mechanism designed to detect and prevent buffer overflow vulnerabilities. By incorporating stack canaries into the program's execution flow, Guardian Wrapper aims to fortify the security of the applications it wraps, reducing the risk of exploitation by malicious actors.

Features
Stack Canary Implementation
Dynamic Generation: The program dynamically generates a stack canary value at runtime using cryptographic hashing techniques to ensure unpredictability and resilience against attacks.
Multiple Hash Functions: Stack canaries are created by hashing random values with multiple hash functions, including BLAKE3 and SHA-256, to enhance diversity and complexity.
Randomization: The location of the stack canary within memory is randomized to prevent predictable exploitation by attackers.
Magic Bytes: Magic bytes are incorporated into the canary value for additional validation and protection against tampering.
Runtime Validation
Continuous Monitoring: The program continuously monitors the integrity of the stack canary during program execution to detect any attempts at buffer overflow or stack manipulation.
Automatic Rotation: Stack canary values are automatically rotated at regular intervals to minimize the risk associated with a static canary value.
Signal Handling: Signal handlers are implemented to respond to critical events, such as child process termination, ensuring proper cleanup and termination of the program.
Security Measures
Memory Protection: Memory protection techniques are applied to safeguard the stack canary value from tampering or overwriting by malicious actors.
Versioning Support: Versioning support is included to facilitate future upgrades or changes to the stack canary generation algorithm, ensuring backward compatibility and flexibility.
Logging and Monitoring
Logging: The program logs critical events and actions to provide visibility into its execution flow and facilitate troubleshooting and incident response.
Monitoring: Monitoring capabilities are integrated to track the usage and behavior of the stack canary, enabling real-time detection of suspicious activities or anomalies.
Usage
To use main.c, follow these steps:

Compile the program using a suitable compiler, such as GCC or Clang.
Execute the compiled binary, providing the path to the target application as a command-line argument.
Monitor the program's output for logging messages and status updates.
Contributing
Contributions to main.c are welcome! If you have suggestions for improvements, bug fixes, or new features, please submit a pull request or open an issue on the project's GitHub repository.

License
This program is distributed under the MIT License. See the LICENSE file for details.
