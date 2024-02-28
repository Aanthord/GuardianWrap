#!/bin/bash

# Path to the GuardianWrap executable and test application
GUARDIAN_WRAP="./guardianwrap" # Assume this is the compiled binary of the C wrapper
TEST_APP="./test_app" # A simple application that triggers different syscalls
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

