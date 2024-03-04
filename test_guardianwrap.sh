#!/bin/bash

# Define paths to the essential components of GuardianWrap
GUARDIAN_WRAP="./guardianwrap" # Path to the Go orchestration layer binary
TEST_APP="./test_app" # Path to a test application designed to trigger syscalls of interest
LOG_FILE="/var/log/guardianwrap.log" # Log file where syscall events are recorded
EVENTS_FILE="/var/log/guardianwrap_events.json" # File for eBPF events, assuming JSON format for simplicity

# Clean up previous log and events files
rm -f "$LOG_FILE" "$EVENTS_FILE"

# Start the GuardianWrap around the test application
$GUARDIAN_WRAP $TEST_APP &

# Capture the PID of the GuardianWrap process
GW_PID=$!

# Wait for the test application to complete its execution
wait $GW_PID

# Check the events file for specific syscall entries, assuming JSON format
if grep -q "execve" "$EVENTS_FILE"; then
    echo "Test Passed: execve syscalls logged."
else
    echo "Test Failed: execve syscalls not found in events."
    exit 1
fi

# This script now focuses on checking the eBPF events file for syscalls,
# as it represents the primary mechanism for monitoring with GuardianWrap.
# Adjustments may be necessary based on the actual format and structure of your events file.

exit 0

