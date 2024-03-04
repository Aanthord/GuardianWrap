#include "../src/include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Map definition for storing file operation events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128); // Adjust based on expected workload
} file_op_events SEC(".maps");

// Data structure for file operation events
struct file_op_event_t {
    __u32 pid; // Process ID
    char filename[256]; // Filename involved in the operation
    char operation[16]; // Type of operation, e.g., "open"
};

// Tracepoint program to intercept 'open' syscalls
SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct trace_event_raw_sys_enter *ctx) {
    struct file_op_event_t event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (__u32)(pid_tgid >> 32);

    // Safely read the filename argument from the syscall
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[0]);
    // Store the operation type in the event structure
    __builtin_memcpy(event.operation, "open", sizeof("open"));

    // Emit the event to user space via the perf event array
    bpf_perf_event_output(ctx, &file_op_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// License declaration for the eBPF program
char LICENSE[] SEC("license") = "GPL";

