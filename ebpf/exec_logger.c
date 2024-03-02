#include <bpf/vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>



// Define a map for storing file operation events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} file_op_events SEC(".maps");

// Struct for file operation events
struct file_op_event_t {
    __u32 pid;
    char filename[256];
    char operation[16];
};

// Tracepoint program for 'open' syscall
SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct trace_event_raw_sys_enter *ctx) {
    struct file_op_event_t event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = (__u32)(pid_tgid >> 32);

    // Use BPF helper to get the filename argument
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[0]);
    __builtin_memcpy(event.operation, "open", sizeof("open"));

    // Emit the event to user space
    bpf_perf_event_output(ctx, &file_op_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

