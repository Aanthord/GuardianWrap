#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct file_op_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char operation[10]; // "open" or "unlink"
};

BPF_PERF_OUTPUT(file_op_events);

// Tracepoint for open
TRACEPOINT_PROBE(syscalls, sys_enter_open) {
    struct file_op_event_t data = {};
    const char __user *filename;
    bpf_probe_read(&filename, sizeof(filename), &args->filename);
    bpf_probe_read_str(&data.filename, sizeof(data.filename), filename);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_str(&data.operation, sizeof(data.operation), "open");
    
    file_op_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// Tracepoint for unlink
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    struct file_op_event_t data = {};
    const char __user *pathname;
    bpf_probe_read(&pathname, sizeof(pathname), &args->pathname);
    bpf_probe_read_str(&data.filename, sizeof(data.filename), pathname);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_str(&data.operation, sizeof(data.operation), "unlink");
    
    file_op_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

