extern crate bcc;
use bcc::perf_event::{Event, PerfMapBuilder};
use bcc::BccError;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// Structs representing the data structure of events we expect from eBPF.
#[repr(C)]
struct ExecveEvent {
    pid: u32,
    filename: [u8; 256], // Adjust size based on eBPF program
    argv: [u8; 256],     // Adjust size as needed
}

#[repr(C)]
struct FileOpEvent {
    pid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
    operation: u32, // Could be an enum or similar representation
}

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<(), BccError> {
    let code = include_str!("exec_logger.c");
    let mut module = bcc::BPF::new(code)?;

    bcc::Tracepoint::new(&mut module, "syscalls", "sys_enter_execve", "on_execve_enter")?.init()?;

    let table = module.table("execve_events")?;
    let perf_map = PerfMapBuilder::new(table, handle_event).build()?;

    println!("Listening for events. Press Ctrl+C to stop.");

    let running = Arc::new(RUNNING);
    ctrlc::set_handler(move || {
        running.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        perf_map.poll(200);
    }

    println!("Exiting...");
    Ok(())
}

fn handle_event(event: Event) {
    if let Ok(data) = event.data() {
        if event.name == "execve_events" {
            if let Ok(exec_event) = parse_execve_event(&data) {
                println!("Execve Event - PID: {}, Filename: {}, Args: {}",
                         exec_event.pid,
                         String::from_utf8_lossy(&exec_event.filename),
                         String::from_utf8_lossy(&exec_event.argv));
            }
        } else if event.name == "file_op_events" {
            if let Ok(file_event) = parse_file_op_event(&data) {
                println!("File Operation Event - PID: {}, Comm: {}, Operation: {}, Filename: {}",
                         file_event.pid,
                         String::from_utf8_lossy(&file_event.comm),
                         file_event.operation, // This would be more descriptive with an enum
                         String::from_utf8_lossy(&file_event.filename));
            }
        }
    }
}

fn parse_execve_event(data: &[u8]) -> Result<ExecveEvent, &'static str> {
    if data.len() != std::mem::size_of::<ExecveEvent>() {
        return Err("Incorrect data size for execve event");
    }
    let execve_event: ExecveEvent = unsafe { std::ptr::read(data.as_ptr() as *const _) };
    Ok(execve_event)
}

fn parse_file_op_event(data: &[u8]) -> Result<FileOpEvent, &'static str> {
    if data.len() != std::mem::size_of::<FileOpEvent>() {
        return Err("Incorrect data size for file operation event");
    }
    let file_op_event: FileOpEvent = unsafe { std::ptr::read(data.as_ptr() as *const _) };
    Ok(file_op_event)
}

