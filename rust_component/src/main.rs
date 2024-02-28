extern crate bcc;
use bcc::perf_event::{Event, PerfMapBuilder};
use bcc::BccError;
use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// Struct representing the data structure of file operation events from eBPF.
#[repr(C)]
struct FileOpEvent {
    pid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
    operation: [u8; 10], // Match the size with the eBPF definition
}

static RUNNING: AtomicBool = AtomicBool::new(true);

fn main() -> Result<(), BccError> {
    // Read eBPF program code from file
    let code = include_str!("exec_logger.c");

    // Load eBPF program
    let mut module = bcc::BPF::new(&code)?;

    // Initialize tracepoint for execve events
    bcc::Tracepoint::new(&mut module, "syscalls", "sys_enter_execve", "on_execve_enter")?.init()?;

    // Initialize perf map for file operation events
    let table = module.table("file_op_events")?;
    let perf_map = PerfMapBuilder::new(table, handle_event).build()?;

    // Print startup message
    println!("Monitoring file operations. Press Ctrl+C to stop.");

    // Set up Ctrl+C handler for graceful exit
    let running = Arc::new(RUNNING);
    ctrlc::set_handler({
        let running = running.clone();
        move || {
            running.store(false, Ordering::SeqCst);
        }
    })?;

    // Poll for file operation events
    while RUNNING.load(Ordering::SeqCst) {
        perf_map.poll(200);
    }

    // Print exit message
    println!("Exiting...");
    Ok(())
}

// Callback function to handle file operation events
fn handle_event(event: Event) {
    if let Ok(data) = event.data() {
        if event.name == "file_op_events" {
            if let Ok(file_event) = parse_file_op_event(&data) {
                // Print file operation event details
                println!("File Operation Event - PID: {}, Comm: {:?}, Operation: {:?}, Filename: {:?}",
                         file_event.pid,
                         String::from_utf8_lossy(&file_event.comm).trim_end_matches('\u{0}'),
                         String::from_utf8_lossy(&file_event.operation).trim_end_matches('\u{0}'),
                         String::from_utf8_lossy(&file_event.filename).trim_end_matches('\u{0}'));
            }
        }
    }
}

// Parse file operation event data into FileOpEvent struct
fn parse_file_op_event(data: &[u8]) -> Result<FileOpEvent, &'static str> {
    if data.len() != std::mem::size_of::<FileOpEvent>() {
        return Err("Incorrect data size for file operation event");
    }
    let file_op_event: FileOpEvent = unsafe { std::ptr::read(data.as_ptr() as *const _) };
    Ok(file_op_event)
}
