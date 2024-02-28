// handle_event_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    
    #[test]
    fn test_handle_event_valid() {
        // Test handling valid file operation event
        let mut data: Vec<u8> = vec![0; std::mem::size_of::<FileOpEvent>()];
        let file_event = FileOpEvent {
            pid: 123,
            comm: CString::new("test").unwrap().into_bytes_with_nul(),
            filename: CString::new("testfile.txt").unwrap().into_bytes_with_nul(),
            operation: CString::new("open").unwrap().into_bytes_with_nul(),
        };
        unsafe {
            std::ptr::copy(&file_event as *const _ as *const u8, data.as_mut_ptr(), data.len());
        }
        handle_event(Event { name: "file_op_events".to_string(), data: data });
        // Add assertions to verify the output (e.g., printed message)
    }
}

