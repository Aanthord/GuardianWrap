// file_op_event_test.rs
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_file_op_event_valid() {
        // Test parsing valid file operation event data
        let data: [u8; std::mem::size_of::<FileOpEvent>()] = [0; std::mem::size_of::<FileOpEvent>()];
        let result = parse_file_op_event(&data);
        assert!(result.is_ok(), "Expected successful parsing");
        let file_op_event = result.unwrap();
        // Add assertions to validate the parsed FileOpEvent struct
    }
    
    #[test]
    fn test_parse_file_op_event_invalid() {
        // Test parsing invalid file operation event data
        let data: [u8; 10] = [0; 10]; // Invalid data size
        let result = parse_file_op_event(&data);
        assert!(result.is_err(), "Expected parsing error for invalid data size");
    }
}

