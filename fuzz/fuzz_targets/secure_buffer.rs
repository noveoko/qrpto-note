#![no_main]

use libfuzzer_sys::fuzz_target;
use your_crate::secure_buf::SecureBuffer;

fuzz_target!(|input: String| {
    let mut buf = SecureBuffer::new();

    for ch in input.chars() {
        buf.insert_char(ch);
    }

    for _ in 0..10 {
        buf.move_left();
        buf.move_right();
        buf.delete_before_cursor();
        buf.delete_at_cursor();
    }

    let _ = buf.as_str();
});
