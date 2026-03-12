#!/bin/bash
set -e

echo "🎯 Fixing the final lints..."

# 1 & 2. src/secure_buf.rs: Pass by value and Pointer cast
if [ -f "src/secure_buf.rs" ]; then
    echo "Updating src/secure_buf.rs..."
    # Change &self to self for the 2-byte struct
    sed -i 's/fully_protected(&self)/fully_protected(self)/g' src/secure_buf.rs
    # Use as_mut_ptr() for the raw pointer cast
    sed -i 's/storage.as_ptr() as \*mut libc::c_void/storage.as_mut_ptr() as *mut libc::c_void/g' src/secure_buf.rs
fi

# 3 & 4. src/storage.rs: usize to u32 truncation
if [ -f "src/storage.rs" ]; then
    echo "Updating src/storage.rs truncation errors..."
    # Using .expect() because we want to avoid naked .unwrap() in this project
    sed -i 's/(self.lines.len() as u32)/u32::try_from(self.lines.len()).expect("Line count overflow")/g' src/storage.rs
    sed -i 's/(line.ciphertext.len() as u32)/u32::try_from(line.ciphertext.len()).expect("Ciphertext overflow")/g' src/storage.rs
fi

echo "✅ Script-based fixes applied."
echo "⚠️  One manual fix remaining: src/ui.rs (the match block)."
