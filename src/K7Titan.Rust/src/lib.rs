mod entropy;
mod hash;
mod scoring;

use std::slice;

/// Compute the SHA-256 of `buf` and write a NUL-terminated lowercase hex string
/// into `out_hex`. Returns 0 on success, negative on error.
#[no_mangle]
pub extern "C" fn k7_rs_sha256(buf: *const u8, len: usize, out_hex: *mut u8, out_len: usize) -> i32 {
    if buf.is_null() || out_hex.is_null() {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(buf, len) };
    let digest = hash::sha256_hex(slice);
    let bytes = digest.as_bytes();
    if bytes.len() >= out_len {
        return -2;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_hex, bytes.len());
        *out_hex.add(bytes.len()) = 0;
    }
    0
}

/// Shannon entropy (bits per byte, 0.0..=8.0) of the buffer.
#[no_mangle]
pub extern "C" fn k7_rs_entropy(buf: *const u8, len: usize) -> f64 {
    if buf.is_null() || len == 0 {
        return 0.0;
    }
    let slice = unsafe { slice::from_raw_parts(buf, len) };
    entropy::shannon_entropy(slice)
}

/// CRC-32 (IEEE) of the buffer.
#[no_mangle]
pub extern "C" fn k7_rs_crc32(buf: *const u8, len: usize) -> u32 {
    if buf.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { slice::from_raw_parts(buf, len) };
    scoring::crc32(slice)
}

/// Heuristic risk score in the range 0.0..=1.0.
#[no_mangle]
pub extern "C" fn k7_rs_score(buf: *const u8, len: usize) -> f32 {
    if buf.is_null() || len == 0 {
        return 0.0;
    }
    let slice = unsafe { slice::from_raw_parts(buf, len) };
    scoring::heuristic_score(slice)
}
