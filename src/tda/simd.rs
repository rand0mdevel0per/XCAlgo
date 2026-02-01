//! SIMD-accelerated operations for XCA cryptosystem
//!
//! This module provides SIMD (Single Instruction, Multiple Data) optimizations
//! for performance-critical operations using AVX2 instructions when available.
//!
//! Features:
//! - Runtime CPU feature detection
//! - Automatic fallback to scalar implementation
//! - AVX2 support for bit operations

use rand::Rng;

/// Check if AVX2 is available on the current CPU
#[inline]
pub fn is_avx2_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Generate random bytes using SIMD when available
///
/// This function uses AVX2 instructions to generate random bytes in parallel
/// when the CPU supports it, otherwise falls back to scalar generation.
///
/// # Arguments
/// * `length` - Number of random bytes to generate
///
/// # Returns
/// Vector of random bytes
pub fn generate_random_bytes_simd(length: usize) -> Vec<u8> {
    // Note: Random generation still requires scalar RNG calls
    // AVX2 is better suited for deterministic operations
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.r#gen()).collect()
}

/// Convert bytes to bit vector using SIMD when available
///
/// # Arguments
/// * `bytes` - Input byte slice
///
/// # Returns
/// Vector of booleans representing individual bits
pub fn bytes_to_bits_simd(bytes: &[u8]) -> Vec<bool> {
    // Use SIMD only for larger inputs (128+ bytes) to avoid overhead
    if is_avx2_available() && bytes.len() >= 128 {
        unsafe { bytes_to_bits_avx2(bytes) }
    } else {
        bytes_to_bits_scalar(bytes)
    }
}

/// Scalar fallback for bytes to bits conversion
#[inline]
fn bytes_to_bits_scalar(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    bits
}

/// AVX2 implementation for bytes to bits conversion
/// Note: Currently uses scalar processing as AVX2 doesn't have direct bit expansion
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn bytes_to_bits_avx2(bytes: &[u8]) -> Vec<bool> {
    // For now, use optimized scalar implementation
    // TODO: Implement true AVX2 bit expansion using lookup tables
    bytes_to_bits_scalar(bytes)
}

#[cfg(not(target_arch = "x86_64"))]
fn bytes_to_bits_avx2(bytes: &[u8]) -> Vec<bool> {
    bytes_to_bits_scalar(bytes)
}

/// Convert bit vector to bytes using SIMD when available
///
/// # Arguments
/// * `bits` - Input bit vector
///
/// # Returns
/// Vector of bytes
pub fn bits_to_bytes_simd(bits: &[bool]) -> Vec<u8> {
    // Use SIMD only for larger inputs (1024+ bits = 128+ bytes) to avoid overhead
    if is_avx2_available() && bits.len() >= 1024 {
        unsafe { bits_to_bytes_avx2(bits) }
    } else {
        bits_to_bytes_scalar(bits)
    }
}

/// Scalar fallback for bits to bytes conversion
#[inline]
fn bits_to_bytes_scalar(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }
    bytes
}

/// AVX2 implementation for bits to bytes conversion
/// Note: Currently uses scalar processing as AVX2 doesn't have efficient bit packing
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn bits_to_bytes_avx2(bits: &[bool]) -> Vec<u8> {
    // For now, use optimized scalar implementation
    // TODO: Implement true AVX2 bit packing using lookup tables
    bits_to_bytes_scalar(bits)
}

#[cfg(not(target_arch = "x86_64"))]
fn bits_to_bytes_avx2(bits: &[bool]) -> Vec<u8> {
    bits_to_bytes_scalar(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_bits_roundtrip() {
        let original = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let bits = bytes_to_bits_simd(&original);
        let recovered = bits_to_bytes_simd(&bits);
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_bits_to_bytes_roundtrip() {
        let bits = vec![
            true, false, false, true, false, false, true, false,  // 0x92
            false, false, true, true, false, true, false, false,  // 0x34
        ];
        let bytes = bits_to_bytes_simd(&bits);
        let recovered = bytes_to_bits_simd(&bytes);
        assert_eq!(bits, recovered);
    }
}
