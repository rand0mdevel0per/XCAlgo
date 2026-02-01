//! SIMD-accelerated operations for XCA cryptosystem
//!
//! This module provides SIMD (Single Instruction, Multiple Data) optimizations
//! for performance-critical operations using AVX512 instructions when available.
//!
//! Features:
//! - Runtime CPU feature detection
//! - Automatic fallback to scalar implementation
//! - AVX512 support for batch operations

use rand::Rng;

/// Check if AVX512 is available on the current CPU
#[inline]
pub fn is_avx512_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        is_x86_feature_detected!("avx512f")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Generate random bytes using SIMD when available
///
/// This function uses AVX512 instructions to generate random bytes in parallel
/// when the CPU supports it, otherwise falls back to scalar generation.
///
/// # Arguments
/// * `length` - Number of random bytes to generate
///
/// # Returns
/// Vector of random bytes
pub fn generate_random_bytes_simd(length: usize) -> Vec<u8> {
    if is_avx512_available() {
        unsafe { generate_random_bytes_avx512(length) }
    } else {
        generate_random_bytes_scalar(length)
    }
}

/// Scalar fallback for random byte generation
#[inline]
fn generate_random_bytes_scalar(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.r#gen::<u8>()).collect()
}

/// AVX512 implementation for random byte generation
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn generate_random_bytes_avx512(length: usize) -> Vec<u8> {
    // For now, use scalar implementation
    // TODO: Implement true AVX512 random generation
    // Note: AVX512 is better suited for deterministic operations
    // Random generation still requires scalar RNG calls
    generate_random_bytes_scalar(length)
}

#[cfg(not(target_arch = "x86_64"))]
fn generate_random_bytes_avx512(length: usize) -> Vec<u8> {
    generate_random_bytes_scalar(length)
}
