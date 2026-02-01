/// Padding module for IND-CPA security in XCA
///
/// The problem: XCA encodes each byte independently as path endpoints.
/// Without proper randomization, the same plaintext produces the same
/// path encodings (except for a nonce at the beginning).
///
/// Solution: Insert random padding chunks at random positions throughout
/// the message, and record their positions/lengths in a header.
///
/// This ensures that the actual data bytes appear at different positions
/// each time, providing true IND-CPA security.

use rand::Rng;

/// Padding chunk information
#[derive(Clone, Debug)]
pub struct PaddingChunk {
    /// Position where padding is inserted (relative to original message)
    pub position: usize,
    /// Length of the padding chunk
    pub length: usize,
}

/// Padding metadata stored in the header
#[derive(Clone, Debug)]
pub struct PaddingMetadata {
    /// Original message length (before padding)
    pub original_length: usize,
    /// Padding chunks information
    pub chunks: Vec<PaddingChunk>,
}

impl PaddingMetadata {
    /// Serialize padding metadata to bytes
    ///
    /// Format:
    /// [original_length: 4 bytes][num_chunks: 2 bytes]
    /// [chunk1_pos: 2 bytes][chunk1_len: 2 bytes]
    /// [chunk2_pos: 2 bytes][chunk2_len: 2 bytes]
    /// ...
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Original length (4 bytes)
        bytes.extend_from_slice(&(self.original_length as u32).to_be_bytes());

        // Number of chunks (2 bytes)
        bytes.extend_from_slice(&(self.chunks.len() as u16).to_be_bytes());

        // Each chunk: position (2 bytes) + length (2 bytes)
        for chunk in &self.chunks {
            bytes.extend_from_slice(&(chunk.position as u16).to_be_bytes());
            bytes.extend_from_slice(&(chunk.length as u16).to_be_bytes());
        }

        bytes
    }

    /// Deserialize padding metadata from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 6 {
            return Err("Padding metadata too short".to_string());
        }

        // Parse original length
        let original_length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        // Parse number of chunks
        let num_chunks = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;

        // Check if we have enough bytes for all chunks
        let expected_len = 6 + num_chunks * 4;
        if bytes.len() < expected_len {
            return Err(format!("Expected {} bytes, got {}", expected_len, bytes.len()));
        }

        // Parse chunks
        let mut chunks = Vec::new();
        let mut offset = 6;

        for _ in 0..num_chunks {
            let position = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            chunks.push(PaddingChunk { position, length });
            offset += 4;
        }

        Ok(PaddingMetadata {
            original_length,
            chunks,
        })
    }

    /// Get the size of the serialized metadata
    pub fn serialized_size(&self) -> usize {
        6 + self.chunks.len() * 4
    }
}

/// Generate random padding chunks
///
/// # Arguments
/// * `message_len` - Length of the original message
/// * `min_chunks` - Minimum number of padding chunks (default: 3)
/// * `max_chunks` - Maximum number of padding chunks (default: 8)
/// * `min_chunk_size` - Minimum size of each chunk (default: 4)
/// * `max_chunk_size` - Maximum size of each chunk (default: 16)
///
/// # Returns
/// Vector of padding chunks with random positions and lengths
pub fn generate_padding_chunks(
    message_len: usize,
    min_chunks: usize,
    max_chunks: usize,
    min_chunk_size: usize,
    max_chunk_size: usize,
) -> Vec<PaddingChunk> {
    let mut rng = rand::thread_rng();

    // Generate random number of chunks
    let num_chunks = rng.gen_range(min_chunks..=max_chunks);

    let mut chunks = Vec::new();

    for _ in 0..num_chunks {
        // Random position (can be anywhere in the message, including before/after)
        let position = rng.gen_range(0..=message_len);

        // Random length
        let length = rng.gen_range(min_chunk_size..=max_chunk_size);

        chunks.push(PaddingChunk { position, length });
    }

    // Sort chunks by position for easier insertion
    chunks.sort_by_key(|c| c.position);

    chunks
}

/// Insert padding into the message
///
/// # Arguments
/// * `message` - Original message bytes
/// * `chunks` - Padding chunks to insert
///
/// # Returns
/// Tuple of (padded_message, metadata)
pub fn insert_padding(message: &[u8], chunks: &[PaddingChunk]) -> (Vec<u8>, PaddingMetadata) {
    let mut rng = rand::thread_rng();
    let mut result = message.to_vec();

    // Insert padding chunks in reverse order to maintain positions
    for chunk in chunks.iter().rev() {
        // Generate random padding bytes
        let padding: Vec<u8> = (0..chunk.length).map(|_| rng.r#gen::<u8>()).collect();

        // Insert at position
        let insert_pos = chunk.position.min(result.len());
        result.splice(insert_pos..insert_pos, padding);
    }

    let metadata = PaddingMetadata {
        original_length: message.len(),
        chunks: chunks.to_vec(),
    };

    (result, metadata)
}

/// Remove padding from the message
///
/// # Arguments
/// * `padded_message` - Message with padding inserted
/// * `metadata` - Padding metadata describing where padding was inserted
///
/// # Returns
/// Original message without padding
pub fn remove_padding(padded_message: &[u8], metadata: &PaddingMetadata) -> Result<Vec<u8>, String> {
    let mut result = padded_message.to_vec();

    // Calculate adjusted positions for each chunk
    // When we inserted padding, later positions shifted by the length of earlier padding
    let mut adjusted_chunks = Vec::new();
    let mut cumulative_shift = 0;

    for chunk in &metadata.chunks {
        adjusted_chunks.push(PaddingChunk {
            position: chunk.position + cumulative_shift,
            length: chunk.length,
        });
        cumulative_shift += chunk.length;
    }

    // Remove padding chunks in reverse order to maintain positions
    for chunk in adjusted_chunks.iter().rev() {
        let start = chunk.position;
        let end = start + chunk.length;

        if end > result.len() {
            return Err(format!(
                "Invalid padding chunk: position {} + length {} exceeds message length {}",
                chunk.position, chunk.length, result.len()
            ));
        }

        result.drain(start..end);
    }

    // Verify the result length matches the original length
    if result.len() != metadata.original_length {
        return Err(format!(
            "Length mismatch after removing padding: expected {}, got {}",
            metadata.original_length, result.len()
        ));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_metadata_serialization() {
        let metadata = PaddingMetadata {
            original_length: 100,
            chunks: vec![
                PaddingChunk { position: 10, length: 5 },
                PaddingChunk { position: 50, length: 8 },
            ],
        };

        let serialized = metadata.serialize();
        let deserialized = PaddingMetadata::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.original_length, 100);
        assert_eq!(deserialized.chunks.len(), 2);
        assert_eq!(deserialized.chunks[0].position, 10);
        assert_eq!(deserialized.chunks[0].length, 5);
        assert_eq!(deserialized.chunks[1].position, 50);
        assert_eq!(deserialized.chunks[1].length, 8);
    }

    #[test]
    fn test_insert_and_remove_padding() {
        let message = b"Hello, World!";
        let chunks = vec![
            PaddingChunk { position: 5, length: 4 },
            PaddingChunk { position: 10, length: 6 },
        ];

        let (padded, metadata) = insert_padding(message, &chunks);

        // Padded message should be longer
        assert_eq!(padded.len(), message.len() + 4 + 6);

        // Remove padding
        let recovered = remove_padding(&padded, &metadata).unwrap();

        // Should match original
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_generate_padding_chunks() {
        let chunks = generate_padding_chunks(100, 3, 8, 4, 16);

        // Should have between 3 and 8 chunks
        assert!(chunks.len() >= 3 && chunks.len() <= 8);

        // Each chunk should have valid position and length
        for chunk in &chunks {
            assert!(chunk.position <= 100);
            assert!(chunk.length >= 4 && chunk.length <= 16);
        }

        // Chunks should be sorted by position
        for i in 1..chunks.len() {
            assert!(chunks[i].position >= chunks[i - 1].position);
        }
    }
}

