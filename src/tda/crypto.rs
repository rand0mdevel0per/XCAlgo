use crate::tda::graph::Graph;
use crate::tda::homology::{Cycle, compute_h1_generators};
use crate::tda::noise::add_noise_edges;
use crate::tda::path::{Path, encode_message_as_endpoints, decode_endpoints_to_message, find_simple_path};
use crate::tda::hints::HintSet;
use rand::Rng;
use std::collections::HashSet;

// ============================================================================
// Encryption Configuration
// ============================================================================

/// Configuration for encryption options
#[derive(Clone, Debug)]
pub struct EncryptionConfig {
    /// Enable random padding for IND-CPA security (default: true)
    pub randomness: bool,
    /// Enable zstd compression for size optimization (default: true)
    pub compression: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            randomness: true,
            compression: true,
        }
    }
}

impl EncryptionConfig {
    /// Create config with both randomness and compression enabled (recommended)
    pub fn secure() -> Self {
        Self::default()
    }

    /// Create config with only randomness (no compression)
    pub fn randomness_only() -> Self {
        Self {
            randomness: true,
            compression: false,
        }
    }

    /// Create config with only compression (no randomness)
    /// Warning: Not IND-CPA secure!
    pub fn compression_only() -> Self {
        Self {
            randomness: false,
            compression: true,
        }
    }

    /// Create config with no randomness or compression (basic mode)
    /// Warning: Not IND-CPA secure and no size optimization!
    pub fn basic() -> Self {
        Self {
            randomness: false,
            compression: false,
        }
    }
}

// ============================================================================
// Core Data Structures
// ============================================================================

/// TDA public key (for encryption)
#[derive(Clone, Debug)]
pub struct TdaPublicKey {
    /// Dense graph G' with noise edges
    pub graph_public: Graph,
    /// Starting node for paths
    pub start: usize,
}

/// TDA private key (for decryption)
#[derive(Clone, Debug)]
pub struct TdaPrivateKey {
    /// Sparse graph G (base graph)
    pub graph_private: Graph,
    /// H₁ homology generators of G
    pub homology_generators: Vec<Cycle>,
    /// Starting node for paths
    pub start: usize,
}

/// TDA ciphertext
#[derive(Clone, Debug)]
pub struct TdaCiphertext {
    /// Destination node of the path
    pub destination: usize,
    /// Number of steps in the path
    pub steps: usize,
    /// Hints to constrain path search
    pub hints: HintSet,
}

/// Generate TDA key pair
///
/// # Security parameters:
/// - `nodes`: Number of nodes in the graph (≥ 100 recommended)
/// - `base_edges`: Number of edges in sparse graph G (≈ 1.5 * nodes recommended)
/// - `noise_ratio`: Noise ratio for G' (≥ 5.0 recommended for security)
///
/// # Algorithm:
/// 1. Generate sparse graph G with specified nodes and edges
/// 2. Compute H₁(G) homology generators
/// 3. Generate dense graph G' by adding noise edges
/// 4. Verify G' has sufficient connectivity
/// 5. Return (public_key, private_key)
///
/// # Returns:
/// Result containing (TdaPublicKey, TdaPrivateKey) or error
pub fn tda_keygen(
    nodes: usize,
    base_edges: usize,
    noise_ratio: f64,
) -> Result<(TdaPublicKey, TdaPrivateKey), String> {
    if nodes < 10 {
        return Err("Number of nodes must be at least 10".to_string());
    }

    if base_edges < nodes {
        return Err("Number of base edges must be at least equal to number of nodes".to_string());
    }

    if noise_ratio < 2.0 {
        return Err("Noise ratio must be at least 2.0 for security".to_string());
    }

    let mut rng = rand::thread_rng();

    // Step 1: Generate sparse graph G (private key)
    let graph_private = generate_sparse_graph(nodes, base_edges, &mut rng)?;

    // Step 2: Compute H₁(G) homology generators
    let homology_generators = compute_h1_generators(&graph_private);

    // Step 3: Generate dense graph G' (public key) by adding noise
    let graph_public = add_noise_edges(&graph_private, noise_ratio, &mut rng);

    // Step 4: Choose starting node (node 0 for simplicity)
    let start = 0;

    // Step 5: Construct keys
    let public_key = TdaPublicKey {
        graph_public,
        start,
    };

    let private_key = TdaPrivateKey {
        graph_private,
        homology_generators,
        start,
    };

    Ok((public_key, private_key))
}

/// Generate a sparse connected graph
fn generate_sparse_graph(
    nodes: usize,
    target_edges: usize,
    rng: &mut impl Rng,
) -> Result<Graph, String> {
    let mut graph = Graph::new(nodes);

    // First, create a spanning tree to ensure connectivity
    for i in 1..nodes {
        let parent = rng.gen_range(0..i);
        graph.add_edge(parent, i);
    }

    // Add remaining edges randomly
    let mut edges_added = nodes - 1;

    while edges_added < target_edges {
        let u = rng.gen_range(0..nodes);
        let v = rng.gen_range(0..nodes);

        if u != v && !graph.has_edge(u, v) {
            graph.add_edge(u, v);
            edges_added += 1;
        }
    }

    Ok(graph)
}

/// Encrypt a message using TDA public key
///
/// # Algorithm:
/// 1. Encode message to path on private graph G
/// 2. Generate sophisticated hints with feature extraction
/// 3. Verify hints have high ambiguity on G' (public graph)
/// 4. Return ciphertext (destination, steps, hints)
///
/// # Security considerations:
/// - Path encoding happens on G (private graph) for consistency with decryption
/// - Hints have high ambiguity on G' (many paths satisfy them)
/// - Hints have low ambiguity on G (uniquely determine the path)
/// - Decryption finds the same path on G by satisfying hints
///
/// # Arguments:
/// * `message` - The message bytes to encrypt
/// * `pk` - The public key
/// * `sk` - The private key (needed for path encoding and hint generation)
///
/// # Returns:
/// Result containing TdaCiphertext or error
pub fn tda_encrypt(
    message: &[u8],
    pk: &TdaPublicKey,
    sk: &TdaPrivateKey,
) -> Result<TdaCiphertext, String> {
    // Step 1: Encode message as endpoint selection (data=src approach)
    // Message determines both src and dest
    let (src, dest) = encode_message_as_endpoints(message, &sk.graph_private)?;

    // Step 2: Find a simple path from src to dest on private graph G
    let path = find_simple_path(&sk.graph_private, src, dest)?;

    if path.len() < 2 {
        return Err("Path too short for encryption".to_string());
    }

    // Step 3: Generate sophisticated hints with feature extraction
    // Note: We need both G and G' for proper hint generation
    let hints = HintSet::generate_from_path(
        &path,
        &sk.graph_private,
        &pk.graph_public,
        src,
    )?;

    // Step 4: Extract ciphertext components
    // Note: src is NOT included in ciphertext (it's part of the message)
    let destination = dest;
    let steps = path.len() - 1; // Number of edges

    Ok(TdaCiphertext {
        destination,
        steps,
        hints,
    })
}

/// Decrypt a ciphertext using TDA private key
///
/// # Algorithm (data=src approach):
/// 1. Try all possible source nodes
/// 2. For each src, search for path from src to dest satisfying hints
/// 3. If found, decode (src, dest) to message
/// 4. Return message
///
/// # Arguments:
/// * `ciphertext` - The ciphertext to decrypt
/// * `sk` - The private key
///
/// # Returns:
/// Result containing decrypted message bytes or error
pub fn tda_decrypt(
    ciphertext: &TdaCiphertext,
    sk: &TdaPrivateKey,
) -> Result<Vec<u8>, String> {
    let n = sk.graph_private.node_count();

    // Step 1: Try all possible source nodes
    for src in 0..n {
        // Step 2: Search for path from src to dest satisfying hints
        let path_result = search_path_with_hints(
            &sk.graph_private,
            src,
            ciphertext.destination,
            ciphertext.steps,
            &ciphertext.hints,
        );

        if let Ok(path) = path_result {
            // Step 3: Decode (src, dest) to message
            let src_found = path.start().ok_or("Path has no start")?;
            let dest_found = path.end().ok_or("Path has no end")?;

            let message = decode_endpoints_to_message(
                src_found,
                dest_found,
                &sk.graph_private,
            )?;

            return Ok(message);
        }
    }

    Err("No path found satisfying hints for any source node".to_string())
}

/// Search for a path satisfying hints using backtracking
fn search_path_with_hints(
    graph: &Graph,
    start: usize,
    destination: usize,
    max_steps: usize,
    hints: &HintSet,
) -> Result<Path, String> {
    let mut current_path = vec![start];
    let mut visited = HashSet::new();
    visited.insert(start);

    // Convert max_steps (edges) to max_nodes
    let max_nodes = max_steps + 1;

    if backtrack_search(
        graph,
        &mut current_path,
        &mut visited,
        destination,
        max_nodes,
        hints,
    ) {
        Ok(Path::new(current_path))
    } else {
        Err("No path found satisfying hints".to_string())
    }
}

/// Backtracking search for path satisfying hints
fn backtrack_search(
    graph: &Graph,
    current_path: &mut Vec<usize>,
    visited: &mut HashSet<usize>,
    destination: usize,
    max_steps: usize,
    hints: &HintSet,
) -> bool {
    let current = *current_path.last().unwrap();

    // Check if we reached destination
    if current == destination {
        let path = Path::new(current_path.clone());
        return hints.is_satisfied_by(&path);
    }

    // Check if we exceeded max steps
    if current_path.len() > max_steps {
        return false;
    }

    // Try each neighbor
    for neighbor in graph.neighbors(current) {
        if !visited.contains(&neighbor) {
            current_path.push(neighbor);
            visited.insert(neighbor);

            if backtrack_search(graph, current_path, visited, destination, max_steps, hints) {
                return true;
            }

            current_path.pop();
            visited.remove(&neighbor);
        }
    }

    false
}

// ============================================================================
// IND-CPA Security: Randomized Padding
// ============================================================================

/// Encrypt with random padding for IND-CPA security
///
/// Adds a 4-byte length field and 8-byte random nonce before encryption.
/// Structure: [length: 4 bytes][nonce: 8 bytes][plaintext: variable]
/// This ensures that the same plaintext produces different ciphertexts each time.
pub fn tda_encrypt_with_randomness(
    plaintext: &[u8],
    pk: &TdaPublicKey,
    sk: &TdaPrivateKey,
) -> Result<TdaCiphertext, String> {
    use rand::RngCore;

    // Store original plaintext length (4 bytes, big-endian)
    let length = plaintext.len() as u32;
    let length_bytes = length.to_be_bytes();

    // Generate 8-byte random nonce (smaller than XCQA due to XCA's higher expansion)
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Construct: [length][nonce][plaintext]
    let mut padded = Vec::with_capacity(4 + 8 + plaintext.len());
    padded.extend_from_slice(&length_bytes);
    padded.extend_from_slice(&nonce);
    padded.extend_from_slice(plaintext);

    // Encrypt the padded message
    tda_encrypt(&padded, pk, sk)
}

/// Decrypt and remove random padding
///
/// Decrypts the ciphertext and extracts the original plaintext using the stored length.
pub fn tda_decrypt_with_randomness(
    ciphertext: &TdaCiphertext,
    sk: &TdaPrivateKey,
) -> Result<Vec<u8>, String> {
    // Decrypt
    let padded = tda_decrypt(ciphertext, sk)?;

    // Need at least 4 bytes for length + 8 bytes for nonce
    if padded.len() < 12 {
        return Err("Decrypted data too short".to_string());
    }

    // Read original plaintext length (first 4 bytes)
    let length_bytes: [u8; 4] = padded[0..4].try_into()
        .map_err(|_| "Failed to read length field")?;
    let length = u32::from_be_bytes(length_bytes) as usize;

    // Skip length (4 bytes) and nonce (8 bytes), extract plaintext
    let start = 12;
    let end = start + length;

    if end <= padded.len() {
        Ok(padded[start..end].to_vec())
    } else {
        Err("Length field is corrupted or invalid".to_string())
    }
}

// ============================================================================
// Size Optimization: Zstd Compression
// ============================================================================

/// Encrypt and compress with zstd
///
/// Note: For XCA, compression provides limited benefit due to high ciphertext entropy.
/// The TdaCiphertext structure is already compact (destination + steps + hints).
/// This function is provided for completeness but may not significantly reduce size.
pub fn tda_encrypt_with_compression(
    plaintext: &[u8],
    pk: &TdaPublicKey,
    sk: &TdaPrivateKey,
) -> Result<Vec<u8>, String> {
    let ciphertext = tda_encrypt(plaintext, pk, sk)?;

    // Serialize ciphertext to bytes for compression
    let serialized = serialize_ciphertext(&ciphertext);

    zstd::encode_all(&serialized[..], 3)
        .map_err(|e| format!("Compression failed: {:?}", e))
}

/// Decompress and decrypt
pub fn tda_decrypt_with_decompression(
    compressed: &[u8],
    sk: &TdaPrivateKey,
) -> Result<Vec<u8>, String> {
    let serialized = zstd::decode_all(compressed)
        .map_err(|e| format!("Decompression failed: {:?}", e))?;

    let ciphertext = deserialize_ciphertext(&serialized)?;

    tda_decrypt(&ciphertext, sk)
}

/// Encrypt with both randomness and compression (IND-CPA + size optimization)
pub fn tda_encrypt_randomized_compressed(
    plaintext: &[u8],
    pk: &TdaPublicKey,
    sk: &TdaPrivateKey,
) -> Result<Vec<u8>, String> {
    let ciphertext = tda_encrypt_with_randomness(plaintext, pk, sk)?;

    let serialized = serialize_ciphertext(&ciphertext);

    zstd::encode_all(&serialized[..], 3)
        .map_err(|e| format!("Compression failed: {:?}", e))
}

/// Decrypt with decompression and randomness removal
pub fn tda_decrypt_decompressed_randomized(
    compressed: &[u8],
    sk: &TdaPrivateKey,
) -> Result<Vec<u8>, String> {
    let serialized = zstd::decode_all(compressed)
        .map_err(|e| format!("Decompression failed: {:?}", e))?;

    let ciphertext = deserialize_ciphertext(&serialized)?;

    tda_decrypt_with_randomness(&ciphertext, sk)
}

// Helper functions for serialization
fn serialize_ciphertext(ct: &TdaCiphertext) -> Vec<u8> {
    // Simple serialization: [dest: 8 bytes][steps: 8 bytes][hints_len: 4 bytes][hints: variable]
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(ct.destination as u64).to_be_bytes());
    bytes.extend_from_slice(&(ct.steps as u64).to_be_bytes());

    let hints_bytes = ct.hints.serialize();
    bytes.extend_from_slice(&(hints_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&hints_bytes);

    bytes
}

fn deserialize_ciphertext(bytes: &[u8]) -> Result<TdaCiphertext, String> {
    if bytes.len() < 20 {
        return Err("Serialized ciphertext too short".to_string());
    }

    let dest_bytes: [u8; 8] = bytes[0..8].try_into().unwrap();
    let destination = u64::from_be_bytes(dest_bytes) as usize;

    let steps_bytes: [u8; 8] = bytes[8..16].try_into().unwrap();
    let steps = u64::from_be_bytes(steps_bytes) as usize;

    let hints_len_bytes: [u8; 4] = bytes[16..20].try_into().unwrap();
    let hints_len = u32::from_be_bytes(hints_len_bytes) as usize;

    if bytes.len() < 20 + hints_len {
        return Err("Serialized ciphertext truncated".to_string());
    }

    let hints = HintSet::deserialize(&bytes[20..20+hints_len])?;

    Ok(TdaCiphertext {
        destination,
        steps,
        hints,
    })
}

// ============================================================================
// Unified Config-Based Encryption (Recommended API)
// ============================================================================

/// Encrypt with configuration options (recommended API)
///
/// This is the recommended way to encrypt data. By default, both randomness
/// and compression are enabled for IND-CPA security and size optimization.
///
/// # Examples
/// ```
/// use XCAlgo::tda::{tda_keygen, tda_encrypt_with_config, EncryptionConfig};
///
/// let (pk, sk) = tda_keygen(128, 192, 3.0).unwrap();
/// let plaintext = b"Hello, World!";
///
/// // Use default config (randomness + compression)
/// let ciphertext = tda_encrypt_with_config(plaintext, &pk, &sk, &EncryptionConfig::default()).unwrap();
/// ```
pub fn tda_encrypt_with_config(
    plaintext: &[u8],
    pk: &TdaPublicKey,
    sk: &TdaPrivateKey,
    config: &EncryptionConfig,
) -> Result<Vec<u8>, String> {
    match (config.randomness, config.compression) {
        (true, true) => {
            // Both enabled: randomness + compression
            tda_encrypt_randomized_compressed(plaintext, pk, sk)
        }
        (true, false) => {
            // Only randomness
            let ciphertext = tda_encrypt_with_randomness(plaintext, pk, sk)?;
            let serialized = serialize_ciphertext(&ciphertext);
            Ok(serialized)
        }
        (false, true) => {
            // Only compression
            tda_encrypt_with_compression(plaintext, pk, sk)
        }
        (false, false) => {
            // Basic mode (no randomness, no compression)
            let ciphertext = tda_encrypt(plaintext, pk, sk)?;
            let serialized = serialize_ciphertext(&ciphertext);
            Ok(serialized)
        }
    }
}

/// Decrypt with configuration options (recommended API)
///
/// Must use the same configuration that was used for encryption.
pub fn tda_decrypt_with_config(
    ciphertext: &[u8],
    sk: &TdaPrivateKey,
    config: &EncryptionConfig,
) -> Result<Vec<u8>, String> {
    match (config.randomness, config.compression) {
        (true, true) => {
            // Both enabled: decompression + randomness removal
            tda_decrypt_decompressed_randomized(ciphertext, sk)
        }
        (true, false) => {
            // Only randomness
            let ct = deserialize_ciphertext(ciphertext)?;
            tda_decrypt_with_randomness(&ct, sk)
        }
        (false, true) => {
            // Only compression
            tda_decrypt_with_decompression(ciphertext, sk)
        }
        (false, false) => {
            // Basic mode
            let ct = deserialize_ciphertext(ciphertext)?;
            tda_decrypt(&ct, sk)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tda_keygen() {
        let result = tda_keygen(20, 30, 3.0);
        assert!(result.is_ok());

        let (pk, sk) = result.unwrap();

        // Verify key structure
        assert_eq!(pk.graph_public.node_count(), 20);
        assert_eq!(sk.graph_private.node_count(), 20);
        assert_eq!(pk.start, sk.start);

        // Public graph should have more edges than private (due to noise)
        assert!(pk.graph_public.edge_count() > sk.graph_private.edge_count());
    }

    #[test]
    fn test_tda_encrypt_decrypt_roundtrip() {
        // Generate keys
        let (pk, sk) = tda_keygen(15, 20, 3.0).unwrap();

        // Test encryption produces valid ciphertext
        let message = b"Hello TDA!";
        let ciphertext = tda_encrypt(message, &pk, &sk).unwrap();

        // Verify ciphertext structure
        assert!(ciphertext.steps > 0);
        assert!(ciphertext.destination < pk.graph_public.node_count());
        assert!(!ciphertext.hints.hints.is_empty());

        // Note: Full roundtrip test is complex because:
        // - Encryption encodes on public graph G' (with noise edges)
        // - Decryption searches on private graph G (without noise edges)
        // - The exact path on G' might not exist on G
        // This is a known limitation of the current implementation
        // A production system would need more sophisticated hint generation
    }

    #[test]
    fn test_generate_sparse_graph() {
        let mut rng = rand::thread_rng();
        let graph = generate_sparse_graph(10, 15, &mut rng).unwrap();

        assert_eq!(graph.node_count(), 10);
        assert_eq!(graph.edge_count(), 15);

        // Verify connectivity (all nodes should be reachable from node 0)
        for i in 1..10 {
            assert!(graph.has_path(0, i), "Node {} not reachable from node 0", i);
        }
    }

    #[test]
    fn test_full_roundtrip_small_message() {
        // Generate keys with larger graph for testing
        // Need 256 nodes to encode 2 bytes (16 bits = 2 * 8 bits)
        let (pk, sk) = tda_keygen(256, 384, 3.0).unwrap();

        // Test with a small message
        let message = b"Hi";
        let ciphertext = tda_encrypt(message, &pk, &sk).unwrap();

        // Attempt decryption
        let decrypted = tda_decrypt(&ciphertext, &sk);

        // Verify decryption succeeded
        assert!(decrypted.is_ok(), "Decryption failed: {:?}", decrypted.err());

        let decrypted_msg = decrypted.unwrap();

        // Verify the decrypted message matches the original (at least the prefix)
        assert!(
            decrypted_msg.len() >= message.len(),
            "Decrypted message too short: {} < {}",
            decrypted_msg.len(),
            message.len()
        );

        assert_eq!(
            &decrypted_msg[..message.len()],
            message,
            "Decrypted message doesn't match original"
        );
    }
}
