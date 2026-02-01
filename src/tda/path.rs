use crate::tda::graph::Graph;
use crate::tda::simd::{bytes_to_bits_simd, bits_to_bytes_simd};

/// Represents a path through the graph
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    pub nodes: Vec<usize>,
}

impl Path {
    /// Create a new path from a sequence of nodes
    pub fn new(nodes: Vec<usize>) -> Self {
        Path { nodes }
    }

    /// Get the length of the path (number of nodes)
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the path is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get the starting node of the path
    pub fn start(&self) -> Option<usize> {
        self.nodes.first().copied()
    }

    /// Get the ending node of the path
    pub fn end(&self) -> Option<usize> {
        self.nodes.last().copied()
    }
}

/// Encode a message into a path through the graph
///
/// Algorithm:
/// 1. Convert message to bit stream
/// 2. Start at the given start node
/// 3. At each step, use bits to select next neighbor:
///    - Get sorted list of neighbors
///    - Use log2(num_neighbors) bits to select which neighbor
///    - Move to selected neighbor
/// 4. Continue until all bits are consumed or stuck
///
/// # Security considerations:
/// - Deterministic encoding ensures same message → same path
/// - Path length reveals message length (information leakage)
/// - Neighbor selection must be deterministic (sorted order)
///
/// # Arguments
/// * `message` - The message bytes to encode
/// * `graph` - The graph to traverse
/// * `start` - The starting node
///
/// # Returns
/// Result containing the encoded path, or error if encoding fails
pub fn encode_message_to_path(
    message: &[u8],
    graph: &Graph,
    start: usize,
) -> Result<Path, String> {
    if start >= graph.node_count() {
        return Err(format!("Start node {} out of bounds", start));
    }

    let mut path = vec![start];
    let mut current = start;

    // Convert message to bits
    let bits = bytes_to_bits(message);
    let mut bit_offset = 0;

    while bit_offset < bits.len() {
        let mut neighbors = graph.neighbors(current);

        if neighbors.is_empty() {
            return Err(format!("Stuck at node {} with {} bits remaining", current, bits.len() - bit_offset));
        }

        // Sort neighbors for deterministic selection
        neighbors.sort_unstable();

        // Calculate how many bits needed to select a neighbor
        let num_neighbors = neighbors.len();
        let bits_needed = (num_neighbors as f64).log2().ceil() as usize;

        if bit_offset + bits_needed > bits.len() {
            // Not enough bits remaining, stop here
            break;
        }

        // Extract bits and convert to neighbor index
        let selection_bits = &bits[bit_offset..bit_offset + bits_needed];
        let mut neighbor_idx = bits_to_usize(selection_bits);

        // Handle case where bits represent value >= num_neighbors
        neighbor_idx %= num_neighbors;

        current = neighbors[neighbor_idx];
        path.push(current);
        bit_offset += bits_needed;
    }

    Ok(Path::new(path))
}

/// Decode a path back into the original message
///
/// Algorithm:
/// 1. Follow the path step by step
/// 2. At each step, determine which neighbor was selected:
///    - Get sorted list of neighbors from previous node
///    - Find index of current node in neighbor list
///    - Convert index to bits
/// 3. Concatenate all bits
/// 4. Convert bits back to bytes
///
/// # Arguments
/// * `path` - The path to decode
/// * `graph` - The graph the path traverses
///
/// # Returns
/// Result containing the decoded message bytes, or error if decoding fails
pub fn decode_path_to_message(
    path: &Path,
    graph: &Graph,
) -> Result<Vec<u8>, String> {
    if path.nodes.len() < 2 {
        return Ok(Vec::new());
    }

    let mut bits = Vec::new();

    for i in 0..path.nodes.len() - 1 {
        let current = path.nodes[i];
        let next = path.nodes[i + 1];

        let mut neighbors = graph.neighbors(current);

        if neighbors.is_empty() {
            return Err(format!("Node {} has no neighbors", current));
        }

        // Sort neighbors for deterministic order
        neighbors.sort_unstable();

        // Find which neighbor was selected
        let neighbor_idx = neighbors.iter()
            .position(|&n| n == next)
            .ok_or_else(|| format!("Node {} is not a neighbor of node {}", next, current))?;

        // Calculate how many bits were used for this selection
        let num_neighbors = neighbors.len();
        let bits_needed = (num_neighbors as f64).log2().ceil() as usize;

        // Convert neighbor index to bits
        let selection_bits = usize_to_bits(neighbor_idx, bits_needed);
        bits.extend(selection_bits);
    }

    Ok(bits_to_bytes(&bits))
}

/// Convert bytes to a bit vector
fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes_to_bits_simd(bytes)
}

/// Convert a bit vector to bytes
fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    bits_to_bytes_simd(bits)
}

/// Convert a slice of bits to usize
fn bits_to_usize(bits: &[bool]) -> usize {
    let mut value = 0usize;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            value |= 1 << (bits.len() - 1 - i);
        }
    }
    value
}

/// Convert usize to a bit vector of specified length
fn usize_to_bits(value: usize, num_bits: usize) -> Vec<bool> {
    let mut bits = Vec::new();
    for i in (0..num_bits).rev() {
        bits.push((value >> i) & 1 == 1);
    }
    bits
}

/// Encode message as endpoint selection (data=src approach)
///
/// This encoding method treats the message as a selection of source and destination nodes.
/// The message is split into two parts:
/// - First part: selects the source node (src)
/// - Second part: selects the destination node (dest)
///
/// # Arguments:
/// * `message` - The message bytes to encode
/// * `graph` - The graph to use for encoding
///
/// # Returns:
/// Result containing (src, dest) or error
pub fn encode_message_as_endpoints(
    message: &[u8],
    graph: &Graph,
) -> Result<(usize, usize), String> {
    let n = graph.node_count();
    if n == 0 {
        return Err("Graph has no nodes".to_string());
    }

    let bits_per_node = (n as f64).log2().ceil() as usize;
    let bits = bytes_to_bits(message);

    if bits.len() < bits_per_node * 2 {
        return Err(format!(
            "Message too short: need at least {} bits, got {}",
            bits_per_node * 2,
            bits.len()
        ));
    }

    // Extract src from first bits
    let src_bits = &bits[0..bits_per_node];
    let src = bits_to_usize(src_bits) % n;

    // Extract dest from next bits
    let dest_bits = &bits[bits_per_node..bits_per_node * 2];
    let dest = bits_to_usize(dest_bits) % n;

    Ok((src, dest))
}

/// Decode message from endpoint selection (data=src approach)
///
/// This decoding method reconstructs the message from source and destination nodes.
///
/// # Arguments:
/// * `src` - The source node
/// * `dest` - The destination node
/// * `graph` - The graph used for encoding
///
/// # Returns:
/// Result containing decoded message bytes or error
pub fn decode_endpoints_to_message(
    src: usize,
    dest: usize,
    graph: &Graph,
) -> Result<Vec<u8>, String> {
    let n = graph.node_count();
    if n == 0 {
        return Err("Graph has no nodes".to_string());
    }

    let bits_per_node = (n as f64).log2().ceil() as usize;
    let mut bits = Vec::new();

    // Encode src as bits
    bits.extend(usize_to_bits(src, bits_per_node));

    // Encode dest as bits
    bits.extend(usize_to_bits(dest, bits_per_node));

    Ok(bits_to_bytes(&bits))
}

/// Find a simple path from src to dest using BFS
///
/// # Arguments:
/// * `graph` - The graph to search
/// * `src` - Starting node
/// * `dest` - Destination node
///
/// # Returns:
/// Result containing Path or error if no path exists
pub fn find_simple_path(
    graph: &Graph,
    src: usize,
    dest: usize,
) -> Result<Path, String> {
    use std::collections::{VecDeque, HashMap};

    if src == dest {
        return Ok(Path::new(vec![src]));
    }

    let mut queue = VecDeque::new();
    let mut parent: HashMap<usize, usize> = HashMap::new();
    let mut visited = vec![false; graph.node_count()];

    queue.push_back(src);
    visited[src] = true;

    while let Some(current) = queue.pop_front() {
        if current == dest {
            // Reconstruct path
            let mut path = vec![dest];
            let mut node = dest;
            while node != src {
                node = *parent.get(&node).ok_or("Path reconstruction failed")?;
                path.push(node);
            }
            path.reverse();
            return Ok(Path::new(path));
        }

        for neighbor in graph.neighbors(current) {
            if !visited[neighbor] {
                visited[neighbor] = true;
                parent.insert(neighbor, current);
                queue.push_back(neighbor);
            }
        }
    }

    Err(format!("No path found from {} to {}", src, dest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_bits_conversion() {
        let bytes = vec![0b10101010, 0b11110000];
        let bits = bytes_to_bits(&bytes);
        let recovered = bits_to_bytes(&bits);
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn test_path_encoding_simple() {
        // Create a simple linear graph: 0-1-2-3-4
        let mut g = Graph::new(5);
        g.add_edge(0, 1);
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 4);

        let message = b"A";
        let path = encode_message_to_path(message, &g, 0).unwrap();

        // Path should start at 0
        assert_eq!(path.start(), Some(0));
        assert!(path.len() > 1);
    }

    #[test]
    fn test_path_encoding_decoding_roundtrip() {
        // Create a graph with multiple paths
        let mut g = Graph::new(6);
        g.add_edge(0, 1);
        g.add_edge(0, 2);
        g.add_edge(1, 3);
        g.add_edge(1, 4);
        g.add_edge(2, 4);
        g.add_edge(2, 5);
        g.add_edge(3, 4);
        g.add_edge(4, 5);

        let message = b"Test";
        let path = encode_message_to_path(message, &g, 0).unwrap();
        let decoded = decode_path_to_message(&path, &g).unwrap();

        // Decoded message should match original (at least the prefix)
        assert_eq!(&decoded[..message.len().min(decoded.len())], message);
    }
}
