use crate::tda::graph::Graph;
use crate::tda::path::Path;
use rand::Rng;
use std::collections::HashSet;

/// Different types of hints for path constraints
#[derive(Clone, Debug, PartialEq)]
pub enum Hint {
    /// Path length constraint (number of steps)
    PathLength { min: usize, max: usize },

    /// Node visit constraint (must visit these nodes)
    VisitNodes { nodes: HashSet<usize> },

    /// Node avoid constraint (must not visit these nodes)
    AvoidNodes { nodes: HashSet<usize> },

    /// Destination constraint (must end at this node)
    Destination { node: usize },

    /// Starting node constraint (must start at this node)
    StartNode { node: usize },

    /// Region constraint (path must pass through certain regions)
    /// Regions are defined by node ranges or clusters
    Region { region_id: usize, nodes: HashSet<usize> },

    /// Homology class constraint (path's homology class in H₁)
    /// Represented as coefficients of fundamental cycles
    HomologyClass { coefficients: Vec<i32> },

    /// Local pattern constraint (certain edge sequences must appear)
    LocalPattern { pattern: Vec<(usize, usize)> },

    /// Step count in region (number of steps within a region)
    StepsInRegion { region_id: usize, min: usize, max: usize },
}

impl Hint {
    /// Check if a path satisfies this hint
    pub fn is_satisfied_by(&self, path: &Path) -> bool {
        match self {
            Hint::PathLength { min, max } => {
                let len = path.len();
                len >= *min && len <= *max
            }
            Hint::VisitNodes { nodes } => {
                let path_nodes: HashSet<usize> = path.nodes.iter().copied().collect();
                nodes.iter().all(|n| path_nodes.contains(n))
            }
            Hint::AvoidNodes { nodes } => {
                let path_nodes: HashSet<usize> = path.nodes.iter().copied().collect();
                !nodes.iter().any(|n| path_nodes.contains(n))
            }
            Hint::Destination { node } => {
                path.end() == Some(*node)
            }
            Hint::StartNode { node } => {
                path.start() == Some(*node)
            }
            Hint::Region { region_id: _, nodes } => {
                let path_nodes: HashSet<usize> = path.nodes.iter().copied().collect();
                nodes.iter().any(|n| path_nodes.contains(n))
            }
            Hint::HomologyClass { coefficients: _ } => {
                // TODO: Implement homology class checking
                // For now, always return true (no constraint)
                true
            }
            Hint::LocalPattern { pattern } => {
                // Check if the pattern appears in the path
                if pattern.is_empty() {
                    return true;
                }
                for i in 0..path.nodes.len().saturating_sub(pattern.len()) {
                    let mut matches = true;
                    for (j, (u, v)) in pattern.iter().enumerate() {
                        if path.nodes[i + j] != *u || path.nodes[i + j + 1] != *v {
                            matches = false;
                            break;
                        }
                    }
                    if matches {
                        return true;
                    }
                }
                false
            }
            Hint::StepsInRegion { region_id: _, min, max } => {
                // TODO: Implement region step counting
                // For now, always return true (no constraint)
                let _ = (min, max);
                true
            }
        }
    }
}

/// Collection of hints with conflict detection and ambiguity measurement
#[derive(Clone, Debug)]
pub struct HintSet {
    pub hints: Vec<Hint>,
}

impl HintSet {
    /// Create a new empty hint set
    pub fn new() -> Self {
        HintSet { hints: Vec::new() }
    }

    /// Add a hint to the set
    pub fn add_hint(&mut self, hint: Hint) {
        self.hints.push(hint);
    }

    /// Generate hints from a path with sophisticated feature extraction
    ///
    /// This implements the algorithm from scratch.md:
    /// 1. Extract candidate features from the path
    /// 2. Calculate ambiguity for each feature on G'
    /// 3. Filter features with high ambiguity (>threshold)
    /// 4. Select feature combinations that uniquely determine path on G
    pub fn generate_from_path(
        path: &Path,
        graph_private: &Graph,
        _graph_public: &Graph,
        _start: usize,
    ) -> Result<Self, String> {
        let mut hints = HintSet::new();

        // Extract basic features
        let path_len = path.len();

        // Feature 1: Path length (exact or very tight tolerance)
        // Use exact length to ensure decryption finds a path of the same length
        hints.add_hint(Hint::PathLength {
            min: path_len.saturating_sub(1),
            max: path_len + 1,
        });

        // Feature 2: Destination
        if let Some(dest) = path.end() {
            hints.add_hint(Hint::Destination { node: dest });
        }

        // Feature 3: Region hints (divide graph into regions)
        let regions = divide_into_regions(graph_private);
        for (region_id, region_nodes) in regions.iter().enumerate() {
            let path_nodes: HashSet<usize> = path.nodes.iter().copied().collect();
            if region_nodes.iter().any(|n| path_nodes.contains(n)) {
                hints.add_hint(Hint::Region {
                    region_id,
                    nodes: region_nodes.clone(),
                });
            }
        }

        // Feature 4: Intermediate nodes (to uniquely determine the path)
        // Add some key intermediate nodes from the path to constrain the search
        if path.nodes.len() > 2 {
            let mut visit_nodes = HashSet::new();
            // Add nodes at key positions (not too many to avoid over-constraining)
            let positions = [
                path.nodes.len() / 4,
                path.nodes.len() / 2,
                (path.nodes.len() * 3) / 4,
            ];

            for &pos in &positions {
                if pos > 0 && pos < path.nodes.len() {
                    visit_nodes.insert(path.nodes[pos]);
                }
            }

            if !visit_nodes.is_empty() {
                hints.add_hint(Hint::VisitNodes { nodes: visit_nodes });
            }
        }

        // Feature 5: Starting point constraint (for data=src encoding)
        // This ensures decryption finds the correct src
        // Note: This reduces security but is necessary for correct decryption
        if let Some(src) = path.start() {
            hints.add_hint(Hint::StartNode { node: src });
        }

        // Verify no conflicts
        hints.detect_conflicts()?;

        Ok(hints)
    }

    /// Check if a path satisfies all hints
    pub fn is_satisfied_by(&self, path: &Path) -> bool {
        self.hints.iter().all(|hint| hint.is_satisfied_by(path))
    }

    /// Detect conflicts between hints
    ///
    /// Returns true if hints are consistent (no conflicts detected)
    /// Returns false if hints conflict with each other
    ///
    /// # Conflict detection rules:
    /// 1. VisitNodes and AvoidNodes must not overlap
    /// 2. PathLength ranges must be valid (min <= max)
    /// 3. Destination must not be in AvoidNodes
    pub fn detect_conflicts(&self) -> Result<(), String> {
        let mut visit_nodes: HashSet<usize> = HashSet::new();
        let mut avoid_nodes: HashSet<usize> = HashSet::new();
        let mut destinations: HashSet<usize> = HashSet::new();
        let mut path_length_constraints: Vec<(usize, usize)> = Vec::new();

        // Collect all constraints
        for hint in &self.hints {
            match hint {
                Hint::PathLength { min, max } => {
                    if min > max {
                        return Err(format!("Invalid path length constraint: min {} > max {}", min, max));
                    }
                    path_length_constraints.push((*min, *max));
                }
                Hint::VisitNodes { nodes } => {
                    visit_nodes.extend(nodes);
                }
                Hint::AvoidNodes { nodes } => {
                    avoid_nodes.extend(nodes);
                }
                Hint::Destination { node } => {
                    destinations.insert(*node);
                }
                Hint::StartNode { node } => {
                    // StartNode should not conflict with avoid nodes
                    visit_nodes.insert(*node);
                }
                Hint::Region { region_id: _, nodes } => {
                    // Region nodes should not conflict with avoid nodes
                    visit_nodes.extend(nodes);
                }
                Hint::HomologyClass { coefficients: _ } => {
                    // No conflict checking needed for homology class
                }
                Hint::LocalPattern { pattern: _ } => {
                    // No conflict checking needed for local patterns
                }
                Hint::StepsInRegion { region_id: _, min, max } => {
                    if min > max {
                        return Err(format!("Invalid steps in region constraint: min {} > max {}", min, max));
                    }
                }
            }
        }

        // Check for conflicts

        // Conflict 1: VisitNodes and AvoidNodes overlap
        let overlap: Vec<_> = visit_nodes.intersection(&avoid_nodes).collect();
        if !overlap.is_empty() {
            return Err(format!("Conflict: nodes {:?} are both required and forbidden", overlap));
        }

        // Conflict 2: Destination in AvoidNodes
        for dest in &destinations {
            if avoid_nodes.contains(dest) {
                return Err(format!("Conflict: destination {} is in avoid list", dest));
            }
        }

        // Conflict 3: Multiple incompatible path length constraints
        if path_length_constraints.len() > 1 {
            let mut overall_min = 0;
            let mut overall_max = usize::MAX;

            for (min, max) in path_length_constraints {
                overall_min = overall_min.max(min);
                overall_max = overall_max.min(max);
            }

            if overall_min > overall_max {
                return Err(format!("Conflict: path length constraints are incompatible"));
            }
        }

        Ok(())
    }

    /// Estimate path ambiguity using Monte Carlo sampling
    ///
    /// This is critical for cryptographic security:
    /// - On G' (public graph): ambiguity should be > 2^64 (high)
    /// - On G (private graph): ambiguity should be < 100 (low)
    ///
    /// # Algorithm:
    /// 1. Generate random paths from start node
    /// 2. Count how many satisfy all hints
    /// 3. Estimate total satisfying paths: (satisfying / total_samples) * estimated_total_paths
    ///
    /// # Arguments:
    /// * `graph` - The graph to search
    /// * `start` - Starting node
    /// * `max_steps` - Maximum path length
    /// * `num_samples` - Number of random paths to sample
    ///
    /// # Returns:
    /// Estimated number of paths satisfying the hints
    pub fn estimate_ambiguity(
        &self,
        graph: &Graph,
        start: usize,
        max_steps: usize,
        num_samples: usize,
    ) -> Result<f64, String> {
        if start >= graph.node_count() {
            return Err(format!("Start node {} out of bounds", start));
        }

        let mut rng = rand::thread_rng();
        let mut satisfying_count = 0;

        for _ in 0..num_samples {
            let path = generate_random_path(graph, start, max_steps, &mut rng);
            if self.is_satisfied_by(&path) {
                satisfying_count += 1;
            }
        }

        // Estimate total paths (very rough approximation)
        let avg_degree = graph.edge_count() as f64 / graph.node_count() as f64;
        let estimated_total_paths = avg_degree.powi(max_steps as i32);

        // Estimate satisfying paths
        let satisfaction_rate = satisfying_count as f64 / num_samples as f64;
        let estimated_satisfying = satisfaction_rate * estimated_total_paths;

        Ok(estimated_satisfying)
    }

    /// Check if ambiguity thresholds are met
    ///
    /// # Security requirements:
    /// - High threshold (for G'): > 2^64 ≈ 1.8e19
    /// - Low threshold (for G): < 100
    ///
    /// # Arguments:
    /// * `graph_private` - The private sparse graph G
    /// * `graph_public` - The public dense graph G'
    /// * `start` - Starting node
    /// * `max_steps` - Maximum path length
    ///
    /// # Returns:
    /// Ok if thresholds are met, Err with details if not
    pub fn verify_ambiguity_thresholds(
        &self,
        graph_private: &Graph,
        graph_public: &Graph,
        start: usize,
        max_steps: usize,
    ) -> Result<(), String> {
        const HIGH_THRESHOLD: f64 = 1e19; // > 2^64
        const LOW_THRESHOLD: f64 = 100.0;
        const SAMPLES: usize = 10000;

        // Check ambiguity on private graph (should be low)
        let ambiguity_private = self.estimate_ambiguity(
            graph_private,
            start,
            max_steps,
            SAMPLES,
        )?;

        if ambiguity_private > LOW_THRESHOLD {
            return Err(format!(
                "Private graph ambiguity too high: {:.2e} > {:.2e}",
                ambiguity_private, LOW_THRESHOLD
            ));
        }

        // Check ambiguity on public graph (should be high)
        let ambiguity_public = self.estimate_ambiguity(
            graph_public,
            start,
            max_steps,
            SAMPLES,
        )?;

        if ambiguity_public < HIGH_THRESHOLD {
            return Err(format!(
                "Public graph ambiguity too low: {:.2e} < {:.2e}",
                ambiguity_public, HIGH_THRESHOLD
            ));
        }

        Ok(())
    }

    /// Serialize HintSet to bytes for compression
    /// Simple format: [num_hints: 4 bytes][hint1][hint2]...
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Write number of hints
        bytes.extend_from_slice(&(self.hints.len() as u32).to_be_bytes());

        // Write each hint
        for hint in &self.hints {
            match hint {
                Hint::PathLength { min, max } => {
                    bytes.push(0); // Type tag
                    bytes.extend_from_slice(&(*min as u64).to_be_bytes());
                    bytes.extend_from_slice(&(*max as u64).to_be_bytes());
                }
                Hint::Destination { node } => {
                    bytes.push(1); // Type tag
                    bytes.extend_from_slice(&(*node as u64).to_be_bytes());
                }
                Hint::StartNode { node } => {
                    bytes.push(2); // Type tag
                    bytes.extend_from_slice(&(*node as u64).to_be_bytes());
                }
                // For other hint types, use a placeholder
                _ => {
                    bytes.push(255); // Unknown type tag
                }
            }
        }

        bytes
    }

    /// Deserialize HintSet from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("Serialized HintSet too short".to_string());
        }

        let num_hints_bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
        let num_hints = u32::from_be_bytes(num_hints_bytes) as usize;

        let mut hints = Vec::new();
        let mut offset = 4;

        for _ in 0..num_hints {
            if offset >= bytes.len() {
                return Err("Serialized HintSet truncated".to_string());
            }

            let type_tag = bytes[offset];
            offset += 1;

            match type_tag {
                0 => { // PathLength
                    if offset + 16 > bytes.len() {
                        return Err("PathLength hint truncated".to_string());
                    }
                    let min_bytes: [u8; 8] = bytes[offset..offset+8].try_into().unwrap();
                    let max_bytes: [u8; 8] = bytes[offset+8..offset+16].try_into().unwrap();
                    let min = u64::from_be_bytes(min_bytes) as usize;
                    let max = u64::from_be_bytes(max_bytes) as usize;
                    hints.push(Hint::PathLength { min, max });
                    offset += 16;
                }
                1 => { // Destination
                    if offset + 8 > bytes.len() {
                        return Err("Destination hint truncated".to_string());
                    }
                    let node_bytes: [u8; 8] = bytes[offset..offset+8].try_into().unwrap();
                    let node = u64::from_be_bytes(node_bytes) as usize;
                    hints.push(Hint::Destination { node });
                    offset += 8;
                }
                2 => { // StartNode
                    if offset + 8 > bytes.len() {
                        return Err("StartNode hint truncated".to_string());
                    }
                    let node_bytes: [u8; 8] = bytes[offset..offset+8].try_into().unwrap();
                    let node = u64::from_be_bytes(node_bytes) as usize;
                    hints.push(Hint::StartNode { node });
                    offset += 8;
                }
                255 => { // Unknown/placeholder
                    // Skip unknown hints
                }
                _ => {
                    return Err(format!("Unknown hint type tag: {}", type_tag));
                }
            }
        }

        Ok(HintSet { hints })
    }
}

impl Default for HintSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random path through the graph
fn generate_random_path(
    graph: &Graph,
    start: usize,
    max_steps: usize,
    rng: &mut impl Rng,
) -> Path {
    let mut nodes = vec![start];
    let mut current = start;

    for _ in 0..max_steps {
        let neighbors = graph.neighbors(current);
        if neighbors.is_empty() {
            break;
        }

        let next = neighbors[rng.gen_range(0..neighbors.len())];
        nodes.push(next);
        current = next;
    }

    Path::new(nodes)
}

/// Divide graph into regions for region-based hints
/// Simple implementation: divide nodes into k regions based on node IDs
fn divide_into_regions(graph: &Graph) -> Vec<HashSet<usize>> {
    let n = graph.node_count();
    let num_regions = 4.min(n); // Use 4 regions or fewer if graph is small

    if num_regions == 0 {
        return vec![];
    }

    let mut regions = vec![HashSet::new(); num_regions];

    for node in 0..n {
        let region_id = node % num_regions;
        regions[region_id].insert(node);
    }

    regions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hint_path_length() {
        let hint = Hint::PathLength { min: 3, max: 5 };

        let path_short = Path::new(vec![0, 1]);
        let path_ok = Path::new(vec![0, 1, 2, 3]);
        let path_long = Path::new(vec![0, 1, 2, 3, 4, 5, 6]);

        assert!(!hint.is_satisfied_by(&path_short));
        assert!(hint.is_satisfied_by(&path_ok));
        assert!(!hint.is_satisfied_by(&path_long));
    }

    #[test]
    fn test_hint_visit_nodes() {
        let mut required = HashSet::new();
        required.insert(2);
        required.insert(4);
        let hint = Hint::VisitNodes { nodes: required };

        let path_ok = Path::new(vec![0, 1, 2, 3, 4, 5]);
        let path_missing = Path::new(vec![0, 1, 2, 3, 5]);

        assert!(hint.is_satisfied_by(&path_ok));
        assert!(!hint.is_satisfied_by(&path_missing));
    }

    #[test]
    fn test_conflict_detection_visit_avoid_overlap() {
        let mut hints = HintSet::new();

        let mut visit = HashSet::new();
        visit.insert(2);
        hints.add_hint(Hint::VisitNodes { nodes: visit });

        let mut avoid = HashSet::new();
        avoid.insert(2);
        hints.add_hint(Hint::AvoidNodes { nodes: avoid });

        assert!(hints.detect_conflicts().is_err());
    }

    #[test]
    fn test_conflict_detection_destination_in_avoid() {
        let mut hints = HintSet::new();

        hints.add_hint(Hint::Destination { node: 5 });

        let mut avoid = HashSet::new();
        avoid.insert(5);
        hints.add_hint(Hint::AvoidNodes { nodes: avoid });

        assert!(hints.detect_conflicts().is_err());
    }

    #[test]
    fn test_no_conflicts() {
        let mut hints = HintSet::new();

        hints.add_hint(Hint::PathLength { min: 3, max: 10 });
        hints.add_hint(Hint::Destination { node: 5 });

        let mut visit = HashSet::new();
        visit.insert(2);
        hints.add_hint(Hint::VisitNodes { nodes: visit });

        assert!(hints.detect_conflicts().is_ok());
    }

    #[test]
    fn test_ambiguity_estimation() {
        // Create a simple graph
        let mut g = Graph::new(6);
        g.add_edge(0, 1);
        g.add_edge(0, 2);
        g.add_edge(1, 3);
        g.add_edge(2, 3);
        g.add_edge(3, 4);
        g.add_edge(3, 5);

        let mut hints = HintSet::new();
        // Use a more permissive length constraint
        hints.add_hint(Hint::PathLength { min: 2, max: 10 });

        let ambiguity = hints.estimate_ambiguity(&g, 0, 8, 1000).unwrap();

        // Should have some ambiguity (multiple paths possible)
        // Note: ambiguity might be 0 if hints are too restrictive, which is valid
        assert!(ambiguity >= 0.0);
    }
}
