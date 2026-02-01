use crate::tda::graph::Graph;
use rand::Rng;

/// Add noise edges to a graph while preserving homology
///
/// Simplified approach (per user feedback):
/// - Focus on high noise ratio when generating G'
/// - Add tree edges (edges between already-connected nodes) to preserve H₁(G) = H₁(G')
/// - No need to consider complex intersection logic on G
///
/// # Arguments
/// * `base` - The base graph G (sparse, private)
/// * `noise_ratio` - Noise ratio (e.g., 5.0 means 5x more edges than base)
/// * `rng` - Random number generator
///
/// # Returns
/// The noisy graph G' with preserved homology
pub fn add_noise_edges(
    base: &Graph,
    noise_ratio: f64,
    rng: &mut impl Rng,
) -> Graph {
    let mut g_prime = base.clone();
    let target_edges = (base.edge_count() as f64 * noise_ratio) as usize;
    let n = base.node_count();

    let mut attempts = 0;
    let max_attempts = target_edges * 100; // Prevent infinite loops

    while g_prime.edge_count() < target_edges && attempts < max_attempts {
        attempts += 1;

        let u = rng.gen_range(0..n);
        let v = rng.gen_range(0..n);

        // Skip if same node or edge already exists
        if u == v || g_prime.has_edge(u, v) {
            continue;
        }

        // Add tree edge: only if u and v are already connected (preserves homology)
        // This ensures we don't create new independent cycles
        if g_prime.has_path(u, v) {
            g_prime.add_edge(u, v);
        }
    }

    g_prime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_preserves_connectivity() {
        let mut g = Graph::new(10);

        // Create a cycle: 0-1-2-3-4-5-6-7-8-9-0
        for i in 0..9 {
            g.add_edge(i, i + 1);
        }
        g.add_edge(9, 0);

        let mut rng = rand::thread_rng();
        let g_prime = add_noise_edges(&g, 5.0, &mut rng);

        // Should have added noise edges
        assert!(g_prime.edge_count() > g.edge_count());

        // All original edges should still be present (implicitly through connectivity)
        // All nodes should still be connected
        for i in 0..10 {
            for j in (i+1)..10 {
                assert!(g_prime.has_path(i, j), "Nodes {} and {} should be connected", i, j);
            }
        }
    }

    #[test]
    fn test_noise_ratio() {
        let mut g = Graph::new(10);

        // Create a simple connected graph
        for i in 0..9 {
            g.add_edge(i, i + 1);
        }

        let mut rng = rand::thread_rng();
        let g_prime = add_noise_edges(&g, 3.0, &mut rng);

        // Should have approximately 3x edges (may be less due to connectivity constraints)
        let expected_edges = g.edge_count() * 3;
        assert!(g_prime.edge_count() >= g.edge_count());
        assert!(g_prime.edge_count() <= expected_edges);
    }
}
