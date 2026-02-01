use crate::tda::graph::Graph;
use std::collections::VecDeque;

/// Represents a cycle in the graph (1-cycle for H₁ homology)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cycle {
    pub nodes: Vec<usize>,
}

impl Cycle {
    /// Create a new cycle from a list of nodes
    pub fn new(nodes: Vec<usize>) -> Self {
        Cycle { nodes }
    }

    /// Get the length of the cycle
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Check if the cycle is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Compute H₁ homology generators using the fundamental cycles method
///
/// Algorithm:
/// 1. Build a spanning tree T using DFS
/// 2. For each non-tree edge e = (u,v):
///    - Find path P from u to v in T
///    - Cycle = P ∪ {e}
///    - Add to generators
/// 3. Return generators
///
/// Time complexity: O(|V| + |E|)
pub fn compute_h1_generators(graph: &Graph) -> Vec<Cycle> {
    let spanning_tree = build_spanning_tree(graph);
    let mut generators = Vec::new();

    // Find all non-tree edges
    for (u, v) in graph.edges() {
        if !spanning_tree.has_edge(u, v) {
            // This is a non-tree edge, find the cycle it creates
            if let Some(cycle) = find_cycle_from_edge((u, v), &spanning_tree) {
                generators.push(cycle);
            }
        }
    }

    generators
}

/// Build a spanning tree using DFS
fn build_spanning_tree(graph: &Graph) -> Graph {
    let n = graph.node_count();
    let mut tree = Graph::new(n);
    let mut visited = vec![false; n];

    // Start DFS from node 0 (or first unvisited node)
    for start in 0..n {
        if !visited[start] {
            dfs_spanning_tree(graph, &mut tree, &mut visited, start, None);
        }
    }

    tree
}

/// DFS helper for building spanning tree
fn dfs_spanning_tree(
    graph: &Graph,
    tree: &mut Graph,
    visited: &mut [bool],
    current: usize,
    _parent: Option<usize>,
) {
    visited[current] = true;

    for neighbor in graph.neighbors(current) {
        if !visited[neighbor] {
            // Add edge to spanning tree
            tree.add_edge(current, neighbor);
            dfs_spanning_tree(graph, tree, visited, neighbor, Some(current));
        }
    }
}

/// Find the cycle created by adding a non-tree edge to the spanning tree
/// Returns the cycle as a sequence of nodes
fn find_cycle_from_edge(edge: (usize, usize), tree: &Graph) -> Option<Cycle> {
    let (u, v) = edge;

    // Find path from u to v in the tree using BFS
    let path = find_path_in_tree(tree, u, v)?;

    // The cycle is: u -> path -> v -> u
    // But we represent it as the sequence of nodes in the path plus the edge back
    let mut cycle_nodes = path;

    // Ensure the cycle is closed (starts and ends at the same node)
    if let Some(&first) = cycle_nodes.first() {
        if cycle_nodes.last() != Some(&first) {
            cycle_nodes.push(first);
        }
    }

    Some(Cycle::new(cycle_nodes))
}

/// Find a path between two nodes in a tree using BFS
fn find_path_in_tree(tree: &Graph, start: usize, end: usize) -> Option<Vec<usize>> {
    if start == end {
        return Some(vec![start]);
    }

    let n = tree.node_count();
    let mut visited = vec![false; n];
    let mut parent = vec![None; n];
    let mut queue = VecDeque::new();

    queue.push_back(start);
    visited[start] = true;

    while let Some(current) = queue.pop_front() {
        if current == end {
            // Reconstruct path
            let mut path = Vec::new();
            let mut node = end;

            while let Some(p) = parent[node] {
                path.push(node);
                node = p;
            }
            path.push(start);
            path.reverse();

            return Some(path);
        }

        for neighbor in tree.neighbors(current) {
            if !visited[neighbor] {
                visited[neighbor] = true;
                parent[neighbor] = Some(current);
                queue.push_back(neighbor);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spanning_tree_simple() {
        let mut g = Graph::new(4);
        g.add_edge(0, 1);
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 0);

        let tree = build_spanning_tree(&g);

        // Spanning tree should have n-1 edges for connected graph
        assert_eq!(tree.edge_count(), 3);
    }

    #[test]
    fn test_h1_single_cycle() {
        let mut g = Graph::new(4);
        g.add_edge(0, 1);
        g.add_edge(1, 2);
        g.add_edge(2, 3);
        g.add_edge(3, 0);

        let generators = compute_h1_generators(&g);

        // Single cycle should have 1 generator
        assert_eq!(generators.len(), 1);
    }

    #[test]
    fn test_h1_tree() {
        let mut g = Graph::new(4);
        g.add_edge(0, 1);
        g.add_edge(1, 2);
        g.add_edge(2, 3);

        let generators = compute_h1_generators(&g);

        // Tree has no cycles, so H₁ should be trivial
        assert_eq!(generators.len(), 0);
    }
}
