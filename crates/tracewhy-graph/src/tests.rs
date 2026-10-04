use super::*;

#[test]
fn dedups_nodes_and_finds_paths() {
    let mut g = CauseGraph::new();
    let a = g.node(NodeKind::Process, "p:1", "node", vec![]).unwrap();
    let b = g
        .node(
            NodeKind::Observation,
            "o:1",
            "connect",
            vec![EvidenceRef::Event { seq: 4 }],
        )
        .unwrap();
    let c = g.node(NodeKind::Cause, "c", "pg down", vec![]).unwrap();
    assert_eq!(g.node(NodeKind::Process, "p:1", "dup", vec![]), Some(a));
    g.edge(a, b, EdgeKind::Attempted, vec![]);
    g.edge(b, c, EdgeKind::Explains, vec![]);
    g.edge(b, c, EdgeKind::Explains, vec![EvidenceRef::Fact { id: 1 }]);
    assert_eq!(g.edges.len(), 2);
    assert_eq!(
        g.path(a, c, &[EdgeKind::Attempted, EdgeKind::Explains]),
        Some(vec![a, b, c])
    );
    assert_eq!(g.path(a, c, &[EdgeKind::Attempted]), None);
    assert_eq!(g.evidence_for(c), vec![EvidenceRef::Fact { id: 1 }]);
}

#[test]
fn respects_node_limit() {
    let mut g = CauseGraph::with_limit(2);
    assert!(g.node(NodeKind::File, "a", "a", vec![]).is_some());
    assert!(g.node(NodeKind::File, "b", "b", vec![]).is_some());
    assert!(g.node(NodeKind::File, "c", "c", vec![]).is_none());
    assert!(g.truncated);
}

#[test]
fn roundtrip_reindex() {
    let mut g = CauseGraph::new();
    let a = g.node(NodeKind::Process, "p", "p", vec![]).unwrap();
    let b = g.node(NodeKind::Cause, "c", "c", vec![]).unwrap();
    g.edge(a, b, EdgeKind::Caused, vec![]);
    let s = serde_json::to_string(&g).unwrap();
    let mut g2: CauseGraph = serde_json::from_str(&s).unwrap();
    g2.reindex();
    assert_eq!(g2.path(a, b, &[EdgeKind::Caused]), Some(vec![a, b]));
    assert!(g2.find("p").is_some());
}

#[test]
fn large_graph_is_linear() {
    let mut g = CauseGraph::new();
    let mut prev = g.node(NodeKind::Command, "root", "root", vec![]).unwrap();
    let first = prev;
    for i in 0..100_000u32 {
        let n = g
            .node(NodeKind::Process, format!("p{i}"), "p", vec![])
            .unwrap();
        g.edge(prev, n, EdgeKind::Spawned, vec![]);
        prev = n;
    }
    assert_eq!(
        g.path(first, prev, &[EdgeKind::Spawned]).map(|p| p.len()),
        Some(100_001)
    );
}
