use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use XCAlgo::tda::tda_keygen;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("XCA KeyGen");

    for nodes in [64, 128, 256].iter() {
        let edges = nodes + nodes / 2;
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}nodes", nodes)),
            nodes,
            |b, &nodes| {
                b.iter(|| {
                    tda_keygen(black_box(nodes), black_box(edges), black_box(3.0))
                });
            },
        );
    }

    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("XCA Encrypt");

    // Pre-generate keys for different sizes
    let (pk_256, sk_256) = tda_keygen(256, 384, 3.0).unwrap();

    for msg_len in [2, 8, 16].iter() {
        let message = vec![0x42u8; *msg_len];
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bytes", msg_len)),
            &message,
            |b, msg| {
                b.iter(|| {
                    XCAlgo::tda::crypto::tda_encrypt(
                        black_box(msg),
                        black_box(&pk_256),
                        black_box(&sk_256),
                    )
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encrypt);
criterion_main!(benches);
