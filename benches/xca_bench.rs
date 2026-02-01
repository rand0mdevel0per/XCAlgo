use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use xcalgo::tda::tda_keygen;
use xcalgo::tda::simd::{generate_random_bytes_simd, is_avx2_available};
use xcalgo::tda::padding::{generate_padding_chunks, insert_padding};

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
                    xcalgo::tda::crypto::tda_encrypt(
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

fn bench_simd_random_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("SIMD Random Bytes");

    // Show AVX2 availability
    println!("AVX2 available: {}", is_avx2_available());

    for size in [64, 256, 1024, 4096].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bytes", size)),
            size,
            |b, &size| {
                b.iter(|| {
                    generate_random_bytes_simd(black_box(size))
                });
            },
        );
    }

    group.finish();
}

fn bench_padding_insertion(c: &mut Criterion) {
    let mut group = c.benchmark_group("Padding Insertion");

    for msg_len in [64, 256, 1024].iter() {
        let message = vec![0x42u8; *msg_len];
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}bytes", msg_len)),
            &message,
            |b, msg| {
                b.iter(|| {
                    let chunks = generate_padding_chunks(msg.len(), 3, 8, 4, 16);
                    insert_padding(black_box(msg), black_box(&chunks))
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_keygen, bench_encrypt, bench_simd_random_bytes, bench_padding_insertion);
criterion_main!(benches);
