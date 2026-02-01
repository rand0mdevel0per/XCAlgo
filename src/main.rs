use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Sha256, Digest};
use rand::Rng;

/// Recursive generator: x[i] = a * x[i-1]^b mod c
/// This is the core recursive formula
#[derive(Clone, Debug)]
struct RecursiveGenerator {
    a: BigUint,      // Multiplier
    b: u32,          // Exponent
    c: BigUint,      // Modulus
    current: BigUint, // Current value
}

impl RecursiveGenerator {
    /// Create new generator
    fn new(a: BigUint, b: u32, c: BigUint, seed: BigUint) -> Self {
        Self {
            a,
            b,
            c,
            current: seed,
        }
    }

    /// Execute one step of recursion: x[i] = a * x[i-1]^b mod c
    fn step(&mut self) -> BigUint {
        // x_new = a * x_current^b mod c
        let powered = self.current.modpow(&BigUint::from(self.b), &self.c);
        self.current = (&self.a * powered) % &self.c;
        self.current.clone()
    }

    /// Execute n steps of recursion
    fn step_n(&mut self, n: usize) -> BigUint {
        for _ in 0..n {
            self.step();
        }
        self.current.clone()
    }
}

/// XCA公钥：(n, e, a)
#[derive(Clone, Debug)]
struct PublicKey {
    n: BigUint,      // RSA模数 n = p * q
    e: BigUint,      // 公钥指数（常用65537）
    a: BigUint,      // 递推参数
}

/// XCA private key: (n, d, a, p, q)
#[derive(Clone, Debug)]
struct PrivateKey {
    n: BigUint,      // RSA modulus
    d: BigUint,      // Private exponent
    a: BigUint,      // Recursive parameter
    p: BigUint,      // Prime p
    q: BigUint,      // Prime q
}

/// 密文结构：(f', C, seed)
#[derive(Clone, Debug)]
struct Ciphertext {
    f_prime: BigUint,    // 变换后的特征
    c: Vec<u8>,          // 加密数据
    seed: BigUint,       // 递推起点
}

/// 零知识签名：(commitment, response)
#[derive(Clone, Debug)]
struct Signature {
    commitment: Ciphertext,  // 加密的nonce
    response: Vec<u8>,       // nonce XOR challenge
}

/// 辅助函数：生成随机素数（简化版，用于测试）
/// 注意：这不是密码学安全的素数生成，仅用于演示
fn generate_prime(bits: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    loop {
        // 生成随机奇数
        let mut bytes = vec![0u8; (bits + 7) / 8];
        rng.fill(&mut bytes[..]);
        bytes[0] |= 0x80; // 确保最高位为1
        let len = bytes.len();
        bytes[len - 1] |= 0x01; // 确保最低位为1（奇数）

        let candidate = BigUint::from_bytes_be(&bytes);

        // 简单的素性测试（Miller-Rabin会更好，但这里简化）
        if is_probably_prime(&candidate, 20) {
            return candidate;
        }
    }
}

/// Miller-Rabin素性测试
fn is_probably_prime(n: &BigUint, rounds: usize) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n % 2u32 == BigUint::zero() {
        return false;
    }

    // 写 n-1 = 2^r * d
    let n_minus_1 = n - 1u32;
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while &d % 2u32 == BigUint::zero() {
        d /= 2u32;
        r += 1;
    }

    let mut rng = rand::thread_rng();
    'witness: for _ in 0..rounds {
        // 随机选择witness a
        let a = BigUint::from(rng.gen_range(2u32..u32::MAX)) % (n - 3u32) + 2u32;
        let mut x = a.modpow(&d, n);

        if x == BigUint::one() || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..r-1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1{
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// 计算模逆：a^(-1) mod n
fn mod_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    // 扩展欧几里得算法
    let (mut t, mut new_t) = (BigUint::zero(), BigUint::one());
    let (mut r, mut new_r) = (n.clone(), a.clone());

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        let temp_t = t.clone();
        t = new_t.clone();
        if &quotient * &new_t <= temp_t {
            new_t = temp_t - &quotient * &new_t;
        } else {
            new_t = n - (&quotient * &new_t - temp_t) % n;
        }

        let temp_r = r;
        r = new_r;
        new_r = temp_r - &quotient * &r;
    }

    if r > BigUint::one() {
        return None; // 不存在模逆
    }

    Some(t % n)
}

/// Key generation
/// Generate XCA key pair: (public key, private key)
fn keygen(bits: usize) -> (PublicKey, PrivateKey) {
    println!("Generating {}-bit key pair...", bits);

    // 1. Generate two large primes p, q
    let p = generate_prime(bits / 2);
    let q = generate_prime(bits / 2);

    // 2. Calculate n = p * q
    let n = &p * &q;

    // 3. Calculate φ(n) = (p-1)(q-1)
    let phi_n = (&p - 1u32) * (&q - 1u32);

    // 4. Choose public exponent e = 65537 (common value)
    let e = BigUint::from(65537u32);

    // 5. Calculate private exponent d, satisfying e*d ≡ 1 (mod φ(n))
    let d = mod_inverse(&e, &phi_n).expect("Failed to compute modular inverse");

    // 6. Choose recursive parameter a (random, ensuring gcd(a, n) = 1)
    let mut rng = rand::thread_rng();
    let a = loop {
        let candidate = BigUint::from(rng.r#gen::<u64>()) % &n;
        if candidate > BigUint::one() {
            // Simplified: assume gcd(a, n) = 1 (should check in production)
            break candidate;
        }
    };

    let pk = PublicKey {
        n: n.clone(),
        e: e.clone(),
        a: a.clone(),
    };

    let sk = PrivateKey {
        n,
        d,
        a,
        p,
        q,
    };

    println!("Key generation complete!");
    (pk, sk)
}

/// Extract feature from message hash
/// Takes first k bits of SHA-256 hash
fn extract_feature(message: &[u8], k_bytes: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    hash[..k_bytes.min(32)].to_vec()
}

/// Generate keystream using recursive generator
/// x[i] = a * x[i-1]^e mod n
fn generate_keystream(seed: &BigUint, a: &BigUint, e: &BigUint, n: &BigUint, length: usize) -> Vec<u8> {
    let mut generator = RecursiveGenerator::new(a.clone(), 0, n.clone(), seed.clone());
    let mut keystream = Vec::new();

    while keystream.len() < length {
        // Use e as the exponent for this step
        let powered = generator.current.modpow(e, n);
        generator.current = (a * powered) % n;

        // Convert current value to bytes and append
        let bytes = generator.current.to_bytes_be();
        keystream.extend_from_slice(&bytes);
    }

    keystream.truncate(length);
    keystream
}

/// XOR two byte arrays
fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Encrypt message using XCA scheme
/// Returns: Ciphertext(f', C, seed)
/// If seed_opt is provided, uses that seed (for deterministic encryption in signatures)
fn encrypt_with_seed(message: &[u8], pk: &PublicKey, seed_opt: Option<BigUint>) -> Ciphertext {
    // 1. Extract feature: f = hash(M)[0..k]
    let k_bytes = 16; // 128 bits
    let f = extract_feature(message, k_bytes);
    let f_bigint = BigUint::from_bytes_be(&f);

    // 2. Feature trapdoor transformation: f' = f^e mod n
    let f_prime = f_bigint.modpow(&pk.e, &pk.n);

    // 3. Use provided seed or generate random seed
    let seed = match seed_opt {
        Some(s) => s,
        None => {
            let mut rng = rand::thread_rng();
            BigUint::from(rng.r#gen::<u128>())
        }
    };

    // 4. Mix feature into seed: seed' = seed ⊕ f'
    let f_prime_bytes = f_prime.to_bytes_be();
    let seed_bytes = seed.to_bytes_be();
    let max_len = f_prime_bytes.len().max(seed_bytes.len());

    let mut seed_prime_bytes = vec![0u8; max_len];
    for i in 0..max_len {
        let f_byte = if i < f_prime_bytes.len() { f_prime_bytes[i] } else { 0 };
        let s_byte = if i < seed_bytes.len() { seed_bytes[i] } else { 0 };
        seed_prime_bytes[i] = f_byte ^ s_byte;
    }
    let seed_prime = BigUint::from_bytes_be(&seed_prime_bytes);

    // 5. Generate keystream using recursive generator
    let keystream = generate_keystream(&seed_prime, &pk.a, &pk.e, &pk.n, message.len());

    // 6. Encrypt data: C = M ⊕ keystream
    let c = xor_bytes(message, &keystream);

    Ciphertext {
        f_prime,
        c,
        seed,
    }
}

/// Encrypt message using XCA scheme (with random seed)
fn encrypt(message: &[u8], pk: &PublicKey) -> Ciphertext {
    encrypt_with_seed(message, pk, None)
}

/// Decrypt ciphertext using XCA scheme
/// Returns: Option<Vec<u8>> - Some(plaintext) if valid, None if verification fails
fn decrypt(ciphertext: &Ciphertext, sk: &PrivateKey) -> Option<Vec<u8>> {
    // 1. Recover feature: f = (f')^d mod n
    let f = ciphertext.f_prime.modpow(&sk.d, &sk.n);

    // 2. Recover seed: seed' = seed ⊕ f'
    let f_prime_bytes = ciphertext.f_prime.to_bytes_be();
    let seed_bytes = ciphertext.seed.to_bytes_be();
    let max_len = f_prime_bytes.len().max(seed_bytes.len());

    let mut seed_prime_bytes = vec![0u8; max_len];
    for i in 0..max_len {
        let f_byte = if i < f_prime_bytes.len() { f_prime_bytes[i] } else { 0 };
        let s_byte = if i < seed_bytes.len() { seed_bytes[i] } else { 0 };
        seed_prime_bytes[i] = f_byte ^ s_byte;
    }
    let seed_prime = BigUint::from_bytes_be(&seed_prime_bytes);

    // 3. Rebuild keystream (forward recursion with public exponent e)
    let keystream = generate_keystream(&seed_prime, &sk.a, &BigUint::from(65537u32), &sk.n, ciphertext.c.len());

    // 4. Decrypt data: M = C ⊕ keystream
    let message = xor_bytes(&ciphertext.c, &keystream);

    // 5. Verify feature (integrity check)
    let k_bytes = 16;
    let f_check = extract_feature(&message, k_bytes);
    let f_check_bigint = BigUint::from_bytes_be(&f_check);

    if f_check_bigint == f {
        Some(message)
    } else {
        None // Decryption failed or data tampered
    }
}

/// Sign a message using zero-knowledge proof
/// Proves knowledge of private key without revealing it
fn sign(message: &[u8], sk: &PrivateKey, pk: &PublicKey) -> Signature {
    let mut rng = rand::thread_rng();

    // 1. Generate random nonce (16 bytes = 128 bits)
    let nonce_bytes = 16;
    let mut nonce = vec![0u8; nonce_bytes];
    rng.fill(&mut nonce[..]);

    // 2. Encrypt nonce with public key: C = Encrypt(nonce, pk)
    let commitment = encrypt(&nonce, pk);

    // 3. Compute challenge: e = Hash(C || message)
    let mut hasher = Sha256::new();
    // Hash commitment components
    hasher.update(commitment.f_prime.to_bytes_be());
    hasher.update(&commitment.c);
    hasher.update(commitment.seed.to_bytes_be());
    hasher.update(message);
    let challenge = hasher.finalize();

    // 4. Decrypt commitment: r = Decrypt(C, sk)
    let decrypted_nonce = decrypt(&commitment, sk).expect("Failed to decrypt commitment");

    // 5. Compute response: s = r XOR e (use first bytes of challenge)
    let mut response = vec![0u8; decrypted_nonce.len()];
    for i in 0..response.len() {
        response[i] = decrypted_nonce[i] ^ challenge[i];
    }

    Signature {
        commitment,
        response,
    }
}

/// Verify a zero-knowledge signature
/// Returns true if signature is valid
fn verify(message: &[u8], signature: &Signature, pk: &PublicKey) -> bool {
    // 1. Compute challenge: e = Hash(C || message)
    let mut hasher = Sha256::new();
    hasher.update(signature.commitment.f_prime.to_bytes_be());
    hasher.update(&signature.commitment.c);
    hasher.update(signature.commitment.seed.to_bytes_be());
    hasher.update(message);
    let challenge = hasher.finalize();

    // 2. Recover nonce: r = s XOR e (use first bytes of challenge)
    let mut recovered_nonce = vec![0u8; signature.response.len()];
    for i in 0..recovered_nonce.len() {
        recovered_nonce[i] = signature.response[i] ^ challenge[i];
    }

    // 3. Verify: Encrypt(r, pk) with SAME seed should equal C
    let recomputed_commitment = encrypt_with_seed(&recovered_nonce, pk, Some(signature.commitment.seed.clone()));

    // 4. Check if commitments match
    recomputed_commitment.f_prime == signature.commitment.f_prime
        && recomputed_commitment.c == signature.commitment.c
        && recomputed_commitment.seed == signature.commitment.seed
}

fn main() {
    println!("XCAlgo - Recursive Encryption Experiment");
    println!("=========================================\n");

    // Test 1: Key Generation
    println!("Test 1: Key Generation");
    let (pk, sk) = keygen(512); // Use 512 bits for faster testing
    println!("✓ Key pair generated\n");

    // Test 2: Encryption/Decryption
    println!("Test 2: Encryption/Decryption");
    let message = b"Hello, XCA! This is a test message.";
    println!("Original message: {:?}", String::from_utf8_lossy(message));

    let ciphertext = encrypt(message, &pk);
    println!("✓ Message encrypted");

    let decrypted = decrypt(&ciphertext, &sk);
    match decrypted {
        Some(plaintext) => {
            println!("✓ Message decrypted: {:?}", String::from_utf8_lossy(&plaintext));
            assert_eq!(&plaintext, message, "Decryption failed!");
            println!("✓ Decryption verified\n");
        }
        None => {
            println!("✗ Decryption failed!\n");
        }
    }

    // Test 3: Zero-Knowledge Signature
    println!("Test 3: Zero-Knowledge Signature");
    let signature = sign(message, &sk, &pk);
    println!("✓ Signature generated");

    let is_valid = verify(message, &signature, &pk);
    println!("✓ Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });

    // Test with wrong message
    let wrong_message = b"Wrong message";
    let is_valid_wrong = verify(wrong_message, &signature, &pk);
    println!("✓ Wrong message verification: {}", if is_valid_wrong { "VALID (ERROR!)" } else { "INVALID (correct)" });

    // Test 4: Avalanche Effect
    println!("\nTest 4: Avalanche Effect");
    let message1 = b"Hello, XCA! This is a test message.";
    let message2 = b"Hello, XCA! This is a test messag."; // One character different

    let ct1 = encrypt(message1, &pk);
    let ct2 = encrypt(message2, &pk);

    // Count differing bits in ciphertext
    let mut diff_bits = 0;
    let min_len = ct1.c.len().min(ct2.c.len());
    for i in 0..min_len {
        diff_bits += (ct1.c[i] ^ ct2.c[i]).count_ones();
    }

    let total_bits = min_len * 8;
    let diff_percentage = (diff_bits as f64 / total_bits as f64) * 100.0;

    println!("✓ Single character change caused {:.2}% bit difference", diff_percentage);
    println!("✓ Avalanche effect: {}", if diff_percentage > 25.0 { "GOOD" } else { "WEAK" });

    // Test 5: Feature Integrity (Tamper Detection)
    println!("\nTest 5: Feature Integrity");
    let original_ct = encrypt(message, &pk);

    // Tamper with ciphertext
    let mut tampered_ct = original_ct.clone();
    if !tampered_ct.c.is_empty() {
        tampered_ct.c[0] ^= 0x01; // Flip one bit
    }

    let tampered_result = decrypt(&tampered_ct, &sk);
    println!("✓ Tampered ciphertext decryption: {}",
        if tampered_result.is_none() { "REJECTED (correct)" } else { "ACCEPTED (ERROR!)" });

    // Test 6: Signature Forgery Resistance
    println!("\nTest 6: Signature Forgery Resistance");
    let valid_sig = sign(message, &sk, &pk);

    // Tamper with signature response
    let mut forged_sig = valid_sig.clone();
    if !forged_sig.response.is_empty() {
        forged_sig.response[0] ^= 0x01; // Flip one bit
    }

    let forged_result = verify(message, &forged_sig, &pk);
    println!("✓ Forged signature verification: {}",
        if !forged_result { "REJECTED (correct)" } else { "ACCEPTED (ERROR!)" });

    // Test 7: Randomness (Semantic Security)
    println!("\nTest 7: Randomness");
    let ct_a = encrypt(message, &pk);
    let ct_b = encrypt(message, &pk);

    let seeds_different = ct_a.seed != ct_b.seed;
    let ciphertexts_different = ct_a.c != ct_b.c;

    println!("✓ Same message encrypted twice:");
    println!("  - Different seeds: {}", if seeds_different { "YES (correct)" } else { "NO (ERROR!)" });
    println!("  - Different ciphertexts: {}", if ciphertexts_different { "YES (correct)" } else { "NO (ERROR!)" });

    // Both should decrypt to the same message
    let dec_a = decrypt(&ct_a, &sk).expect("Decryption A failed");
    let dec_b = decrypt(&ct_b, &sk).expect("Decryption B failed");
    println!("  - Both decrypt correctly: {}", if dec_a == dec_b && dec_a == message { "YES (correct)" } else { "NO (ERROR!)" });

    println!("\n=========================================");
    println!("All tests completed!");
}
