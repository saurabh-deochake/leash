use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use serde::Serialize;
use std::time::Instant;

/// Experiment 3 (Rust): Per-operation cryptographic latency benchmark.
/// Measures each LEASH operation individually over 100 iterations,
/// reporting mean, std, and P99 in milliseconds.

const ITERATIONS: usize = 100;

#[derive(Serialize)]
struct OpResult {
    operation: String,
    mean_ms: f64,
    std_ms: f64,
    p99_ms: f64,
}

fn measure<F: FnMut()>(mut f: F) -> Vec<f64> {
    // Warmup
    for _ in 0..10 {
        f();
    }
    let mut latencies = Vec::with_capacity(ITERATIONS);
    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        f();
        let elapsed_ms = t0.elapsed().as_nanos() as f64 / 1_000_000.0;
        latencies.push(elapsed_ms);
    }
    latencies
}

fn stats(latencies: &[f64]) -> (f64, f64, f64) {
    let n = latencies.len() as f64;
    let mean = latencies.iter().sum::<f64>() / n;
    let variance = latencies.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let std = variance.sqrt();
    let mut sorted = latencies.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p99_idx = ((sorted.len() as f64) * 0.99) as usize;
    let p99 = sorted[p99_idx.min(sorted.len() - 1)];
    (mean, std, p99)
}

fn main() {
    let mut results: Vec<OpResult> = Vec::new();

    // 1. Key Generation
    let lats = measure(|| {
        let _sk = SigningKey::random(&mut OsRng);
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Key Generation:      mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Key Generation".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    // 2. Child Derivation (key gen + binding hash)
    let parent_sk = SigningKey::random(&mut OsRng);
    let parent_vk = VerifyingKey::from(&parent_sk);
    let lats = measure(|| {
        let child_sk = SigningKey::random(&mut OsRng);
        let _child_vk = VerifyingKey::from(&child_sk);
        let parent_pub = parent_vk.to_sec1_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&parent_pub);
        hasher.update(b"child-0");
        let _binding: [u8; 32] = hasher.finalize().into();
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Child Derivation:    mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Child Derivation".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    // 3. Heartbeat Generation (commitment + ECDSA sign)
    let lats = measure(|| {
        let epoch = 1000u64;
        let mut hasher = Sha256::new();
        hasher.update(epoch.to_be_bytes());
        hasher.update(b"heartbeat");
        let commitment: [u8; 32] = hasher.finalize().into();
        let mut sign_data = Vec::with_capacity(40);
        sign_data.extend_from_slice(&epoch.to_be_bytes());
        sign_data.extend_from_slice(&commitment);
        let _sig: Signature = parent_sk.sign(&sign_data);
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Heartbeat Gen:       mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Heartbeat Gen".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    // 4. Heartbeat Verify (ECDSA verify + freshness check)
    let epoch = 1000u64;
    let mut hasher = Sha256::new();
    hasher.update(epoch.to_be_bytes());
    hasher.update(b"heartbeat");
    let commitment: [u8; 32] = hasher.finalize().into();
    let mut sign_data = Vec::with_capacity(40);
    sign_data.extend_from_slice(&epoch.to_be_bytes());
    sign_data.extend_from_slice(&commitment);
    let hb_sig: Signature = parent_sk.sign(&sign_data);

    let lats = measure(|| {
        // Freshness check
        let current_epoch = 1000u64;
        let age = current_epoch - epoch;
        assert!(age <= 3);
        // Signature verify
        let mut sd = Vec::with_capacity(40);
        sd.extend_from_slice(&epoch.to_be_bytes());
        sd.extend_from_slice(&commitment);
        parent_vk.verify(&sd, &hb_sig).unwrap();
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Heartbeat Verify:    mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Heartbeat Verify".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    // 5. Credential Creation (hash only)
    let lats = measure(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"parent-pub-key-placeholder");
        hasher.update(b"child-0");
        hasher.update(b"role:worker");
        let _cred_hash: [u8; 32] = hasher.finalize().into();
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Credential Creation: mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Credential Creation".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    // 6. Proof Creation (challenge hash + ECDSA sign)
    let child_sk = SigningKey::random(&mut OsRng);
    let child_vk = VerifyingKey::from(&child_sk);
    let parent_pub = parent_vk.to_sec1_bytes();
    let mut bh = Sha256::new();
    bh.update(&parent_pub);
    bh.update(b"child-0");
    let binding_hash: [u8; 32] = bh.finalize().into();

    let lats = measure(|| {
        let mut ch = Sha256::new();
        ch.update(epoch.to_be_bytes());
        ch.update(b"challenge-nonce");
        let challenge: [u8; 32] = ch.finalize().into();

        let mut proof_data = Vec::with_capacity(128);
        proof_data.extend_from_slice(&binding_hash);
        proof_data.extend_from_slice(&epoch.to_be_bytes());
        proof_data.extend_from_slice(&commitment);
        proof_data.extend_from_slice(&challenge);
        let _proof_sig: Signature = child_sk.sign(&proof_data);
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Proof Creation:      mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Proof Creation".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    // 7. Full Verification (heartbeat verify + proof verify + binding check)
    let mut ch = Sha256::new();
    ch.update(epoch.to_be_bytes());
    ch.update(b"challenge-nonce");
    let challenge: [u8; 32] = ch.finalize().into();
    let mut proof_data = Vec::with_capacity(128);
    proof_data.extend_from_slice(&binding_hash);
    proof_data.extend_from_slice(&epoch.to_be_bytes());
    proof_data.extend_from_slice(&commitment);
    proof_data.extend_from_slice(&challenge);
    let proof_sig: Signature = child_sk.sign(&proof_data);

    let lats = measure(|| {
        // Heartbeat freshness
        let current_epoch = 1000u64;
        let age = current_epoch - epoch;
        assert!(age <= 3);

        // Heartbeat signature verify
        let mut sd = Vec::with_capacity(40);
        sd.extend_from_slice(&epoch.to_be_bytes());
        sd.extend_from_slice(&commitment);
        parent_vk.verify(&sd, &hb_sig).unwrap();

        // Proof signature verify
        child_vk.verify(&proof_data, &proof_sig).unwrap();

        // Binding check
        let ppub = parent_vk.to_sec1_bytes();
        let mut bhasher = Sha256::new();
        bhasher.update(&ppub);
        bhasher.update(b"child-0");
        let expected: [u8; 32] = bhasher.finalize().into();
        assert_eq!(expected, binding_hash);
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Full Verification:   mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Full Verification".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    // 8. Auth Flow Total (HB gen + proof create + full verify)
    let lats = measure(|| {
        // HB gen
        let ep = 1000u64;
        let mut h = Sha256::new();
        h.update(ep.to_be_bytes());
        h.update(b"heartbeat");
        let comm: [u8; 32] = h.finalize().into();
        let mut sd = Vec::with_capacity(40);
        sd.extend_from_slice(&ep.to_be_bytes());
        sd.extend_from_slice(&comm);
        let hb_s: Signature = parent_sk.sign(&sd);

        // Proof create
        let mut ch2 = Sha256::new();
        ch2.update(ep.to_be_bytes());
        ch2.update(b"challenge-nonce");
        let chal: [u8; 32] = ch2.finalize().into();
        let mut pd = Vec::with_capacity(128);
        pd.extend_from_slice(&binding_hash);
        pd.extend_from_slice(&ep.to_be_bytes());
        pd.extend_from_slice(&comm);
        pd.extend_from_slice(&chal);
        let ps: Signature = child_sk.sign(&pd);

        // Full verify
        let current = 1000u64;
        let age = current - ep;
        assert!(age <= 3);
        let mut sv = Vec::with_capacity(40);
        sv.extend_from_slice(&ep.to_be_bytes());
        sv.extend_from_slice(&comm);
        parent_vk.verify(&sv, &hb_s).unwrap();
        child_vk.verify(&pd, &ps).unwrap();
        let ppub = parent_vk.to_sec1_bytes();
        let mut bh2 = Sha256::new();
        bh2.update(&ppub);
        bh2.update(b"child-0");
        let exp2: [u8; 32] = bh2.finalize().into();
        assert_eq!(exp2, binding_hash);
    });
    let (mean, std, p99) = stats(&lats);
    eprintln!("Auth Flow Total:     mean={mean:.4}ms  std={std:.4}ms  p99={p99:.4}ms");
    results.push(OpResult {
        operation: "Auth Flow Total".into(),
        mean_ms: (mean * 10000.0).round() / 10000.0,
        std_ms: (std * 10000.0).round() / 10000.0,
        p99_ms: (p99 * 10000.0).round() / 10000.0,
    });

    let json = serde_json::to_string_pretty(&results).unwrap();
    println!("{json}");
}
