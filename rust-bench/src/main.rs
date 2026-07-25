use actix_web::{web, App, HttpServer, HttpResponse, get, post};
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};
use sha2::{Sha256, Digest};
use rand::rngs::OsRng;
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

/// Minimal LEASH verification replica in Rust.
/// Mirrors the Python implementation's verification flow:
///   1. Parent generates heartbeat (epoch + commitment + ECDSA signature)
///   2. Child creates proof (credential + heartbeat + challenge + signature)
///   3. Verifier checks: heartbeat signature, heartbeat freshness, proof signature, binding

#[derive(Clone)]
struct LeashState {
    parent_signing: Arc<SigningKey>,
    parent_verifying: Arc<VerifyingKey>,
    child_signing: Arc<SigningKey>,
    child_verifying: Arc<VerifyingKey>,
    binding_hash: [u8; 32],
    max_age_epochs: u64,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    latency_us: f64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
}

fn create_heartbeat(state: &LeashState, epoch: u64) -> (u64, [u8; 32], Signature) {
    // Commitment = SHA256(epoch || "heartbeat")
    let mut hasher = Sha256::new();
    hasher.update(epoch.to_be_bytes());
    hasher.update(b"heartbeat");
    let commitment: [u8; 32] = hasher.finalize().into();

    // Sign the heartbeat
    let mut sign_data = Vec::with_capacity(40);
    sign_data.extend_from_slice(&epoch.to_be_bytes());
    sign_data.extend_from_slice(&commitment);
    let signature: Signature = state.parent_signing.sign(&sign_data);

    (epoch, commitment, signature)
}

fn verify_heartbeat(
    state: &LeashState,
    epoch: u64,
    commitment: &[u8; 32],
    signature: &Signature,
    current_epoch: u64,
) -> bool {
    // Check freshness
    if current_epoch < epoch {
        return false; // Future heartbeat
    }
    let age = current_epoch - epoch;
    if age > state.max_age_epochs {
        return false; // Stale
    }

    // Verify signature
    let mut sign_data = Vec::with_capacity(40);
    sign_data.extend_from_slice(&epoch.to_be_bytes());
    sign_data.extend_from_slice(commitment);
    state.parent_verifying.verify(&sign_data, signature).is_ok()
}

fn create_and_verify_proof(state: &LeashState) -> bool {
    let current_epoch = 1000u64;

    // 1. Parent generates heartbeat
    let (hb_epoch, commitment, hb_sig) = create_heartbeat(state, current_epoch);

    // 2. Generate challenge
    let mut hasher = Sha256::new();
    hasher.update(current_epoch.to_be_bytes());
    hasher.update(b"challenge-nonce");
    let challenge: [u8; 32] = hasher.finalize().into();

    // 3. Child signs proof (credential + heartbeat + challenge)
    let mut proof_data = Vec::with_capacity(128);
    proof_data.extend_from_slice(&state.binding_hash);
    proof_data.extend_from_slice(&hb_epoch.to_be_bytes());
    proof_data.extend_from_slice(&commitment);
    proof_data.extend_from_slice(&challenge);
    let proof_sig: Signature = state.child_signing.sign(&proof_data);

    // 4. Verifier checks everything
    // 4a. Heartbeat freshness + signature
    if !verify_heartbeat(state, hb_epoch, &commitment, &hb_sig, current_epoch) {
        return false;
    }

    // 4b. Proof signature
    if state.child_verifying.verify(&proof_data, &proof_sig).is_err() {
        return false;
    }

    // 4c. Binding check (child bound to parent's heartbeat key)
    let parent_pub_bytes = state.parent_verifying.to_sec1_bytes();
    let mut bind_hasher = Sha256::new();
    bind_hasher.update(&parent_pub_bytes);
    bind_hasher.update(b"child-0");
    let expected_binding: [u8; 32] = bind_hasher.finalize().into();
    if expected_binding != state.binding_hash {
        return false;
    }

    true
}

#[post("/verify")]
async fn verify_endpoint(state: web::Data<LeashState>) -> HttpResponse {
    let t0 = Instant::now();
    let valid = create_and_verify_proof(&state);
    let elapsed_us = t0.elapsed().as_nanos() as f64 / 1000.0;

    HttpResponse::Ok().json(VerifyResponse {
        valid,
        latency_us: (elapsed_us * 100.0).round() / 100.0,
    })
}

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok".to_string(),
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Pre-initialize crypto fixtures
    let parent_sk = SigningKey::random(&mut OsRng);
    let parent_vk = VerifyingKey::from(&parent_sk);
    let child_sk = SigningKey::random(&mut OsRng);
    let child_vk = VerifyingKey::from(&child_sk);

    // Compute binding hash
    let parent_pub_bytes = parent_vk.to_sec1_bytes();
    let mut bind_hasher = Sha256::new();
    bind_hasher.update(&parent_pub_bytes);
    bind_hasher.update(b"child-0");
    let binding_hash: [u8; 32] = bind_hasher.finalize().into();

    let state = LeashState {
        parent_signing: Arc::new(parent_sk),
        parent_verifying: Arc::new(parent_vk),
        child_signing: Arc::new(child_sk),
        child_verifying: Arc::new(child_vk),
        binding_hash,
        max_age_epochs: 3,
    };

    let port = 18924u16;
    eprintln!("LEASH Rust verification server starting on port {port}");

    let workers = num_cpus::get();
    eprintln!("Workers: {workers}");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(verify_endpoint)
            .service(health)
    })
    .workers(workers)
    .backlog(2048)
    .max_connections(10_000)
    .keep_alive(actix_web::http::KeepAlive::Os)
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
