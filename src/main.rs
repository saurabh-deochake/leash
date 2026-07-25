//! LEASH Demo Application
//!
//! Demonstrates the Liveness-Enforced Authorization for Swarm Hierarchies.

use leash::{
    keys::{AgentKeyPair, KeyHierarchy},
    heartbeat::{HeartbeatGenerator, HeartbeatCache, Heartbeat},
    credentials::{CredentialBuilder, CredentialProof},
    verification::{Verifier, ChallengeBuilder},
    LeashConfig,
};

fn main() -> anyhow::Result<()> {
    println!("=== LEASH Demo ===\n");

    // Configuration
    let config = LeashConfig {
        heartbeat_interval_secs: 10,
        max_heartbeat_age_secs: 30,
        ..Default::default()
    };

    // 1. Create parent agent (e.g., command center)
    println!("1. Creating parent agent hierarchy...");
    let mut hierarchy = KeyHierarchy::new("command-center")?;
    println!("   Parent agent ID: {}", hierarchy.root.agent_id);

    // 2. Derive child agents (e.g., drones)
    println!("\n2. Deriving child agent credentials...");
    let child_ids = ["drone-alpha", "drone-beta", "drone-gamma"];
    
    for child_id in &child_ids {
        hierarchy.add_child(child_id)?;
        println!("   Created child: {}", child_id);
    }

    // 3. Create heartbeat generator for parent
    println!("\n3. Starting heartbeat generation...");
    let mut heartbeat_gen = HeartbeatGenerator::new(
        hierarchy.root.heartbeat_key.clone(),
        config.clone(),
    );
    
    let heartbeat = heartbeat_gen.generate();
    println!("   Generated heartbeat for epoch: {}", heartbeat.epoch);

    // 4. Issue credentials to children
    println!("\n4. Issuing credentials to child agents...");
    let child = hierarchy.get_child("drone-alpha").unwrap();
    
    let credential = CredentialBuilder::new()
        .with_scope("survey")
        .with_scope("report")
        .with_attribute("mission", "disaster-response")
        .with_max_delegation_depth(2)
        .build(child, &hierarchy.root.heartbeat_public_key());
    
    println!("   Issued credential to: {}", credential.agent_id);
    println!("   Scopes: {:?}", credential.metadata.scopes);

    // 5. Child receives heartbeat and creates auth proof
    println!("\n5. Child agent creating authentication proof...");
    let mut child_cache = HeartbeatCache::new(config.clone(), 10);
    child_cache.add(heartbeat.clone());
    
    let challenge = ChallengeBuilder::new()
        .for_resource("/api/survey-data")
        .for_action("submit")
        .build();
    
    let proof = CredentialProof::new(
        credential.clone(),
        heartbeat.clone(),
        &challenge,
        &child.identity_key,
    );
    println!("   Proof created with heartbeat epoch: {}", proof.heartbeat_epoch());

    // 6. Verifier validates the proof
    println!("\n6. Resource server verifying proof...");
    let mut verifier = Verifier::new(config.clone());
    verifier.trust_parent("command-center", hierarchy.root.heartbeat_public_key());
    
    match verifier.verify(&proof, &challenge) {
        Ok(result) => {
            println!("   ✓ Verification SUCCESSFUL");
            println!("   Agent: {}", result.agent_id);
            println!("   Scopes: {:?}", result.scopes);
            println!("   Heartbeat epoch: {} (current: {})", 
                result.heartbeat_epoch, result.current_epoch);
            if !result.warnings.is_empty() {
                println!("   Warnings: {:?}", result.warnings);
            }
        }
        Err(e) => {
            println!("   ✗ Verification FAILED: {}", e);
        }
    }

    // 7. Demonstrate revocation (parent stops heartbeats)
    println!("\n7. Simulating parent revocation (stale heartbeat)...");
    
    // Create a proof with an old heartbeat
    let old_heartbeat = Heartbeat::new(
        &hierarchy.root.heartbeat_key,
        heartbeat_gen.current_epoch().saturating_sub(10), // 10 epochs ago
    );
    
    let old_proof = CredentialProof::new(
        credential,
        old_heartbeat,
        &challenge,
        &child.identity_key,
    );
    
    match verifier.verify(&old_proof, &challenge) {
        Ok(_) => {
            println!("   Verification succeeded (unexpected)");
        }
        Err(e) => {
            println!("   ✓ Verification FAILED as expected: {}", e);
            println!("   → Child credential is effectively REVOKED");
        }
    }

    // 8. Demonstrate pre-generation for planned disconnection
    println!("\n8. Pre-generating heartbeats for planned disconnection...");
    let pregenerated = heartbeat_gen.pregenerate(6); // 1 minute of heartbeats
    println!("   Pre-generated {} heartbeats for future epochs", pregenerated.len());
    for hb in pregenerated {
        println!("   - Epoch {}", hb.epoch);
    }

    println!("\n=== Demo Complete ===");
    println!("\nKey Takeaways:");
    println!("• Child credentials are cryptographically bound to parent heartbeats");
    println!("• When parent stops generating heartbeats, children cannot authenticate");
    println!("• No network connectivity required for revocation to take effect");
    println!("• Zombie window is bounded by max_heartbeat_age ({} seconds)", 
        config.max_heartbeat_age_secs);

    Ok(())
}
