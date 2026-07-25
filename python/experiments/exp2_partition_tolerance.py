#!/usr/bin/env python3
"""
Experiment 2: Verify revocation works during network partition.

Hypothesis: Child agents cannot authenticate after heartbeat expires,
even when completely partitioned from all authorities.

Run with: python experiments/exp2_partition_tolerance.py
"""

import time
import sys
sys.path.insert(0, '..')

from leash import LeashConfig, Verifier
from leash.keys import AgentKeyPair
from leash.heartbeat import Heartbeat
from leash.credentials import CredentialBuilder, CredentialProof
from leash.verification import generate_challenge


def simulate_partition_scenario():
    print("=" * 60)
    print("EXPERIMENT 2: Partition Tolerance")
    print("=" * 60)
    print("\nHypothesis: Revocation works even when child is completely")
    print("partitioned from all central authorities.\n")
    
    config = LeashConfig(heartbeat_interval_secs=2, max_heartbeat_age_secs=6)
    
    # Setup
    parent = AgentKeyPair.generate_root("parent")
    child = parent.derive_child("child")
    
    # Verifier is COMPLETELY ISOLATED - no connection to parent
    # This simulates a resource server in a partitioned network segment
    isolated_verifier = Verifier(config)
    isolated_verifier.trust_parent("parent", parent.heartbeat_public_key())
    
    credential = CredentialBuilder().build(child, parent.heartbeat_public_key())
    
    # Child has ONE heartbeat from before partition
    pre_partition_heartbeat = Heartbeat.create(
        parent.heartbeat_key, 
        isolated_verifier.current_epoch()
    )
    
    print("Scenario Setup:")
    print("-" * 40)
    print("1. Parent creates child with credential")
    print("2. Child receives ONE heartbeat")
    print("3. Network PARTITIONS - child and verifier isolated")
    print("4. Parent is REVOKED (stops heartbeats)")
    print("5. Question: Can child still authenticate?")
    print("-" * 40)
    
    print("\nTime | Heartbeat Age | Auth Result | Notes")
    print("-" * 60)
    
    challenge = generate_challenge()
    start_time = time.time()
    
    auth_succeeded = 0
    auth_failed = 0
    
    for i in range(10):
        current_epoch = isolated_verifier.current_epoch()
        heartbeat_age = current_epoch - pre_partition_heartbeat.epoch
        
        proof = CredentialProof.create(
            credential, pre_partition_heartbeat, challenge, child.identity_key
        )
        result = isolated_verifier.verify(proof, challenge)
        
        if result.valid:
            status = "✓ SUCCESS"
            note = "(zombie - stale heartbeat still valid)"
            auth_succeeded += 1
        else:
            status = "✗ DENIED"
            note = "(heartbeat expired)"
            auth_failed += 1
        
        print(f"{i}s   | {heartbeat_age} epochs       | {status:12} | {note}")
        
        time.sleep(1)
    
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    
    print(f"\nAuthentication attempts: {auth_succeeded + auth_failed}")
    print(f"  Succeeded (zombie): {auth_succeeded}")
    print(f"  Denied (revoked):   {auth_failed}")
    
    max_age_epochs = config.max_age_epochs()
    expected_zombie = max_age_epochs + 1  # +1 for partial epoch
    
    print(f"\nExpected zombie window: ~{expected_zombie} epochs")
    print(f"Observed zombie window: {auth_succeeded} epochs")
    
    if auth_failed > 0:
        print("\n✓ HYPOTHESIS CONFIRMED")
        print("  Revocation worked WITHOUT any network connectivity!")
        print("  The verifier denied access based solely on heartbeat age.")
        print("  No communication with parent or central authority was needed.")
    else:
        print("\n⚠ Test duration too short to observe revocation")
    
    print("\n" + "-" * 60)
    print("KEY INSIGHT:")
    print("  Traditional systems (OAuth, OCSP) would FAIL here because")
    print("  they need network to check revocation status.")
    print("  LEASH works because revocation is IMPLICIT in heartbeat expiry.")
    print("-" * 60)


if __name__ == "__main__":
    simulate_partition_scenario()
