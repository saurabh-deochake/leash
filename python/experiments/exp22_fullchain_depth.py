#!/usr/bin/env python3
"""
Experiment 22: Full-Chain vs Immediate-Parent Verification by Depth

Motivation: Alg. VerifyAuth checks a single heartbeat, which suggests O(1)
verification, yet a compromised intermediate coordinator still holds its own
heartbeat signing key and keeps signing for its subtree -- so immediate-parent
verification cannot cascade a root kill past a compromised intermediate. LEASH
therefore offers two verification MODES, selected by threat model:

  * Immediate-parent (O(1) compute): the verifier checks only the child's
    direct-parent heartbeat. Cascade relies on each honest intermediate ceasing
    its own heartbeat once its own authentication lapses, so a root kill ripples
    down one W_max per level (cascade latency ~ d * W_max). Defends the
    operator-kill / crash / zombie threat (honest-but-halted intermediates).

  * Full-chain (O(d) compute): the child staples every ancestor's heartbeat and
    the verifier caches every ancestor heartbeat key. A root kill invalidates
    the child within a single W_max regardless of a compromised intermediate,
    because only the (dead) root can sign the root heartbeat. This is the NIST
    SP 800-207 "assume breach" tenet applied to a delegation chain.

This experiment quantifies the compute/proof-size cost of full-chain vs
immediate-parent verification as hierarchy depth d grows. Note the NETWORK cost
is zero round-trips in BOTH modes; only local compute differs. This resolves the
reported O(1)-vs-O(d) inconsistency: it is a mode distinction, not a bug.

Run with: python experiments/exp22_fullchain_depth.py
"""

import hashlib
import json
import os
import secrets
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leash.keys import AgentKeyPair, compute_heartbeat_binding
from leash.heartbeat import Heartbeat

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)


def build_chain(depth: int) -> list[AgentKeyPair]:
    """Root at index 0, leaf at index depth. Each node is a child of the prior."""
    chain = [AgentKeyPair.generate_root("L0-root")]
    for level in range(1, depth + 1):
        chain.append(chain[-1].derive_child(f"L{level}-agent"))
    return chain


def heartbeat_size_bytes(hb: Heartbeat) -> int:
    """On-the-wire heartbeat size (commitment + signature + pubkey + epoch)."""
    return len(hb.commitment) + len(hb.signature) + len(hb.parent_heartbeat_pubkey) + 8


def bench(depths=(1, 2, 3, 4, 5, 6, 7, 8), trials=200):
    """Benchmark the COMPLETE VerifyAuth path per Algorithm 3 of the paper:

      1. epoch freshness checks (integer compares, negligible)
      2. beacon signature verify   -- 1 in immediate mode, d in full-chain mode
      3. credential ISSUER verify  -- Verify(pk_p, id||pk_c||b, sigma_p), 1 in both
      4. binding hash compare      -- H(hpk_p||id) == cred.b, 1 in both
      5. possession verify         -- Verify(pk_c, c||e||sigma_h, sigma_c), 1 in both

    So immediate-parent = 3 ECDSA verifies + 1 hash, full-chain = d+2 verifies + 1 hash.
    """
    epoch = 1_000_000
    epoch_bytes = epoch.to_bytes(8, "big")
    rows = []
    for d in depths:
        chain = build_chain(d)
        # Ancestors that must be alive for the leaf to act: levels 0..d-1.
        ancestors = chain[:d]
        leaf = chain[d]
        parent = ancestors[-1]
        heartbeats = [Heartbeat.create(a.heartbeat_key, epoch) for a in ancestors]
        ancestor_hpks = [a.heartbeat_public_key() for a in ancestors]

        one_hb_bytes = heartbeat_size_bytes(heartbeats[-1])

        # Credential issuance (parent signs id || pk_c || binding) -- Algorithm in Sec 3.2.
        binding = compute_heartbeat_binding(parent.heartbeat_public_key(), leaf.agent_id)
        cred_msg = leaf.agent_id.encode() + leaf.public_key_bytes() + binding
        issuer_sig = parent.identity_key.sign(cred_msg)
        parent_ipk = parent.identity_public_key()
        leaf_ipk = leaf.identity_public_key()

        # Challenge-response possession proof (child signs c || e || sigma_h).
        challenge = secrets.token_bytes(32)
        parent_hb = heartbeats[-1]
        proof_data = challenge + epoch_bytes + parent_hb.signature
        possession_sig = leaf.identity_key.sign(proof_data)

        def constant_checks():
            """Per-proof checks shared by both modes (Alg. 3 lines 6-8)."""
            parent_ipk.verify(issuer_sig, cred_msg)                       # issuer
            expected = compute_heartbeat_binding(parent.heartbeat_public_key(), leaf.agent_id)
            assert expected == binding                                    # binding
            leaf_ipk.verify(possession_sig, proof_data)                   # possession

        # ---- Immediate-parent: ONE beacon verify + constant checks ----
        imm = []
        for _ in range(trials):
            hb = heartbeats[-1]
            hpk = ancestor_hpks[-1]
            t0 = time.perf_counter()
            hpk.verify(hb.signature, hb.commitment)
            constant_checks()
            imm.append((time.perf_counter() - t0) * 1000)

        # ---- Full-chain: ALL d ancestor beacon verifies + constant checks ----
        full = []
        for _ in range(trials):
            t0 = time.perf_counter()
            for hb, hpk in zip(heartbeats, ancestor_hpks):
                hpk.verify(hb.signature, hb.commitment)
            constant_checks()
            full.append((time.perf_counter() - t0) * 1000)

        rows.append({
            "depth": d,
            "immediate_verify_ms": round(statistics.mean(imm), 4),
            "fullchain_verify_ms": round(statistics.mean(full), 4),
            "fullchain_verify_p99_ms": round(sorted(full)[int(len(full) * 0.99) - 1], 4),
            "immediate_proof_bytes": one_hb_bytes,
            "fullchain_proof_bytes": one_hb_bytes * d,
            "immediate_ecdsa_verifies": 3,
            "fullchain_ecdsa_verifies": d + 2,
        })
        print(f"d={d}  immediate={rows[-1]['immediate_verify_ms']:.3f}ms (3 verifies) "
              f"full-chain={rows[-1]['fullchain_verify_ms']:.3f}ms ({d + 2} verifies)  "
              f"beacon staple: {one_hb_bytes}B -> {one_hb_bytes * d}B")

    return rows


def main():
    print("=" * 70)
    print("Experiment 22: Full-Chain vs Immediate-Parent Verification by Depth")
    print("=" * 70)
    rows = bench()

    # Linearity check: full-chain verify time should scale ~linearly with depth.
    d1 = next(r for r in rows if r["depth"] == 1)["fullchain_verify_ms"]
    d8 = next(r for r in rows if r["depth"] == 8)["fullchain_verify_ms"]
    ratio = round(d8 / d1, 2) if d1 else None

    out = {
        "experiment": "exp22_fullchain_depth",
        "description": "Full-chain (O(d)) vs immediate-parent (O(1)) verification "
                       "cost by hierarchy depth, measuring the COMPLETE VerifyAuth "
                       "path (beacon + credential-issuer + possession verifies, "
                       "binding hash). Network cost is zero round-trips in both "
                       "modes; only local compute differs.",
        "primitives": "ECDSA-secp256k1 heartbeat signatures",
        "curve": "secp256k1",
        "results": rows,
        "fullchain_scaling_d8_over_d1": ratio,
        "notes": {
            "immediate_parent": "O(1) compute; cascade latency ~ d*W_max; assumes "
                                "honest-but-halted intermediates (zombie threat).",
            "full_chain": "O(d) compute; cascade latency ~ W_max at every level; "
                          "defends compromised intermediates (assume-breach).",
            "network": "Both modes require ZERO network round-trips to verify.",
        },
    }
    out_path = os.path.join(RESULTS_DIR, "exp22_fullchain_depth.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nFull-chain scaling (d=8 / d=1): {ratio}x  (expected ~8x -> linear in d)")
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
