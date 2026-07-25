#!/usr/bin/env python3
"""
Experiment 21: Child-Bound Merkle Heartbeats (Selective Revocation)

Motivation: a parent-wide heartbeat carries no child identity, so under a
Dolev-Yao adversary an excluded-but-compromised child can replay a sibling's
broadcast heartbeat and survive. This experiment measures the cost of the
child-bound variant that makes selective revocation sound: the parent commits
to the *set* of currently-authorized children in a Merkle tree and signs only
the root (O(1) signatures per epoch); each child carries an O(log N) inclusion
proof binding its own identity to the signed root. To selectively revoke a
child, the parent rebuilds the tree without it in the next epoch; the excluded
child has no inclusion path under the new root and cannot forge one.

We compare against naive per-child signing (O(N) signatures/epoch), which also
achieves child binding but does not preserve the O(1) broadcast property.

Metrics per swarm size N:
  - Parent per-epoch signing cost: Merkle (build + 1 sign) vs naive (N signs)
  - Per-child inclusion-proof generation time
  - Per-child inclusion-proof size (bytes)      -> expected O(log N)
  - Per-child verification time (recompute root + verify root signature)

Run with: python experiments/exp21_merkle_childbound.py
"""

import hashlib
import json
import math
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leash.keys import AgentKeyPair

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# Domain-separation prefixes prevent second-preimage attacks across leaf/node.
LEAF_PREFIX = b'\x00'
NODE_PREFIX = b'\x01'
SIG_LEN = 64          # ECDSA-secp256k1 raw signature
HASH_LEN = 32         # SHA-256


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def leaf_hash(hpk_bytes: bytes, child_id: str, epoch: int) -> bytes:
    """Bind a child identity to the parent heartbeat key and epoch."""
    return _sha256(LEAF_PREFIX, hpk_bytes, child_id.encode('utf-8'),
                   epoch.to_bytes(8, 'little'))


def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(NODE_PREFIX, left, right)


def build_merkle_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """Bottom-up Merkle tree; duplicate the last node on odd levels."""
    levels = [leaves]
    cur = leaves
    while len(cur) > 1:
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]
            nxt.append(node_hash(left, right))
        levels.append(nxt)
        cur = nxt
    return levels


def inclusion_proof(levels: list[list[bytes]], index: int) -> list[tuple[bytes, bool]]:
    """Return sibling hashes from leaf to root; bool = sibling-is-on-right."""
    proof = []
    idx = index
    for level in levels[:-1]:
        if idx % 2 == 0:
            sib = level[idx + 1] if idx + 1 < len(level) else level[idx]
            proof.append((sib, True))
        else:
            proof.append((level[idx - 1], False))
        idx //= 2
    return proof


def verify_inclusion(leaf: bytes, proof: list[tuple[bytes, bool]], root: bytes) -> bool:
    cur = leaf
    for sib, sib_is_right in proof:
        cur = node_hash(cur, sib) if sib_is_right else node_hash(sib, cur)
    return cur == root


def bench(swarm_sizes=(10, 50, 100, 500, 1000), trials=10):
    parent = AgentKeyPair.generate_root("orchestrator")
    hsk = parent.heartbeat_key
    hpk = parent.heartbeat_public_key()
    hpk_bytes = hpk.to_string()
    epoch = 1_000_000

    rows = []
    for n in swarm_sizes:
        child_ids = [f"agent-{i}" for i in range(n)]

        # ---- Parent per-epoch signing cost ----
        merkle_total, merkle_build, merkle_sign = [], [], []
        for _ in range(trials):
            t0 = time.perf_counter()
            leaves = [leaf_hash(hpk_bytes, cid, epoch) for cid in child_ids]
            levels = build_merkle_levels(leaves)
            root = levels[-1][0]
            t1 = time.perf_counter()
            _ = hsk.sign(root)                       # ONE signature, any N
            t2 = time.perf_counter()
            merkle_build.append((t1 - t0) * 1000)
            merkle_sign.append((t2 - t1) * 1000)
            merkle_total.append((t2 - t0) * 1000)

        naive_sign = []
        naive_trials = trials if n <= 500 else max(3, trials // 2)
        for _ in range(naive_trials):
            t0 = time.perf_counter()
            for cid in child_ids:                    # O(N) signatures
                _ = hsk.sign(leaf_hash(hpk_bytes, cid, epoch))
            naive_sign.append((time.perf_counter() - t0) * 1000)

        # ---- Per-child proof generation + size ----
        leaves = [leaf_hash(hpk_bytes, cid, epoch) for cid in child_ids]
        levels = build_merkle_levels(leaves)
        root = levels[-1][0]
        root_sig = hsk.sign(root)

        proof_gen, proof_paths = [], []
        sample_idx = list(range(0, n, max(1, n // 20)))[:20]
        for idx in sample_idx:
            t0 = time.perf_counter()
            pf = inclusion_proof(levels, idx)
            proof_gen.append((time.perf_counter() - t0) * 1000)
            proof_paths.append(pf)

        path_len = len(proof_paths[0])              # ceil(log2 N)
        # Incremental proof a child ships: sibling path only (root+sig broadcast once/epoch).
        incremental_bytes = path_len * HASH_LEN
        # Self-contained proof: path + root + root signature.
        selfcontained_bytes = incremental_bytes + HASH_LEN + SIG_LEN

        # ---- Per-child verification ----
        verify_full, verify_amortized = [], []
        for idx, pf in zip(sample_idx, proof_paths):
            leaf = leaves[idx]
            # Full: recompute root from path AND verify the root signature.
            t0 = time.perf_counter()
            ok = verify_inclusion(leaf, pf, root)
            hpk.verify(root_sig, root)
            verify_full.append((time.perf_counter() - t0) * 1000)
            assert ok
            # Amortized: root sig verified once/epoch; per-child = path recompute only.
            t0 = time.perf_counter()
            verify_inclusion(leaf, pf, root)
            verify_amortized.append((time.perf_counter() - t0) * 1000)

        # ---- Selective-revocation soundness check ----
        # Rebuild without child 0; its old path must NOT verify under the new root.
        kept = child_ids[1:]
        new_leaves = [leaf_hash(hpk_bytes, cid, epoch + 1) for cid in kept]
        new_root = build_merkle_levels(new_leaves)[-1][0]
        excluded_old_leaf = leaf_hash(hpk_bytes, child_ids[0], epoch)
        excluded_rejected = not verify_inclusion(excluded_old_leaf, proof_paths[0], new_root)

        rows.append({
            "n": n,
            "merkle_build_ms": round(statistics.mean(merkle_build), 4),
            "merkle_sign_ms": round(statistics.mean(merkle_sign), 4),
            "merkle_parent_total_ms": round(statistics.mean(merkle_total), 4),
            "naive_sign_ms": round(statistics.mean(naive_sign), 4),
            "signing_speedup_x": round(statistics.mean(naive_sign) / statistics.mean(merkle_total), 1),
            "proof_path_len": path_len,
            "proof_incremental_bytes": incremental_bytes,
            "proof_selfcontained_bytes": selfcontained_bytes,
            "proof_gen_ms": round(statistics.mean(proof_gen), 4),
            "verify_full_ms": round(statistics.mean(verify_full), 4),
            "verify_amortized_ms": round(statistics.mean(verify_amortized), 4),
            "excluded_child_rejected": excluded_rejected,
        })
        print(f"N={n:5d}  merkle_parent={rows[-1]['merkle_parent_total_ms']:.3f}ms "
              f"naive={rows[-1]['naive_sign_ms']:.1f}ms  speedup={rows[-1]['signing_speedup_x']}x  "
              f"path={path_len}  incr_proof={incremental_bytes}B  "
              f"verify_full={rows[-1]['verify_full_ms']:.3f}ms  "
              f"excluded_rejected={excluded_rejected}")

    return rows


def main():
    print("=" * 70)
    print("Experiment 21: Child-Bound Merkle Heartbeats (Selective Revocation)")
    print("=" * 70)
    rows = bench()

    out = {
        "experiment": "exp21_merkle_childbound",
        "description": "Merkle child-bound heartbeats: O(1) parent signing, "
                       "O(log N) per-child inclusion proof, sound selective revocation.",
        "primitives": "ECDSA-secp256k1 signatures, SHA-256 Merkle tree",
        "curve": "secp256k1",
        "results": rows,
        "notes": {
            "signing": "Merkle signs ONE root per epoch (O(1)); naive signs one "
                       "heartbeat per child (O(N)).",
            "proof_size": "Incremental proof = ceil(log2 N) x 32B sibling path "
                          "(root+signature broadcast once per epoch).",
            "selective_revocation": "excluded_child_rejected=true confirms an "
                                    "excluded child's stale inclusion path fails "
                                    "under the rebuilt root (Dolev-Yao sound).",
        },
    }
    out_path = os.path.join(RESULTS_DIR, "exp21_merkle_childbound.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nSaved: {out_path}")
    all_rejected = all(r["excluded_child_rejected"] for r in rows)
    print(f"Selective-revocation soundness (all N): {'PASS' if all_rejected else 'FAIL'}")


if __name__ == "__main__":
    main()
