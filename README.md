# LEASH: Zero-Trust Containment for AI Agent Swarms

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22775602.svg)](https://doi.org/10.5281/zenodo.22775602)

Artifact accompanying the AISec 2026 (ACM CCS) paper.

LEASH (Liveness-Enforced Authorization for Swarm Hierarchies) binds the
validity of a child agent's credential to a fresh, signed liveness beacon
from its parent. When the parent stops beaconing — operator kill, safety
shutdown, or crash — every descendant fails closed within a provably
bounded window, verified offline at the enforcement point with only cached
public keys and a local clock.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Rust reference implementation (`k256`): key derivation, beacon generation, `VerifyAuth`, actix-web PEP |
| `rust-bench/` | Rust criterion benchmark harness (core crypto, scalability, HTTP PEP) |
| `python/leash/` | Python reference implementation (keys, beacons, credentials, verification) |
| `python/experiments/` | Numbered experiment scripts (`exp1`–`exp22`) driving every table and figure |
| `python/examples/` | Framework integration examples (LangChain-/LangGraph-style agents) |
| `python/tests/` | Unit tests |
| `results/` | Raw JSON outputs backing every number reported in the paper |

## Setup

Python (3.10+):

```bash
cd python
python -m venv venv && source venv/bin/activate
pip install -e .
python experiments/exp22_fullchain_depth.py   # no API key needed
```

Rust (1.75+):

```bash
cargo build --release
cd rust-bench && cargo run --release
```

The real-LLM experiments (exp11–exp17) call GPT-4o-mini through an
OpenAI-compatible gateway; set `OPENAI_API_KEY` (and optionally
`OPENAI_BASE_URL`) to re-run them. All other experiments are fully local.

## Experiment-to-paper mapping

| Experiment | Paper location | What it produces |
|---|---|---|
| `exp1_zombie_window` | §4 (validates Theorem 1) | Zombie-window bound sanity check |
| `exp2_partition_tolerance` | Appendix C | Authentication under total partition |
| `exp3_performance` (+ Rust) | §6.2.1 | Core-crypto operation latencies |
| `exp4_baseline_comparison` | §6.1.2 baseline | OAuth bearer-token comparison harness |
| `exp5_extreme_edge_cases` | supplementary | Boundary-epoch edge cases |
| `exp6_scalability` (+ Rust) | §6.2.1 | Flat per-verification latency, 10–1,000 agents |
| `exp7_packet_loss` | Table 7, Table 8, Appendix C | False-denial rate vs. loss; W_max knee |
| `exp8_clock_skew` | Appendix C | Two-sided freshness regimes under skew |
| `exp9_concurrent_http` / `exp9_rust_http_bench` | §6.2.1, Appendix C | PEP throughput; WAN/`tc netem` runs |
| `exp11_real_llm_overhead` | §6.1.1, Table 4 | Per-task auth overhead (0.71% end-to-end) |
| `exp12_zombie_demo` | §6.1.2, Fig. 4 (left) | Post-kill calls, OAuth vs. LEASH |
| `exp13_multi_framework` | §6.1.6 | 14–18-line integrations, revocation correct |
| `exp14_prompt_injection` | §6.1.3, Fig. 4 (right) | Guardrail bypass vs. LEASH containment |
| `exp15_cascading_revocation` | §6.1.4, Fig. 5 | 49-agent, 4-level cascade within bound |
| `exp16_credential_theft` | §6.1.5 | 295x exposure reduction vs. OAuth |
| `exp17_long_running` | §6.1.6 | 300 s soak: stability, P99, zero false denials |
| `exp18_scalability_10k` | §6.2.2, Appendix C | 10,000-agent derivation/beacon/verify scale |
| `exp19_gossip_fprr` | supplementary | Gossip-based beacon distribution study |
| `exp20_monotonic_epoch` | Appendix C | Monotonic sequence-counter variant |
| `exp21_merkle_childbound` | §6.2, Table 5 | Child-bound Merkle beacons: O(1) sign, O(log N) proofs |
| `exp22_fullchain_depth` | §6.2.3, Table 6 | Full VerifyAuth path: immediate-parent vs. full-chain by depth |

Raw outputs for each experiment are in `results/` under the matching name;
`results/*.txt` files are the WAN (`tc netem`) runs.

No dataset, human-subject data, or proprietary model is involved. The
sandbox (`python/experiments/tools/`) is a local mock tool server; all
credentials, users, and "attacks" in it are synthetic.

## License

This artifact is licensed under [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/).
