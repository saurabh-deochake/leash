# LEASH Quick Start Guide with Visualizations

This guide will help you run and **visualize** all experiments to understand the LEASH protocol in depth.

## Setup (5 minutes)

```bash
cd leash/python

# Activate virtual environment
source venv/bin/activate

# Install visualization dependencies
pip install matplotlib seaborn plotly networkx rich

# Create results directory
mkdir -p results/figures
```

## 1. Interactive Visual Demo (RECOMMENDED START HERE)

**This shows the protocol in real-time with visual feedback!**

```bash
python visual_demo.py
```

**What you'll see:**
- ✅ Real-time status table showing parent/child agents
- 📊 Visual timeline of heartbeat expiration
- 📝 Live authentication attempt log
- 🔴 Revocation happening at 15 seconds
- ⏱️ Zombie window visualization (9 seconds vs 3600 for OAuth)

**Duration:** 30 seconds of automated demo

---

## 2. Run Experiments with Visualizations

### Experiment 1: Zombie Window Measurement

```bash
python experiments/exp1_zombie_window.py
```

**What you'll see:**
- Colored terminal output with progress bars
- Measurements across 3 configurations
- **2 plots automatically generated:**
  - Measured vs Expected zombie window
  - LEASH vs OAuth vs Short-lived Certs comparison
- Saved to: `results/figures/exp1_zombie_window.png`

**Key insight:** Zombie window is bounded at ~40s (vs 3600s for OAuth = **90x improvement**)

---

### Experiment 2: Partition Tolerance

```bash
python experiments/exp2_partition_tolerance.py
```

**What you'll see:**
- Timeline of authentication attempts during network partition
- Visual indication when heartbeat expires
- **Plot showing:**
  - Authentication success/failure over time
  - Heartbeat age progression
  - Revocation effectiveness without network
- Saved to: `results/figures/exp2_partition_tolerance.png`

**Key insight:** Revocation works even when completely disconnected from parent

---

### Experiment 3: Performance Benchmarks

```bash
python experiments/exp3_performance.py
```

**What you'll see:**
- Performance metrics for each cryptographic operation
- **Bar charts showing:**
  - Mean latency with error bars
  - Color-coded by speed (green = fast, orange = slower)
  - Comparison to 100ms threshold for constrained devices
- Saved to: `results/figures/exp3_performance.png`

**Key insight:** All operations complete in <10ms on laptop (would be <100ms on Raspberry Pi)

---

### Experiment 4: Baseline Comparison

```bash
python experiments/exp4_baseline_comparison.py
```

**What you'll see:**
- Side-by-side comparison of zombie windows
- **Bar chart comparing:**
  - OAuth 2.0 (3600s)
  - Short-lived Certs (300s)
  - LEASH (40s)
- Improvement factors annotated on chart
- Saved to: `results/figures/exp4_baseline_comparison.png`

**Key insight:** LEASH provides 90x improvement over OAuth, 7.5x over short-lived certs

---

## 3. View All Generated Plots

After running experiments, view your results:

```bash
# On macOS
open results/figures/

# Or view individual plots
open results/figures/exp1_zombie_window.png
open results/figures/exp2_partition_tolerance.png
open results/figures/exp3_performance.png
open results/figures/exp4_baseline_comparison.png
```

---

## 4. Understanding the Visualizations

### Color Coding
- 🟢 **Green:** LEASH (your contribution)
- 🔴 **Red:** OAuth 2.0 (baseline)
- 🟡 **Yellow/Orange:** Short-lived certificates (middle ground)

### Key Metrics to Look For

| Metric | What It Shows | Good Value |
|--------|---------------|------------|
| **Zombie Window** | Time revoked agent can still authenticate | <60s |
| **Revocation Latency** | Time from revocation to access denial | <max_age + interval |
| **Operation Latency** | Crypto operation speed | <10ms |
| **Improvement Factor** | LEASH vs baselines | >50x |

---

## 5. For Your Paper

Use these visualizations directly in your paper:

```latex
\begin{figure}[t]
  \centering
  \includegraphics[width=0.8\linewidth]{figures/exp1_zombie_window.png}
  \caption{Zombie window comparison: LEASH achieves 90x improvement over OAuth 2.0}
  \label{fig:zombie-window}
\end{figure}
```

All plots are saved at 300 DPI, publication-ready quality.

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'rich'"

```bash
pip install rich matplotlib seaborn plotly networkx
```

### "No display found" (on headless server)

Add this at the top of experiment files:
```python
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
```

### Plots not showing

Check `results/figures/` directory - plots are saved even if display fails.

---

## Next Steps

1. ✅ Run `visual_demo.py` to see it in action
2. ✅ Run all 4 experiments to collect data
3. ✅ Review plots in `results/figures/`
4. 📝 Use plots in your paper
5. 📚 Read related work (see RESEARCH_STUDY_PLAN.md)

---

## Quick Reference

| Command | What It Does | Duration |
|---------|--------------|----------|
| `python visual_demo.py` | Interactive real-time demo | 30s |
| `python experiments/exp1_zombie_window.py` | Measure zombie window | ~30s |
| `python experiments/exp2_partition_tolerance.py` | Test partition tolerance | ~15s |
| `python experiments/exp3_performance.py` | Benchmark performance | ~10s |
| `python experiments/exp4_baseline_comparison.py` | Compare with baselines | <1s |

**Total time to run everything:** ~2 minutes

---

## Understanding Cloud IAM Integration

**Important:** LEASH is NOT a replacement for cloud IAM. It's a complementary layer:

```
┌─────────────────────────────────┐
│  AI Agent (proves identity)     │
│  ↓ Uses LEASH credential         │
├─────────────────────────────────┤
│  LEASH Verifier                  │
│  ✓ Validates agent identity     │
│  ↓ Returns verified agent_id    │
├─────────────────────────────────┤
│  Cloud IAM (AWS/GCP)            │
│  Maps agent_id → permissions    │
└─────────────────────────────────┘
```

**For your paper:** Focus on LEASH (agent identity & revocation). Cloud IAM integration is "future work."
