#!/usr/bin/env python3
"""
Experiment 1: Measure zombie window under different configurations.

Hypothesis: Zombie window = max_heartbeat_age + heartbeat_interval

Run with: python experiments/exp1_zombie_window.py
"""

import time
import sys
import os

# Add parent directory to path to import visualizations
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leash import LeashConfig, Verifier
from leash.keys import AgentKeyPair
from leash.heartbeat import Heartbeat, HeartbeatGenerator
from leash.credentials import CredentialBuilder, CredentialProof
from leash.verification import generate_challenge
from visualizations import LEASHVisualizer, print_visual_summary
from rich.console import Console
from rich.progress import track


def measure_zombie_window(heartbeat_interval: int, max_age: int, trials: int = 3):
    """Measure actual zombie window for given configuration."""
    
    config = LeashConfig(
        heartbeat_interval_secs=heartbeat_interval,
        max_heartbeat_age_secs=max_age
    )
    
    results = []
    
    for trial in range(trials):
        # Setup
        parent = AgentKeyPair.generate_root(f"parent-{trial}")
        child = parent.derive_child("child")
        
        verifier = Verifier(config)
        verifier.trust_parent(f"parent-{trial}", parent.heartbeat_public_key())
        
        credential = CredentialBuilder().build(child, parent.heartbeat_public_key())
        
        # Generate last heartbeat before "revocation"
        gen = HeartbeatGenerator(parent.heartbeat_key, config)
        last_heartbeat = gen.generate()
        revocation_time = time.time()
        
        # Measure how long child can still authenticate
        zombie_duration = 0
        challenge = generate_challenge()
        
        while True:
            proof = CredentialProof.create(
                credential, last_heartbeat, challenge, child.identity_key
            )
            result = verifier.verify(proof, challenge)
            
            if not result.valid:
                zombie_duration = time.time() - revocation_time
                break
            
            time.sleep(0.5)
            
            # Safety timeout
            if time.time() - revocation_time > max_age + heartbeat_interval + 10:
                zombie_duration = time.time() - revocation_time
                break
        
        results.append(zombie_duration)
        print(f"  Trial {trial+1}: zombie_duration = {zombie_duration:.2f}s")
    
    return results


def run_experiment():
    console = Console()
    visualizer = LEASHVisualizer()
    
    console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold yellow]EXPERIMENT 1: Zombie Window Measurement[/bold yellow]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("\n[italic]Hypothesis: Zombie window ≤ max_heartbeat_age + heartbeat_interval[/italic]\n")
    
    configurations = [
        (2, 6),    # 2s interval, 6s max age -> expected max 8s
        (5, 15),   # 5s interval, 15s max age -> expected max 20s
        (10, 30),  # 10s interval, 30s max age -> expected max 40s (production-like)
    ]
    
    console.print("[bold]" + "-" * 60 + "[/bold]\n")
    
    all_passed = True
    all_results = []
    
    for interval, max_age in track(configurations, description="Running configurations..."):
        expected_max = max_age + interval
        console.print(f"\n[bold cyan]Configuration:[/bold cyan] interval={interval}s, max_age={max_age}s")
        console.print(f"[yellow]Expected maximum zombie window:[/yellow] {expected_max}s")
        
        results = measure_zombie_window(interval, max_age, trials=3)
        avg = sum(results) / len(results)
        max_observed = max(results)
        
        # Store for visualization
        tree_size = 2  # parent + child
        all_results.append({
            'interval': interval,
            'max_age': max_age,
            'tree_size': tree_size,
            'zombie_window_ms': avg * 1000,
            'expected_max_ms': expected_max * 1000,
            'max_observed_ms': max_observed * 1000
        })
        
        # Allow 1s tolerance for timing variations
        within_bound = max_observed <= expected_max + 1
        
        status = "[green]✓ PASS[/green]" if within_bound else "[red]✗ FAIL[/red]"
        all_passed = all_passed and within_bound
        
        console.print(f"  [cyan]Average:[/cyan] {avg:.2f}s, [cyan]Max observed:[/cyan] {max_observed:.2f}s")
        console.print(f"  [bold]Result:[/bold] {status}")
    
    console.print("\n[bold cyan]" + "=" * 60 + "[/bold cyan]")
    console.print("[bold yellow]RESULTS SUMMARY[/bold yellow]")
    console.print("[bold cyan]" + "=" * 60 + "[/bold cyan]")
    
    if all_passed:
        console.print("\n[bold green]✓ HYPOTHESIS CONFIRMED[/bold green]")
        console.print("[green]  Zombie window is bounded by (max_heartbeat_age + heartbeat_interval)[/green]")
        console.print("[green]  This is a key property of LEASH that enables predictable revocation.[/green]")
    else:
        console.print("\n[bold red]✗ HYPOTHESIS NEEDS REVIEW[/bold red]")
        console.print("[red]  Some configurations exceeded expected bounds.[/red]")
    
    console.print("\n[bold]Comparison with baselines:[/bold]")
    console.print(f"  [red]OAuth 2.0 (1hr tokens):[/red]     3600s zombie window")
    console.print(f"  [yellow]Short-lived certs (5min):[/yellow]   300s zombie window")
    console.print(f"  [green]LEASH (10s/30s config):[/green]      ~40s zombie window")
    console.print(f"  [bold green]Improvement over OAuth:[/bold green]     {3600/40:.0f}x")
    
    # Generate visualizations
    console.print("\n[bold yellow]Generating visualizations...[/bold yellow]")
    os.makedirs('results/figures', exist_ok=True)
    
    visualizer.plot_zombie_window_comparison(
        all_results,
        save_path='results/figures/exp1_zombie_window.png'
    )
    
    console.print("[bold green]✓ Experiment complete! Check results/figures/ for plots.[/bold green]\n")


if __name__ == "__main__":
    run_experiment()
