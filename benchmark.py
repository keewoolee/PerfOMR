#!/usr/bin/env python3
"""
Benchmarking script for PerfOMR experiments.
Runs experiments multiple times and outputs formatted results for paper tables/figures.
"""

import subprocess
import re
import statistics
from dataclasses import dataclass

NUM_RUNS = 5
MAX_RETRIES = 5

# Regex patterns to extract timing from program output
PATTERNS = {
    "Affine": r"Affine time:\s*([\d.]+)sec",
    "RangeCheck": r"RangeCheck time:\s*([\d.]+)sec",
    "Preprocessing": r"Preprocessing time:\s*([\d.]+)sec",
    "Compression": r"Compression time:\s*([\d.]+)sec",
    "Decode": r"Decode time:\s*([\d.]+)ms",
}

SIZE_PATTERNS = {
    "DigestSize": r"Digest size:\s*(\d+)KB",
}


@dataclass
class Stats:
    mean: float
    std: float

    def __str__(self):
        return f"{self.mean:.1f} ± {self.std:.1f}"


def compute_stats(values):
    return Stats(
        mean=statistics.mean(values),
        std=statistics.stdev(values) if len(values) > 1 else 0.0
    )


def run_once(cmd):
    """Run command once, retrying on verification failure."""
    for attempt in range(1, MAX_RETRIES + 1):
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = proc.stdout
        if "Result is correct!" in output:
            return output
        print(f"    WARNING: verification failed (attempt {attempt}/{MAX_RETRIES}), retrying...")
    raise RuntimeError(f"Verification failed after {MAX_RETRIES} attempts: {' '.join(cmd)}")


def run_benchmark(scheme, cores, msgs_per_bundle, num_bundles, k):
    """Run benchmark NUM_RUNS times and return statistics for each metric."""

    cmd = ["./OMRdemos", scheme, str(cores), str(msgs_per_bundle), str(num_bundles), str(k)]

    results = {name: [] for name in PATTERNS}
    sizes = {}

    for run in range(NUM_RUNS):
        output = run_once(cmd)

        for name, pattern in PATTERNS.items():
            match = re.search(pattern, output)
            if not match:
                raise RuntimeError(f"Run {run+1}: Failed to parse '{name}' from output:\n{output}")
            results[name].append(float(match.group(1)))

        # Sizes are deterministic; capture from first run only
        if run == 0:
            for name, pattern in SIZE_PATTERNS.items():
                match = re.search(pattern, output)
                if match:
                    sizes[name] = int(match.group(1))

    # Compute stats for each metric
    stats = {name: compute_stats(values) for name, values in results.items()}

    # Derived metrics
    detection_values = [a + r for a, r in zip(results["Affine"], results["RangeCheck"])]
    stats["Detection"] = compute_stats(detection_values)

    digest_values = [d + c + p for d, c, p in zip(detection_values, results["Compression"], results["Preprocessing"])]
    stats["Digest"] = compute_stats(digest_values)

    return stats, sizes


# =============================================================================
# Experiment Definitions
# =============================================================================

# Each experiment: (scheme, cores, msgs_per_bundle, num_bundles, k)
EXPERIMENTS = {
    "perfomr1_1_2_32768_50":   ("perfomr1", 1, 2, 32768, 50),
    "perfomd1_1_2_32768_50":   ("perfomd1", 1, 2, 32768, 50),
    "perfomr1_1_2_262144_50":  ("perfomr1", 1, 2, 262144, 50),
    "perfomd1_1_2_262144_50":  ("perfomd1", 1, 2, 262144, 50),
    "perfomr1_1_16_32768_50":  ("perfomr1", 1, 16, 32768, 50),
    "perfomd1_1_16_32768_50":  ("perfomd1", 1, 16, 32768, 50),
}

# Group experiments by figure/table
FIGURES = {
    "Table 4 / Figure 2": [
        "perfomr1_1_2_32768_50",
        "perfomd1_1_2_32768_50",
    ],
    "Table 8 / Figure 4": [
        "perfomr1_1_2_262144_50",
        "perfomr1_1_16_32768_50",
        "perfomd1_1_2_262144_50",
        "perfomd1_1_16_32768_50",
    ],
}


def main():
    print("Running experiments...")
    results = {}
    for name, (scheme, cores, msgs_per_bundle, num_bundles, k) in EXPERIMENTS.items():
        print(f"  {name}...")
        results[name] = run_benchmark(scheme, cores, msgs_per_bundle, num_bundles, k)

    print("\n" + "=" * 80)

    # Output results by figure/table
    for fig_name, exp_names in FIGURES.items():
        print(f"\n[{fig_name}]")
        print("-" * 80)

        # Digest & Decode times
        print(f"\n{'Config':<26}{'Digest (s)':>14}{'std':>8}{'Decode (ms)':>14}{'std':>8}{'Digest (KB)':>14}")
        for name in exp_names:
            stats, sizes = results[name]
            d, c = stats["Digest"], stats["Decode"]
            digest_kb = sizes.get("DigestSize", "")
            print(f"{name:<26}{d.mean:14.1f}{d.std:8.1f}{c.mean:14.1f}{c.std:8.1f}{digest_kb:>14}")

        # Breakdown format
        print(f"\n{'Config':<26}{'Affine (s)':>14}{'RangeCheck (s)':>16}{'Compress (s)':>14}{'Preproc (s)':>14}")
        for name in exp_names:
            s, _ = results[name]
            print(f"{name:<26}{s['Affine'].mean:14.1f}{s['RangeCheck'].mean:16.1f}{s['Compression'].mean:14.1f}{s['Preprocessing'].mean:14.1f}")


if __name__ == "__main__":
    main()
