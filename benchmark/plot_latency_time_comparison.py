from __future__ import annotations

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path

import numpy as np
import matplotlib

if not hasattr(np, "Inf"):
    np.Inf = np.inf

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from plot_latency_common import resolve_primary_start_ts

TIME_AXIS_PROPOSAL = "proposal"
TIME_AXIS_COMMIT = "commit"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare latency over time between two configs (default k2-c4 vs k2-c7). "
            "X-axis is time since primary start."
        )
    )
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--label-a", default="k2-c4")
    parser.add_argument("--label-b", default="k2-c7")
    parser.add_argument(
        "--time-axis",
        choices=[TIME_AXIS_PROPOSAL, TIME_AXIS_COMMIT],
        default=TIME_AXIS_COMMIT,
        help="Use commit/proposal time for alignment.",
    )
    parser.add_argument("--bin-size", type=float, default=1.0)
    parser.add_argument("--min-samples", type=int, default=10)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Default: <input-dir>/latency_time_comparison_<label-a>_vs_<label-b>.png",
    )
    return parser.parse_args()


def config_label_from_metadata(run_dir: Path) -> str | None:
    metadata_file = run_dir / "run_metadata.json"
    if not metadata_file.exists():
        return None
    try:
        data = json.loads(metadata_file.read_text())
    except Exception:
        return None
    node_params = data.get("node_params", {})
    kappa = node_params.get("kappa")
    coverage = node_params.get("coverage")
    if kappa is None or coverage is None:
        return None
    return f"k{int(kappa)}-c{int(coverage)}"


def load_attack_window(run_dir: Path) -> tuple[float | None, float | None]:
    metadata_file = run_dir / "run_metadata.json"
    if not metadata_file.exists():
        return None, None
    try:
        data = json.loads(metadata_file.read_text())
    except Exception:
        return None, None
    node_params = data.get("node_params", {})
    if not bool(node_params.get("attack_enabled", False)):
        return None, None
    start = node_params.get("attack_start_secs")
    duration = node_params.get("attack_duration_secs")
    if start is None:
        return None, None
    return float(start), float(duration or 0.0)


def discover_runs(input_dir: Path) -> list[Path]:
    return sorted(path.parent for path in input_dir.rglob("latency.csv"))


def load_rows(run_dir: Path, time_axis: str) -> list[tuple[float, float]]:
    latency_file = run_dir / "latency.csv"
    if not latency_file.exists():
        return []

    raw: list[tuple[float, float, float]] = []
    with latency_file.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("metric") != "consensus_latency":
                continue
            proposal = row.get("proposal_ts")
            commit = row.get("commit_ts")
            latency = row.get("latency_ms")
            if not proposal or not latency:
                continue
            proposal_ts = float(proposal)
            latency_ms = float(latency)
            commit_ts = float(commit) if commit else proposal_ts + latency_ms / 1000.0
            raw.append((proposal_ts, commit_ts, latency_ms))

    if not raw:
        return []

    fallback = min(p for p, _, _ in raw)
    primary_start = resolve_primary_start_ts(run_dir, fallback)
    use_commit = time_axis == TIME_AXIS_COMMIT
    points: list[tuple[float, float]] = []
    for proposal_ts, commit_ts, latency_ms in raw:
        event_ts = commit_ts if use_commit else proposal_ts
        points.append((event_ts - primary_start, latency_ms))
    return points


def aggregate_bins(
    points: list[tuple[float, float]],
    bin_size: float,
    min_samples: int,
) -> list[dict[str, float]]:
    buckets: dict[int, list[float]] = defaultdict(list)
    for x, latency_ms in points:
        b = math.floor(x / bin_size)
        buckets[b].append(latency_ms)

    rows: list[dict[str, float]] = []
    for b in sorted(buckets.keys()):
        vals = buckets[b]
        if len(vals) < min_samples:
            continue
        arr = np.array(vals, dtype=float)
        rows.append(
            {
                "x": b * bin_size,
                "mean": float(np.mean(arr)),
                "p95": float(np.percentile(arr, 95)),
                "count": float(len(arr)),
                "sum_latency": float(np.sum(arr)),
            }
        )

    # cumulative mean to show where overall average diverges
    cumulative_sum = 0.0
    cumulative_count = 0.0
    for row in rows:
        cumulative_sum += row["sum_latency"]
        cumulative_count += row["count"]
        row["cum_mean"] = cumulative_sum / cumulative_count if cumulative_count else 0.0
    return rows


def build_series_by_label(
    input_dir: Path,
    label_a: str,
    label_b: str,
    time_axis: str,
    bin_size: float,
    min_samples: int,
) -> tuple[dict[str, list[dict[str, float]]], tuple[float | None, float | None]]:
    grouped_points: dict[str, list[tuple[float, float]]] = {label_a: [], label_b: []}
    attack_start: float | None = None
    attack_duration: float | None = None

    for run_dir in discover_runs(input_dir):
        label = config_label_from_metadata(run_dir)
        if label not in grouped_points:
            continue
        grouped_points[label].extend(load_rows(run_dir, time_axis))

        a_start, a_duration = load_attack_window(run_dir)
        if attack_start is None and a_start is not None:
            attack_start = a_start
            attack_duration = a_duration

    series = {
        label_a: aggregate_bins(grouped_points[label_a], bin_size, min_samples),
        label_b: aggregate_bins(grouped_points[label_b], bin_size, min_samples),
    }
    return series, (attack_start, attack_duration)


def map_by_x(rows: list[dict[str, float]], key: str) -> dict[float, float]:
    return {row["x"]: row[key] for row in rows}


def draw(
    series: dict[str, list[dict[str, float]]],
    label_a: str,
    label_b: str,
    attack_window: tuple[float | None, float | None],
    output: Path,
    time_axis: str,
) -> None:
    a = series[label_a]
    b = series[label_b]
    if not a or not b:
        raise SystemExit(f"Insufficient data for {label_a} or {label_b}")

    c_a = "#dc2626"
    c_b = "#2563eb"
    c_diff = "#16a34a"

    fig, axes = plt.subplots(3, 1, figsize=(11, 10), dpi=180, sharex=True)

    # panel 1: rolling mean
    axes[0].plot([r["x"] for r in a], [r["mean"] for r in a], color=c_a, linewidth=2.0, label=f"{label_a} mean")
    axes[0].plot([r["x"] for r in b], [r["mean"] for r in b], color=c_b, linewidth=2.0, label=f"{label_b} mean")
    axes[0].set_ylabel("Rolling mean (ms)")
    axes[0].grid(True, linestyle="--", linewidth=0.6, alpha=0.45)
    axes[0].legend()

    # panel 2: rolling p95
    axes[1].plot([r["x"] for r in a], [r["p95"] for r in a], color=c_a, linewidth=2.0, label=f"{label_a} p95")
    axes[1].plot([r["x"] for r in b], [r["p95"] for r in b], color=c_b, linewidth=2.0, label=f"{label_b} p95")
    axes[1].set_ylabel("Rolling p95 (ms)")
    axes[1].grid(True, linestyle="--", linewidth=0.6, alpha=0.45)
    axes[1].legend()

    # panel 3: cumulative mean difference (A - B)
    a_cum = map_by_x(a, "cum_mean")
    b_cum = map_by_x(b, "cum_mean")
    xs = sorted(set(a_cum.keys()) & set(b_cum.keys()))
    diff = [a_cum[x] - b_cum[x] for x in xs]
    axes[2].axhline(0, color="#64748b", linewidth=1.0)
    axes[2].plot(xs, diff, color=c_diff, linewidth=2.2, label=f"cum_mean({label_a}) - cum_mean({label_b})")
    axes[2].fill_between(xs, diff, 0, color=c_diff, alpha=0.18)
    axes[2].set_ylabel("Cum-mean diff (ms)")
    axes[2].grid(True, linestyle="--", linewidth=0.6, alpha=0.45)
    axes[2].legend()

    # attack window overlay
    attack_start, attack_duration = attack_window
    if attack_start is not None:
        for ax in axes:
            ax.axvline(attack_start, color="#475569", linestyle="--", linewidth=1.2)
            if attack_duration and attack_duration > 0:
                attack_end = attack_start + attack_duration
                ax.axvspan(attack_start, attack_end, color="#94a3b8", alpha=0.12)
                ax.axvline(attack_end, color="#64748b", linestyle=":", linewidth=1.0)

    xlabel = "Time since primary start (s) - commit axis" if time_axis == TIME_AXIS_COMMIT else "Time since primary start (s) - proposal axis"
    axes[2].set_xlabel(xlabel)
    fig.suptitle(f"Latency Time Comparison: {label_a} vs {label_b}", y=0.98)
    fig.tight_layout(rect=[0, 0, 1, 0.97])

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")


def main() -> None:
    args = parse_args()
    if args.bin_size <= 0:
        raise SystemExit("--bin-size must be > 0")

    input_dir = args.input_dir.resolve()
    output = (
        args.output.resolve()
        if args.output
        else input_dir / f"latency_time_comparison_{args.label_a}_vs_{args.label_b}.png"
    )

    series, attack_window = build_series_by_label(
        input_dir=input_dir,
        label_a=args.label_a,
        label_b=args.label_b,
        time_axis=args.time_axis,
        bin_size=args.bin_size,
        min_samples=args.min_samples,
    )
    draw(
        series=series,
        label_a=args.label_a,
        label_b=args.label_b,
        attack_window=attack_window,
        output=output,
        time_axis=args.time_axis,
    )
    print(output)


if __name__ == "__main__":
    main()
